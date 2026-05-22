//! Live terminal UI.
//!
//! This module owns the event loop and mutable UI state. Rendering details are
//! split into sibling modules so scan-event handling, row merging, and terminal
//! lifecycle stay easy to reason about independently.

mod devices;
mod interfaces;
mod layout;
mod logs;
mod session;
mod theme;

use super::OutputOptions;
use crate::{model::Device, scanner::ScanEvent};
use chrono::{DateTime, Local};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use devices::{
    DeviceKey, device_log_summary, device_mac_changed, device_matches_search, device_row,
    live_identity_signature, merge_live_device, visible_columns_for_devices,
};
pub use interfaces::LiveInterfacePanel;
use interfaces::{interface_panel_width, render_interfaces, top_panel_height};
use layout::{TABLE_COLUMN_SPACING, corrected_table_offset, panel_content_width};
use logs::{
    LiveLogEntry, LiveLogLevel, help_bar, key_span, source_legend, styled_log_line, value_span,
};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{
        Cell as TuiCell, HighlightSpacing, Paragraph, Row as TuiRow, Table as TuiTable, TableState,
        Wrap,
    },
};
use session::TuiSession;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::Arc,
    time::Duration,
};
use theme::NeonTheme;
use tokio::{
    sync::{mpsc::UnboundedReceiver, watch},
    time::MissedTickBehavior,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveOutcome {
    Completed,
    Cancelled,
}

impl LiveOutcome {
    pub fn is_cancelled(self) -> bool {
        matches!(self, Self::Cancelled)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveInputAction {
    Continue,
    Exit,
    Pause,
    Resume,
}

const MAX_LIVE_LOG_LINES: usize = 200;

pub async fn run_live_table(
    events: UnboundedReceiver<ScanEvent>,
    pause_tx: watch::Sender<bool>,
    options: OutputOptions,
    interface_panel: LiveInterfacePanel,
) -> io::Result<LiveOutcome> {
    run_live_table_with_time_source(events, pause_tx, options, interface_panel, Local::now).await
}

pub async fn run_live_table_with_time_source<F>(
    events: UnboundedReceiver<ScanEvent>,
    pause_tx: watch::Sender<bool>,
    options: OutputOptions,
    interface_panel: LiveInterfacePanel,
    now: F,
) -> io::Result<LiveOutcome>
where
    F: Fn() -> DateTime<Local> + Send + Sync + 'static,
{
    run_live_table_with_app(
        events,
        pause_tx,
        LiveTable::new_with_time_source(options, interface_panel, Arc::new(now)),
    )
    .await
}

async fn run_live_table_with_app(
    mut events: UnboundedReceiver<ScanEvent>,
    pause_tx: watch::Sender<bool>,
    mut app: LiveTable,
) -> io::Result<LiveOutcome> {
    let mut tui = TuiSession::enter()?;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut channel_open = true;
    let mut exit_after_draw = false;

    loop {
        tokio::select! {
            event = events.recv(), if channel_open => {
                match event {
                    Some(event) => app.apply(event),
                    None => {
                        channel_open = false;
                        if !app.finished {
                            app.warn("scan stopped before completion".to_string());
                            app.phase = "stopped".to_string();
                            app.finished = true;
                            exit_after_draw = true;
                        }
                    }
                }
            }
            _ = tick.tick() => {}
        }

        while event::poll(Duration::ZERO)? {
            if let Event::Key(key) = event::read()? {
                match app.handle_key(key) {
                    LiveInputAction::Continue => {}
                    LiveInputAction::Pause => {
                        let _ = pause_tx.send(true);
                    }
                    LiveInputAction::Resume => {
                        let _ = pause_tx.send(false);
                    }
                    LiveInputAction::Exit => {
                        return Ok(if app.finished {
                            LiveOutcome::Completed
                        } else {
                            LiveOutcome::Cancelled
                        });
                    }
                }
            }
        }

        tui.draw(|frame| app.render(frame))?;
        if exit_after_draw {
            return Ok(LiveOutcome::Completed);
        }
    }
}

struct LiveTable {
    target: Option<String>,
    interface: Option<String>,
    profile: Option<String>,
    phase: String,
    devices: BTreeMap<DeviceKey, Device>,
    device_rounds: BTreeMap<DeviceKey, u64>,
    current_round: Option<u64>,
    warnings: Vec<String>,
    logs: VecDeque<LiveLogEntry>,
    finished: bool,
    paused: bool,
    table_state: TableState,
    scroll: usize,
    search_query: String,
    search_editing: bool,
    options: OutputOptions,
    interface_panel: LiveInterfacePanel,
    now: Arc<dyn Fn() -> DateTime<Local> + Send + Sync>,
}

impl LiveTable {
    #[cfg(test)]
    fn new(options: OutputOptions, interface_panel: LiveInterfacePanel) -> Self {
        Self::new_with_time_source(options, interface_panel, Arc::new(Local::now))
    }

    fn new_with_time_source(
        options: OutputOptions,
        interface_panel: LiveInterfacePanel,
        now: Arc<dyn Fn() -> DateTime<Local> + Send + Sync>,
    ) -> Self {
        Self {
            target: None,
            interface: None,
            profile: None,
            phase: "starting".to_string(),
            devices: BTreeMap::new(),
            device_rounds: BTreeMap::new(),
            current_round: None,
            warnings: Vec::new(),
            logs: VecDeque::new(),
            finished: false,
            paused: false,
            table_state: TableState::default().with_selected(Some(0)),
            scroll: 0,
            search_query: String::new(),
            search_editing: false,
            options,
            interface_panel,
            now,
        }
    }

    fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Started {
                target,
                interface,
                profile,
            } => {
                self.target = Some(target);
                self.interface = Some(interface);
                self.profile = Some(profile.to_string());
                let interface_summary = self.interface.clone().unwrap_or_default();
                self.note_scan_interfaces(&interface_summary);
                self.phase = "starting".to_string();
                self.push_log(
                    LiveLogLevel::Info,
                    format!(
                        "scan started target={} iface={} profile={}",
                        self.target.as_deref().unwrap_or("-"),
                        self.interface.as_deref().unwrap_or("-"),
                        self.profile.as_deref().unwrap_or("-")
                    ),
                );
            }
            ScanEvent::RoundStarted { round } => {
                self.current_round = Some(round);
                self.phase = format!("scan round {round}");
            }
            ScanEvent::Phase(phase) => {
                self.phase = phase;
            }
            ScanEvent::DeviceUpdated(device) => {
                let key = DeviceKey::from_device(&device);
                if let Some(message) = self.upsert_device_update(*device) {
                    self.push_log(LiveLogLevel::Device, message);
                }
                if !self.paused {
                    self.select_device(&key);
                }
                self.clamp_selection();
            }
            ScanEvent::Warning(warning) => {
                self.warn(warning);
            }
            ScanEvent::Finished { devices, warnings } => {
                self.devices = devices
                    .into_iter()
                    .map(|device| (DeviceKey::from_device(&device), device))
                    .collect();
                self.device_rounds.clear();
                if let Some(round) = self.current_round {
                    self.device_rounds
                        .extend(self.devices.keys().cloned().map(|key| (key, round)));
                }
                for warning in &warnings {
                    if !self.warnings.iter().any(|existing| existing == warning) {
                        self.push_log(LiveLogLevel::Warning, format!("warning {warning}"));
                    }
                }
                self.warnings = warnings;
                self.phase = "complete".to_string();
                self.finished = true;
                self.clamp_selection();
                self.push_log(
                    LiveLogLevel::Info,
                    format!(
                        "scan complete devices={} warnings={}",
                        self.devices.len(),
                        self.warnings.len()
                    ),
                );
            }
        }
    }

    fn upsert_device_update(&mut self, device: Device) -> Option<String> {
        let key = DeviceKey::from_device(&device);
        if let Some(round) = self.current_round {
            self.device_rounds.insert(key.clone(), round);
        }
        if let Some(existing) = self.devices.get_mut(&key) {
            if device_mac_changed(existing, &device) {
                let message = format!(
                    "device replaced {}",
                    device_log_summary(&device, self.options)
                );
                *existing = device;
                return Some(message);
            }
            let before = live_identity_signature(existing);
            merge_live_device(existing, device);
            let after = live_identity_signature(existing);
            if before != after {
                Some(format!(
                    "device updated {}",
                    device_log_summary(existing, self.options)
                ))
            } else {
                None
            }
        } else {
            let message = format!(
                "device discovered {}",
                device_log_summary(&device, self.options)
            );
            self.devices.insert(key, device);
            Some(message)
        }
    }

    fn device_is_current_round(&self, key: &DeviceKey) -> bool {
        match self.current_round {
            Some(round) => self.device_rounds.get(key).copied() == Some(round),
            None => true,
        }
    }

    fn note_scan_interfaces(&mut self, summary: &str) {
        for name in summary
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty() && *name != "default")
        {
            if !self
                .interface_panel
                .scan_interfaces
                .iter()
                .any(|existing| existing == name)
            {
                self.interface_panel.scan_interfaces.push(name.to_string());
            }
        }
    }

    fn warn(&mut self, warning: String) {
        if !self.warnings.iter().any(|existing| existing == &warning) {
            self.push_log(LiveLogLevel::Warning, format!("warning {warning}"));
            self.warnings.push(warning);
        }
    }

    fn select_device(&mut self, key: &DeviceKey) {
        // The selected row acts as a live update marker: every fresh device
        // event moves the cursor to the row that just changed. That makes the
        // table's highlight meaningful even when the operator is only watching
        // the scan rather than navigating manually.
        if let Some(index) = self
            .visible_device_entries()
            .iter()
            .position(|(candidate, _)| *candidate == key)
        {
            self.table_state.select(Some(index));
        }
    }

    fn visible_device_count(&self) -> usize {
        self.visible_device_entries().len()
    }

    fn visible_device_entries(&self) -> Vec<(&DeviceKey, &Device)> {
        self.devices
            .iter()
            .filter(|(_, device)| device_matches_search(device, &self.search_query))
            .collect()
    }

    fn push_log(&mut self, level: LiveLogLevel, message: impl Into<String>) {
        // The live log is a moving operational trace, not history storage. A
        // bounded buffer keeps continuous scan memory flat even on long-running
        // scans where phases repeat and devices keep refreshing Last Seen.
        while self.logs.len() >= MAX_LIVE_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(LiveLogEntry {
            timestamp: self.now(),
            level,
            message: message.into(),
        });
    }

    fn handle_key(&mut self, key: KeyEvent) -> LiveInputAction {
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            return LiveInputAction::Exit;
        }

        if self.search_editing {
            return self.handle_search_key(key);
        }

        match key.code {
            KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                if !self.paused {
                    self.paused = true;
                    self.phase = "paused".to_string();
                    self.push_log(LiveLogLevel::Info, "scan paused");
                    LiveInputAction::Pause
                } else {
                    LiveInputAction::Continue
                }
            }
            KeyCode::Esc if self.paused => {
                self.paused = false;
                self.phase = "resuming".to_string();
                self.push_log(LiveLogLevel::Info, "scan resumed");
                LiveInputAction::Resume
            }
            KeyCode::Char('/') => {
                self.search_editing = true;
                LiveInputAction::Continue
            }
            KeyCode::Esc if self.has_search_filter() => {
                self.clear_search();
                LiveInputAction::Continue
            }
            KeyCode::Down => {
                self.move_selection(1);
                LiveInputAction::Continue
            }
            KeyCode::Char('j') => {
                self.move_selection(1);
                LiveInputAction::Continue
            }
            KeyCode::Up => {
                self.move_selection(-1);
                LiveInputAction::Continue
            }
            KeyCode::Char('k') => {
                self.move_selection(-1);
                LiveInputAction::Continue
            }
            KeyCode::PageDown => {
                self.move_selection(10);
                LiveInputAction::Continue
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.move_selection(10);
                LiveInputAction::Continue
            }
            KeyCode::PageUp => {
                self.move_selection(-10);
                LiveInputAction::Continue
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.move_selection(-10);
                LiveInputAction::Continue
            }
            KeyCode::Home => {
                self.select_index(0);
                LiveInputAction::Continue
            }
            KeyCode::End => {
                self.select_last();
                LiveInputAction::Continue
            }
            KeyCode::Esc => LiveInputAction::Continue,
            _ => LiveInputAction::Continue,
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> LiveInputAction {
        match key.code {
            KeyCode::Esc => {
                self.clear_search();
                LiveInputAction::Continue
            }
            KeyCode::Enter => {
                self.search_editing = false;
                LiveInputAction::Continue
            }
            KeyCode::Backspace => {
                self.search_query.pop();
                self.reset_visible_selection();
                LiveInputAction::Continue
            }
            KeyCode::Char(ch)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                self.search_query.push(ch);
                self.reset_visible_selection();
                LiveInputAction::Continue
            }
            _ => LiveInputAction::Continue,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.visible_device_count();
        if len == 0 {
            self.table_state.select(Some(0));
            self.scroll = 0;
            return;
        }
        let current = self.table_state.selected().unwrap_or(0).min(len - 1);
        let next = current.saturating_add_signed(delta).min(len - 1);
        self.select_index(next);
    }

    fn select_index(&mut self, index: usize) {
        let len = self.visible_device_count();
        if len == 0 {
            self.table_state.select(Some(0));
            self.scroll = 0;
            return;
        }
        self.table_state.select(Some(index.min(len - 1)));
        self.clamp_selection();
    }

    fn select_last(&mut self) {
        let len = self.visible_device_count();
        self.select_index(len.saturating_sub(1));
    }

    fn has_search_filter(&self) -> bool {
        !self.search_query.trim().is_empty()
    }

    fn clear_search(&mut self) {
        self.search_query.clear();
        self.search_editing = false;
        self.reset_visible_selection();
    }

    fn reset_visible_selection(&mut self) {
        self.table_state.select(Some(0));
        self.scroll = 0;
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        let len = self.visible_device_count();
        if len == 0 {
            self.table_state.select(Some(0));
            self.scroll = 0;
            return;
        }
        let selected = self.table_state.selected().unwrap_or(0).min(len - 1);
        self.table_state.select(Some(selected));
        self.scroll = self.scroll.min(len - 1);
    }

    fn render(&mut self, frame: &mut Frame<'_>) {
        let area = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(top_panel_height()),
                Constraint::Min(8),
                Constraint::Length(1),
            ])
            .split(area);

        let interface_width = self.interface_panel_width(chunks[1].width);
        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(interface_width)])
            .split(chunks[1]);

        frame.render_widget(help_bar(chunks[0].width, self.now()), chunks[0]);
        frame.render_widget(self.live_scan(top[0].width), top[0]);
        render_interfaces(frame, top[1], &self.interface_panel, self.options);
        self.render_table(frame, chunks[2]);
        frame.render_widget(
            source_legend(chunks[3].width, self.footer_indicator()),
            chunks[3],
        );
    }

    fn footer_indicator(&self) -> Option<String> {
        let filter = (self.search_editing || self.has_search_filter())
            .then(|| format!("filter=/{}", self.search_query));
        match (filter, self.paused) {
            (Some(filter), true) => Some(format!("{filter}  Paused")),
            (Some(filter), false) => Some(filter),
            (None, true) => Some("Paused".to_string()),
            (None, false) => None,
        }
    }

    fn live_scan(&self, width: u16) -> Paragraph<'_> {
        let status = if self.paused {
            "paused"
        } else if self.finished {
            "complete"
        } else {
            "scanning"
        };
        let mut lines = vec![Line::from(vec![
            key_span("status="),
            value_span(status),
            key_span("  profile="),
            value_span(self.profile.as_deref().unwrap_or("-")),
            key_span("  phase="),
            value_span(self.phase.clone()),
        ])];
        let visible_logs = top_panel_height().saturating_sub(3) as usize;
        let start = self.logs.len().saturating_sub(visible_logs);
        let log_width = panel_content_width(width) as usize;
        lines.extend(
            self.logs
                .iter()
                .skip(start)
                .map(|entry| styled_log_line(entry, log_width)),
        );
        if self.logs.is_empty() && visible_logs > 0 {
            lines.push(Line::from(Span::styled(
                "waiting for scan events",
                Style::default()
                    .fg(NeonTheme::DIM)
                    .bg(NeonTheme::BACKGROUND),
            )));
        }

        Paragraph::new(lines)
            .style(NeonTheme::panel())
            .block(NeonTheme::block("Live Scan"))
            .wrap(Wrap { trim: true })
    }

    fn now(&self) -> DateTime<Local> {
        (self.now)()
    }

    fn interface_panel_width(&self, available_width: u16) -> u16 {
        interface_panel_width(available_width, &self.interface_panel, self.options)
    }

    fn render_table(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let entries = self.visible_device_entries();
        let devices = entries
            .iter()
            .map(|(_, device)| *device)
            .collect::<Vec<_>>();
        let columns = visible_columns_for_devices(area.width, &devices, self.options);
        let header = TuiRow::new(columns.iter().map(|column| TuiCell::from(column.title())))
            .style(NeonTheme::table_header());

        let rows = entries
            .iter()
            .map(|(key, device)| {
                device_row(
                    device,
                    &columns,
                    self.options,
                    self.device_is_current_round(key),
                )
            })
            .collect::<Vec<_>>();
        let offset = self.update_table_offset(area);
        *self.table_state.offset_mut() = offset;

        let table = TuiTable::new(
            rows,
            columns
                .iter()
                .map(|column| column.constraint())
                .collect::<Vec<_>>(),
        )
        .header(header)
        .block(NeonTheme::block("Devices"))
        .style(NeonTheme::panel())
        .column_spacing(TABLE_COLUMN_SPACING)
        .row_highlight_style(NeonTheme::selected_row())
        .highlight_spacing(HighlightSpacing::Never);

        frame.render_stateful_widget(table, area, &mut self.table_state);
    }

    fn update_table_offset(&mut self, area: Rect) -> usize {
        let selected = self.table_state.selected().unwrap_or(0);
        let visible_rows = area.height.saturating_sub(3).max(1) as usize;
        // The highlighted row marks the device most recently touched by a scan
        // event. Keep that marker visible without making the table jump on
        // every refresh; only scroll when the highlighted row crosses an edge.
        self.scroll = corrected_table_offset(selected, self.scroll, visible_rows);
        self.scroll
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{
        devices::{
            DeviceColumn, DeviceTableColumn, device_row_style, stale_device_row_style,
            visible_columns,
        },
        interfaces::{
            INTERFACE_PANEL_VISIBLE_ROWS, InterfaceColumn, InterfaceTableColumn,
            desired_interface_panel_width, interface_column_kinds, interface_panel_height,
            interface_row_style, visible_interface_columns,
        },
        layout::{fit_cell, panel_content_width, table_spacing_width},
        logs::{help_line, log_style, source_footer_line},
    };
    use crate::net::InterfaceInfo;
    use crate::{model::Device, output::MacAddressDisplay, scanner::ScanEvent};
    use chrono::{Local, TimeZone, Utc};
    use ratatui::{
        Terminal,
        backend::TestBackend,
        buffer::Buffer,
        style::{Color, Modifier},
        text::Line,
    };

    #[test]
    fn table_offset_keeps_cursor_moving_inside_viewport() {
        assert_eq!(corrected_table_offset(0, 0, 5), 0);
        assert_eq!(corrected_table_offset(1, 0, 5), 0);
        assert_eq!(corrected_table_offset(4, 0, 5), 0);
    }

    #[test]
    fn table_offset_scrolls_only_at_edges() {
        assert_eq!(corrected_table_offset(5, 0, 5), 1);
        assert_eq!(corrected_table_offset(2, 4, 5), 2);
    }

    #[test]
    fn tui_cells_are_trimmed_to_stable_widths() {
        assert_eq!(fit_cell("abcdef".to_string(), 0), "");
        assert_eq!(fit_cell("abcdef".to_string(), 4), "abc~");
        assert_eq!(fit_cell("abc".to_string(), 4), "abc");
    }

    #[test]
    fn tui_allocates_identity_columns_from_remaining_width() {
        let wide = visible_columns(180);
        assert_eq!(column_width(&wide, DeviceColumn::Ip), 15);
        assert_eq!(column_width(&wide, DeviceColumn::Interface), 8);
        assert_eq!(column_width(&wide, DeviceColumn::Mac), 17);
        assert_eq!(column_width(&wide, DeviceColumn::Confidence), 6);
        assert_eq!(column_width(&wide, DeviceColumn::Sources), 10);
        assert_eq!(column_width(&wide, DeviceColumn::Seen), 8);

        let wide_identity_widths = [
            column_width(&wide, DeviceColumn::Vendor),
            column_width(&wide, DeviceColumn::Model),
            column_width(&wide, DeviceColumn::Name),
            column_width(&wide, DeviceColumn::Os),
        ];
        let min = wide_identity_widths.into_iter().min().unwrap();
        let max = wide_identity_widths.into_iter().max().unwrap();
        assert!(max - min <= 1);
        assert!(min > column_width(&wide, DeviceColumn::Sources));

        let medium = visible_columns(132);
        assert!(has_column(&medium, DeviceColumn::Vendor));
        assert!(has_column(&medium, DeviceColumn::Os));
        assert!(has_column(&medium, DeviceColumn::Sources));
        assert!(!has_column(&medium, DeviceColumn::Model));

        let medium_identity_widths = [
            column_width(&medium, DeviceColumn::Vendor),
            column_width(&medium, DeviceColumn::Name),
            column_width(&medium, DeviceColumn::Os),
        ];
        let min = medium_identity_widths.into_iter().min().unwrap();
        let max = medium_identity_widths.into_iter().max().unwrap();
        assert!(max - min <= 1);
        assert_eq!(total_device_table_width(&medium), panel_content_width(132));
    }

    #[test]
    fn tui_rebalances_identity_columns_toward_truncated_values() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.22.195".parse().unwrap(), now);
        device.vendor = Some("Amazon Technologies Inc.".to_string());
        device.set_model_guess("RS819", "upnp", 0.85);
        device.add_name("7ff41467-6f7e-607c-3a1d-4f8fad4a", "mdns", 0.9);
        device.set_os_guess("Windows/SMB capable", "netbios", 0.9);
        let devices = vec![&device];

        let equal = visible_columns(180);
        let dynamic = visible_columns_for_devices(180, &devices, OutputOptions::default());

        assert_eq!(total_device_table_width(&dynamic), panel_content_width(180));
        assert_eq!(column_width(&dynamic, DeviceColumn::Ip), 15);
        assert!(
            column_width(&dynamic, DeviceColumn::Name) > column_width(&equal, DeviceColumn::Name)
        );
        assert!(
            column_width(&dynamic, DeviceColumn::Name)
                >= "7ff41467-6f7e-607c-3a1d-4f8fad4a".len() as u16
        );
        assert!(
            column_width(&dynamic, DeviceColumn::Vendor) >= "Amazon Technologies Inc.".len() as u16
        );
        assert!(column_width(&dynamic, DeviceColumn::Os) >= "Windows/SMB capable".len() as u16);
        assert!(
            column_width(&dynamic, DeviceColumn::Model) < column_width(&equal, DeviceColumn::Model)
        );
    }

    #[test]
    fn tui_keeps_ipv4_column_wide_enough_for_full_address() {
        let narrow = visible_columns(80);

        assert_eq!(column_width(&narrow, DeviceColumn::Ip), 15);
        assert_eq!(
            fit_cell(
                "255.255.255.255".to_string(),
                column_width(&narrow, DeviceColumn::Ip) as usize
            ),
            "255.255.255.255"
        );
        assert_eq!(total_device_table_width(&narrow), panel_content_width(80));
    }

    #[test]
    fn seen_column_uses_system_timezone() {
        let seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let device = Device::new("192.168.1.10".parse().unwrap(), seen);
        let column = DeviceTableColumn {
            kind: DeviceColumn::Seen,
            width: 8,
        };

        assert_eq!(
            column.value(&device, OutputOptions::default()),
            seen.with_timezone(&Local).format("%H:%M:%S").to_string()
        );
    }

    #[test]
    fn top_row_shrinks_interfaces_and_gives_live_scan_the_rest() {
        let panel = sample_interface_panel();
        let width = interface_panel_width(180, &panel, OutputOptions::default());

        assert!(width < 90);
        assert!(180 - width > width);
        assert_eq!(
            width,
            desired_interface_panel_width(
                interface_column_kinds(),
                &panel,
                OutputOptions::default()
            )
        );
    }

    #[test]
    fn interface_columns_use_minimum_content_widths() {
        let panel = sample_interface_panel();
        let width = interface_panel_width(180, &panel, OutputOptions::default());
        let columns = visible_interface_columns(width, &panel, OutputOptions::default());

        assert_eq!(interface_column_width(&columns, InterfaceColumn::Use), 4);
        assert_eq!(
            interface_column_width(&columns, InterfaceColumn::Default),
            3
        );
        assert_eq!(interface_column_width(&columns, InterfaceColumn::Name), 5);
        assert_eq!(interface_column_width(&columns, InterfaceColumn::Ipv4), 15);
        assert_eq!(
            interface_column_width(&columns, InterfaceColumn::Network),
            18
        );
        assert_eq!(interface_column_width(&columns, InterfaceColumn::Mac), 17);
        assert_eq!(
            total_interface_table_width(&columns),
            panel_content_width(width)
        );
    }

    #[test]
    fn interface_panel_reserves_six_visible_rows() {
        // Keep the top row stable across machines with one NIC, many VLANs, or
        // transient VPN interfaces. The table height is six data rows plus a
        // header and the two border rows.
        assert_eq!(interface_panel_height(), INTERFACE_PANEL_VISIBLE_ROWS + 3);
    }

    #[test]
    fn tui_theme_uses_evangelion_interface_palette() {
        assert_eq!(NeonTheme::BACKGROUND, Color::Rgb(26, 10, 2));
        assert_eq!(NeonTheme::HEADER_BG, Color::Rgb(58, 18, 3));
        assert_eq!(NeonTheme::SELECTED_BG, Color::Rgb(92, 24, 2));
        assert_eq!(NeonTheme::PRIMARY, Color::Rgb(240, 144, 58));
        assert_eq!(NeonTheme::PRIMARY_SOFT, Color::Rgb(255, 170, 68));
        assert_eq!(NeonTheme::TEXT, Color::Rgb(238, 136, 34));
        assert_eq!(NeonTheme::ACCENT_GREEN, Color::Rgb(88, 242, 165));
        assert_eq!(NeonTheme::STALE_RED, Color::Rgb(150, 45, 38));
    }

    #[test]
    fn tui_green_accent_is_reserved_for_chrome_not_data() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut vendor_only = Device::new("192.168.1.10".parse().unwrap(), now);
        vendor_only.vendor = Some("Example Inc".to_string());

        assert_eq!(NeonTheme::table_header().fg, Some(NeonTheme::ACCENT_GREEN));
        assert_eq!(NeonTheme::label().fg, Some(NeonTheme::ACCENT_GREEN));
        assert_eq!(
            device_row_style(&vendor_only).fg,
            Some(NeonTheme::PRIMARY_SOFT)
        );
        assert_eq!(
            interface_row_style(true, false).fg,
            Some(NeonTheme::PRIMARY_SOFT)
        );
        assert_eq!(interface_row_style(false, true).fg, Some(NeonTheme::TEXT));
        assert_eq!(
            log_style(LiveLogLevel::Info).fg,
            Some(NeonTheme::PRIMARY_SOFT)
        );
        assert_eq!(log_style(LiveLogLevel::Device).fg, Some(NeonTheme::TEXT));
    }

    #[test]
    fn stale_device_rows_are_dimmed_red() {
        let style = stale_device_row_style();

        assert_eq!(style.fg, Some(NeonTheme::STALE_RED));
        assert!(style.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn tui_log_lines_show_timestamps_and_keep_green_out_of_live_log() {
        let entry = LiveLogEntry {
            timestamp: Local.with_ymd_and_hms(2026, 1, 1, 12, 34, 56).unwrap(),
            level: LiveLogLevel::Info,
            message: "scan started target=192.168.20.0/22 iface=en7".to_string(),
        };

        let line = styled_log_line(&entry, 120);

        assert_eq!(line.spans[0].content.as_ref(), "12:34:56");
        assert_eq!(line.spans[0].style.fg, Some(NeonTheme::DIM));
        assert_eq!(line.spans[2].content.as_ref(), "scan");
        assert_eq!(line.spans[2].style.fg, Some(NeonTheme::PRIMARY_SOFT));
        assert_eq!(line.spans[6].content.as_ref(), "target=");
        assert_eq!(line.spans[6].style.fg, Some(NeonTheme::PRIMARY_SOFT));
        assert_eq!(line.spans[7].content.as_ref(), "192.168.20.0/22");
        assert_eq!(line.spans[7].style.fg, Some(NeonTheme::PRIMARY_SOFT));
        assert_eq!(line.spans[9].content.as_ref(), "iface=");
        assert_eq!(line.spans[9].style.fg, Some(NeonTheme::PRIMARY_SOFT));
        assert_eq!(line.spans[10].content.as_ref(), "en7");
        assert_eq!(line.spans[10].style.fg, Some(NeonTheme::PRIMARY_SOFT));
        assert!(
            line.spans
                .iter()
                .all(|span| span.style.fg != Some(NeonTheme::ACCENT_GREEN))
        );
    }

    #[test]
    fn device_live_log_summary_is_dense_and_single_line_safe() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 12, 34, 56).unwrap();
        let mut device = Device::new("192.168.22.153".parse().unwrap(), now);
        device.interface = Some("en7".to_string());
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Sony Corporation".to_string());
        device.set_model_guess("BRAVIA 4K VH2", "upnp", 0.85);
        device.add_name("Living Room TV", "upnp", 0.85);
        device.set_os_guess("Android TV", "upnp", 0.85);
        device.add_service("http", "deep", Some(80), 0.7);
        device.add_evidence("upnp", "manufacturer", "Sony Corporation", 0.8);

        let summary = device_log_summary(
            &device,
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
        );

        assert!(summary.contains("ip=192.168.22.153"));
        assert!(summary.contains("iface=en7"));
        assert!(summary.contains("mac=aa:bb:cc:**:**:**"));
        assert!(summary.contains("vendor=Sony_Corporation"));
        assert!(summary.contains("model=BRAVIA_4K_VH2"));
        assert!(summary.contains("name=Living_Room_TV"));
        assert!(summary.contains("os=Android_TV"));
        assert!(summary.contains("conf="));
        assert!(summary.contains("sources="));
        let expected_seen = now.with_timezone(&Local).format("%H:%M:%S");
        assert!(summary.contains(&format!("seen={expected_seen}")));
        assert!(summary.contains("svc=1"));
        assert!(summary.contains("ev=1"));
    }

    #[test]
    fn live_log_lines_truncate_to_panel_width() {
        let entry = LiveLogEntry {
            timestamp: Local.with_ymd_and_hms(2026, 1, 1, 12, 34, 56).unwrap(),
            level: LiveLogLevel::Device,
            message: "device updated ip=192.168.22.153 iface=en7 vendor=Sony_Corporation model=BRAVIA_4K_VH2 name=Living_Room_TV os=Android_TV sources=AOU".to_string(),
        };

        let line = styled_log_line(&entry, 72);
        let text = line_to_string(&line);

        assert_eq!(text.chars().count(), 72);
        assert!(text.ends_with('~'));
        assert!(text.contains("ip=192.168.22.153"));
    }

    #[test]
    fn live_tui_omits_device_type_column() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.set_device_type_guess("smart-home", "identity_rule", 0.68);

        let columns = visible_columns(180);
        assert!(!columns.iter().any(|column| column.title() == "Type"));

        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());
        app.apply(ScanEvent::DeviceUpdated(Box::new(device)));
        let frame = render_app_to_text(&mut app, 180, 30);
        assert!(!frame.contains("Type"));
        assert!(!frame.contains("type="));
        assert!(!frame.contains("smart-home"));
    }

    #[test]
    fn source_column_uses_single_letter_source_codes() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Example Inc".to_string());
        device.add_name("host.local", "mdns", 0.9);
        device.add_evidence("deep", "port", "443", 0.55);
        device.add_evidence("local", "hostname", "host", 0.95);

        let sources = DeviceTableColumn {
            kind: DeviceColumn::Sources,
            width: 10,
        }
        .value(&device, OutputOptions::default());
        assert_eq!(sources, "ADLMO");
    }

    #[test]
    fn live_tui_renders_interface_panel_with_mac_masking() {
        let iface = InterfaceInfo {
            name: "en0".to_string(),
            ip: "192.168.1.2".parse().unwrap(),
            netmask: "255.255.255.0".parse().unwrap(),
            prefix: 24,
            network: "192.168.1.0/24".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
        };
        let mut app = LiveTable::new(
            OutputOptions {
                mac: MacAddressDisplay::MaskLower24,
            },
            LiveInterfacePanel {
                interfaces: vec![iface],
                default_interface: Some("en0".to_string()),
                scan_interfaces: vec!["en0".to_string()],
            },
        );

        let frame = render_app_to_text(&mut app, 180, 34);

        assert!(frame.contains("Interfaces"));
        assert!(frame.contains("en0"));
        assert!(frame.contains("192.168.1.0/24"));
        assert!(frame.contains("aa:bb:cc:**:**:**"));
        assert!(!frame.contains("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn live_tui_panels_pad_content_horizontally() {
        let mut app = LiveTable::new(OutputOptions::default(), sample_interface_panel());
        let frame = render_app_to_text(&mut app, 180, 30);

        let status_line = frame.lines().find(|line| line.contains("status=")).unwrap();
        assert_eq!(char_before_text(status_line, "status="), Some(' '));

        let interface_header = frame
            .lines()
            .find(|line| line.contains("Use") && line.contains("Def") && line.contains("IPv4"))
            .unwrap();
        assert_eq!(char_before_text(interface_header, "Use"), Some(' '));

        let device_header = frame
            .lines()
            .find(|line| line.contains("IP") && line.contains("Iface") && line.contains("Conf"))
            .unwrap();
        assert_eq!(char_before_text(device_header, "IP"), Some(' '));
    }

    #[test]
    fn continuous_live_updates_do_not_erase_existing_identity() {
        let first_seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let later_seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 5).unwrap();
        let ip = "192.168.1.44".parse().unwrap();
        let mut enriched = Device::new(ip, first_seen);
        enriched.interface = Some("en0".to_string());
        enriched.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        enriched.vendor = Some("Example Inc".to_string());
        enriched.add_name("workstation.local", "mdns", 0.9);
        enriched.set_os_guess("macOS", "mdns", 0.85);
        enriched.add_service("_ssh._tcp.local", "mdns", Some(22), 0.75);

        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());
        app.apply(ScanEvent::DeviceUpdated(Box::new(enriched)));

        let mut next_round_arp_only = Device::new(ip, later_seen);
        next_round_arp_only.interface = Some("en0".to_string());
        next_round_arp_only.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        next_round_arp_only.vendor = Some("Example Inc".to_string());
        app.apply(ScanEvent::DeviceUpdated(Box::new(next_round_arp_only)));

        let stored = app
            .devices
            .get(&DeviceKey {
                interface: "en0".to_string(),
                ip,
            })
            .expect("live table should keep the device row");

        assert_eq!(stored.hostname.as_deref(), Some("workstation"));
        assert_eq!(
            stored.os.as_ref().map(|guess| guess.value.as_str()),
            Some("macOS")
        );
        assert!(
            stored
                .services
                .iter()
                .any(|service| service.name == "_ssh._tcp.local")
        );
        assert_eq!(stored.last_seen, later_seen);
        assert_eq!(app.logs.len(), 1);
    }

    #[test]
    fn continuous_round_marks_unseen_devices_stale() {
        let first_round = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let second_round = Utc.with_ymd_and_hms(2026, 1, 1, 0, 1, 0).unwrap();
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        app.apply(ScanEvent::RoundStarted { round: 1 });
        for ip in ["192.168.1.10", "192.168.1.20"] {
            let mut device = Device::new(ip.parse().unwrap(), first_round);
            device.interface = Some("en0".to_string());
            app.apply(ScanEvent::DeviceUpdated(Box::new(device)));
        }

        app.apply(ScanEvent::RoundStarted { round: 2 });
        let stale_key = DeviceKey {
            interface: "en0".to_string(),
            ip: "192.168.1.10".parse().unwrap(),
        };
        let refreshed_key = DeviceKey {
            interface: "en0".to_string(),
            ip: "192.168.1.20".parse().unwrap(),
        };
        assert!(!app.device_is_current_round(&stale_key));
        assert!(!app.device_is_current_round(&refreshed_key));

        let mut refreshed = Device::new(refreshed_key.ip, second_round);
        refreshed.interface = Some("en0".to_string());
        app.apply(ScanEvent::DeviceUpdated(Box::new(refreshed)));

        assert!(!app.device_is_current_round(&stale_key));
        assert!(app.device_is_current_round(&refreshed_key));
    }

    #[test]
    fn continuous_live_replaces_same_ip_when_mac_changes() {
        let first_seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let later_seen = Utc.with_ymd_and_hms(2026, 1, 1, 0, 5, 0).unwrap();
        let ip = "192.168.1.44".parse().unwrap();
        let key = DeviceKey {
            interface: "en0".to_string(),
            ip,
        };
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        app.apply(ScanEvent::RoundStarted { round: 1 });
        let mut first = Device::new(ip, first_seen);
        first.interface = Some("en0".to_string());
        first.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        first.vendor = Some("Old Vendor".to_string());
        first.add_name("old-host.local", "mdns", 0.9);
        first.add_service("http", "deep", Some(80), 0.7);
        app.apply(ScanEvent::DeviceUpdated(Box::new(first)));

        app.apply(ScanEvent::RoundStarted { round: 2 });
        let mut replacement = Device::new(ip, later_seen);
        replacement.interface = Some("en0".to_string());
        replacement.mac = Some("00:11:22:33:44:55".to_string());
        replacement.vendor = Some("New Vendor".to_string());
        app.apply(ScanEvent::DeviceUpdated(Box::new(replacement)));

        let stored = app
            .devices
            .get(&key)
            .expect("device row should remain keyed by IP");
        assert_eq!(stored.mac.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(stored.vendor.as_deref(), Some("New Vendor"));
        assert!(stored.hostname.is_none());
        assert!(stored.services.is_empty());
        assert_eq!(stored.first_seen, later_seen);
        assert_eq!(stored.last_seen, later_seen);
        assert!(app.device_is_current_round(&key));
    }

    #[test]
    fn live_tui_selects_the_most_recently_refreshed_device() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        for ip in ["192.168.1.10", "192.168.1.30", "192.168.1.20"] {
            let mut device = Device::new(ip.parse().unwrap(), now);
            device.interface = Some("en0".to_string());
            app.apply(ScanEvent::DeviceUpdated(Box::new(device)));
        }

        assert_eq!(app.table_state.selected(), Some(1));

        let mut refreshed = Device::new("192.168.1.30".parse().unwrap(), now);
        refreshed.interface = Some("en0".to_string());
        app.apply(ScanEvent::DeviceUpdated(Box::new(refreshed)));

        assert_eq!(app.table_state.selected(), Some(2));
    }

    #[test]
    fn live_tui_cursor_is_user_navigable() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        for ip in ["192.168.1.10", "192.168.1.30", "192.168.1.20"] {
            let mut device = Device::new(ip.parse().unwrap(), now);
            device.interface = Some("en0".to_string());
            app.apply(ScanEvent::DeviceUpdated(Box::new(device)));
        }

        assert_eq!(app.table_state.selected(), Some(1));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(2));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(1));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(2));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(1));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(2));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(0));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(0));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(2));
    }

    #[test]
    fn live_tui_ctrl_z_pause_freezes_auto_follow_until_escape_resumes() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        for ip in ["192.168.1.10", "192.168.1.20"] {
            let mut device = Device::new(ip.parse().unwrap(), now);
            device.interface = Some("en0".to_string());
            app.apply(ScanEvent::DeviceUpdated(Box::new(device)));
        }

        assert_eq!(app.table_state.selected(), Some(1));
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::CONTROL)),
            LiveInputAction::Pause
        );
        assert!(app.paused);
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.table_state.selected(), Some(0));

        let mut refreshed = Device::new("192.168.1.20".parse().unwrap(), now);
        refreshed.interface = Some("en0".to_string());
        refreshed.add_name("updated", "mdns", 0.9);
        app.apply(ScanEvent::DeviceUpdated(Box::new(refreshed)));
        assert_eq!(app.table_state.selected(), Some(0));

        let frame = render_app_to_text(&mut app, 140, 30);
        let last_row = frame.lines().last().unwrap_or_default();
        assert!(last_row.trim_end().ends_with("Paused"));
        assert!(last_row.ends_with(' '));

        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            LiveInputAction::Resume
        );
        assert!(!app.paused);
    }

    #[test]
    fn live_tui_filters_devices_with_case_insensitive_partial_search() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        let mut nas = Device::new("192.168.1.10".parse().unwrap(), now);
        nas.interface = Some("en0".to_string());
        nas.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        nas.vendor = Some("Synology Incorporated".to_string());
        nas.set_model_guess("RS819", "upnp", 0.85);
        nas.add_name("utakata", "mdns", 0.9);
        nas.set_os_guess("DSM", "upnp", 0.85);

        let mut laptop = Device::new("192.168.1.20".parse().unwrap(), now);
        laptop.interface = Some("en0".to_string());
        laptop.mac = Some("00:e0:4c:96:80:5b".to_string());
        laptop.vendor = Some("Apple, Inc.".to_string());
        laptop.add_name("Shizk-Book", "mdns", 0.9);
        laptop.set_os_guess("macOS", "mdns", 0.85);

        app.apply(ScanEvent::DeviceUpdated(Box::new(nas)));
        app.apply(ScanEvent::DeviceUpdated(Box::new(laptop)));

        assert_eq!(app.handle_key(key('/')), LiveInputAction::Continue);
        for ch in "apple".chars() {
            assert_eq!(app.handle_key(key(ch)), LiveInputAction::Continue);
        }

        let visible = app.visible_device_entries();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].1.vendor.as_deref(), Some("Apple, Inc."));

        let frame = render_app_to_text(&mut app, 180, 34);
        assert!(frame.contains("filter=/apple"));

        let lines = frame.lines().collect::<Vec<_>>();
        let last_row = lines.last().copied().unwrap_or_default();
        assert!(last_row.starts_with(" Sources:"));
        assert!(last_row.trim_end().ends_with("filter=/apple"));
        assert!(last_row.ends_with(' '));
        assert!(
            !lines[..lines.len().saturating_sub(1)]
                .iter()
                .any(|line| line.contains("filter=/apple"))
        );
    }

    #[test]
    fn source_footer_truncates_sources_before_right_aligned_filter() {
        let line = source_footer_line(36, "filter=/apple".to_string());
        let text = line_to_string(&line);

        assert_eq!(text.chars().count(), 36);
        assert!(text.starts_with(" Sources:"));
        assert!(text.trim_end().ends_with("filter=/apple"));
        assert!(text.ends_with(' '));
        assert!(text.contains('~'));
        assert!(!text.contains("K=Cache"));
    }

    #[test]
    fn source_footer_right_indicator_uses_green_chrome() {
        let filter_line = source_footer_line(80, "filter=/apple".to_string());
        let filter_spans = filter_line.spans;
        let filter_start = filter_spans
            .iter()
            .position(|span| span.content.as_ref() == "filter=")
            .unwrap();
        assert_eq!(
            filter_spans[filter_start].style.fg,
            Some(NeonTheme::ACCENT_GREEN)
        );
        assert_eq!(
            filter_spans[filter_start + 1].style.fg,
            Some(NeonTheme::ACCENT_GREEN)
        );

        let paused_line = source_footer_line(80, "Paused".to_string());
        let paused = paused_line
            .spans
            .iter()
            .find(|span| span.content.as_ref() == "Paused")
            .unwrap();
        assert_eq!(paused.style.fg, Some(NeonTheme::ACCENT_GREEN));
    }

    #[test]
    fn live_tui_search_matches_ip_mac_model_name_and_os() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let mut device = Device::new("192.168.1.10".parse().unwrap(), now);
        device.mac = Some("aa:bb:cc:dd:ee:ff".to_string());
        device.vendor = Some("Synology Incorporated".to_string());
        device.set_model_guess("RS819", "upnp", 0.85);
        device.add_name("utakata", "mdns", 0.9);
        device.set_os_guess("DSM", "upnp", 0.85);

        for query in ["192.168.1", "AA:BB", "synology", "rs819", "TAKA", "dsm"] {
            assert!(
                device_matches_search(&device, query),
                "{query} should match searchable device fields"
            );
        }
        assert!(!device_matches_search(&device, "android"));
    }

    #[test]
    fn live_tui_escape_clears_search_without_exiting() {
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        assert_eq!(app.handle_key(key('/')), LiveInputAction::Continue);
        assert_eq!(app.handle_key(key('n')), LiveInputAction::Continue);
        assert_eq!(app.search_query, "n");

        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert!(app.search_query.is_empty());
        assert!(!app.search_editing);

        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            LiveInputAction::Continue
        );
        assert_eq!(app.handle_key(key('q')), LiveInputAction::Continue);
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            LiveInputAction::Exit
        );
    }

    #[test]
    fn live_tui_moves_status_summary_into_live_scan_panel() {
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());
        app.apply(ScanEvent::Started {
            target: "192.168.20.0/22".to_string(),
            interface: "en7".to_string(),
            profile: crate::scanner::ScanProfile::Normal,
        });
        app.apply(ScanEvent::Phase("ARP discovery".to_string()));

        let frame = render_app_to_text(&mut app, 140, 28);

        assert!(frame.contains("Live Scan"));
        assert!(frame.contains("status=scanning  profile=normal  phase=ARP discovery"));
        assert!(!frame.contains("Status"));
        assert!(!frame.contains("devices=0"));
        assert!(!frame.contains("phase ARP discovery"));
        assert!(!frame.contains("Selected Device"));
    }

    #[test]
    fn live_tui_reserves_bottom_row_for_source_legend() {
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        let frame = render_app_to_text(&mut app, 180, 30);
        let last_row = frame.lines().last().unwrap_or_default();

        assert!(last_row.contains("Sources:"));
        assert!(last_row.starts_with(" Sources:"));
        assert!(last_row.contains("A=ARP"));
        assert!(last_row.contains("O=OUI"));
        assert!(last_row.contains("M=mDNS"));
    }

    #[test]
    fn live_tui_reserves_top_row_for_keyboard_help() {
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());

        let frame = render_app_to_text(&mut app, 180, 30);
        let first_row = frame.lines().next().unwrap_or_default();

        assert!(first_row.contains("Keys:"));
        assert!(first_row.starts_with(" Keys:"));
        assert!(first_row.contains("Ctrl-Z=Pause"));
        assert!(!first_row.contains("w=Pause"));
        assert!(!first_row.contains("Esc=Resume"));
        assert!(first_row.contains("j=Down k=Up"));
        assert!(first_row.contains("Ctrl-D=PageDown"));
        assert!(first_row.contains("Ctrl-U=PageUp"));
        assert!(!first_row.contains("Ctrl-D/U"));
        assert!(!first_row.contains("Up/Down,j/k"));
        assert!(!first_row.contains('|'));
        assert!(first_row.contains("Ctrl-C=Quit"));
        assert!(first_row.contains("Now="));
        assert!(first_row.ends_with(' '));
        assert!(!first_row.contains("Live Scan"));
    }

    #[test]
    fn live_tui_uses_injected_time_source_for_chrome() {
        let now = Local.with_ymd_and_hms(2026, 1, 1, 12, 34, 56).unwrap();
        let mut app = LiveTable::new_with_time_source(
            OutputOptions::default(),
            LiveInterfacePanel::default(),
            Arc::new(move || now),
        );
        app.push_log(LiveLogLevel::Info, "scan started target=demo");

        let frame = render_app_to_text(&mut app, 140, 30);

        assert!(
            frame
                .lines()
                .next()
                .unwrap_or_default()
                .contains("Now=12:34:56")
        );
        assert!(frame.contains("12:34:56 scan started"));
    }

    #[test]
    fn help_line_truncates_to_available_width() {
        let now = Local.with_ymd_and_hms(2026, 1, 1, 12, 34, 56).unwrap();
        let line = help_line(48, now);
        let text = line_to_string(&line);

        assert_eq!(text.chars().count(), 48);
        assert!(text.starts_with(" Keys: /=Filter j=Down k=Up"));
        assert!(text.contains("Now=12:34:56"));
        assert!(text.trim_end().ends_with("Now=12:34:56"));
        assert!(text.ends_with(' '));
    }

    #[test]
    fn help_line_styles_keys_label_as_chrome() {
        let now = Local.with_ymd_and_hms(2026, 1, 1, 12, 34, 56).unwrap();
        let line = help_line(120, now);

        assert_eq!(line.spans[1].content.as_ref(), "Keys:");
        assert_eq!(line.spans[1].style.fg, Some(NeonTheme::ACCENT_GREEN));
        assert_eq!(line.spans[2].style.fg, Some(NeonTheme::TEXT));
        assert!(line_to_string(&line).contains("Ctrl-D=PageDown"));
        assert!(line_to_string(&line).contains("Ctrl-U=PageUp"));
        assert!(line_to_string(&line).contains("Now=12:34:56"));
    }

    #[test]
    fn live_tui_log_discards_old_entries_and_autoscrolls() {
        let mut app = LiveTable::new(OutputOptions::default(), LiveInterfacePanel::default());
        for index in 0..(MAX_LIVE_LOG_LINES + 5) {
            app.push_log(LiveLogLevel::Info, format!("log-{index:03}"));
        }

        assert_eq!(app.logs.len(), MAX_LIVE_LOG_LINES);
        assert_eq!(app.logs.front().unwrap().message, "log-005");

        let frame = render_app_to_text(&mut app, 140, 30);
        assert!(frame.contains("log-204"));
        assert!(frame.contains("log-199"));
        assert!(!frame.contains("log-198"));
    }

    fn render_app_to_text(app: &mut LiveTable, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        buffer_to_text(terminal.backend().buffer())
    }

    fn line_to_string(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>()
    }

    fn char_before_text(line: &str, text: &str) -> Option<char> {
        let index = line.find(text)?;
        line[..index].chars().next_back()
    }

    fn key(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)
    }

    fn sample_interface_panel() -> LiveInterfacePanel {
        LiveInterfacePanel {
            interfaces: vec![
                InterfaceInfo {
                    name: "en0".to_string(),
                    ip: "192.168.22.197".parse().unwrap(),
                    netmask: "255.255.252.0".parse().unwrap(),
                    prefix: 22,
                    network: "192.168.20.0/22".parse().unwrap(),
                    mac: Some("22:7c:bf:92:90:95".to_string()),
                },
                InterfaceInfo {
                    name: "en7".to_string(),
                    ip: "192.168.22.206".parse().unwrap(),
                    netmask: "255.255.252.0".parse().unwrap(),
                    prefix: 22,
                    network: "192.168.20.0/22".parse().unwrap(),
                    mac: Some("00:e0:4c:96:80:5b".to_string()),
                },
                InterfaceInfo {
                    name: "utun4".to_string(),
                    ip: "100.100.152.126".parse().unwrap(),
                    netmask: "255.255.255.255".parse().unwrap(),
                    prefix: 32,
                    network: "100.100.152.126/32".parse().unwrap(),
                    mac: Some("00:00:00:00:00:00".to_string()),
                },
            ],
            default_interface: Some("en7".to_string()),
            scan_interfaces: vec!["en7".to_string()],
        }
    }

    fn has_column(columns: &[DeviceTableColumn], kind: DeviceColumn) -> bool {
        columns.iter().any(|column| column.kind == kind)
    }

    fn column_width(columns: &[DeviceTableColumn], kind: DeviceColumn) -> u16 {
        columns
            .iter()
            .find(|column| column.kind == kind)
            .map(|column| column.width)
            .unwrap_or_else(|| panic!("missing {kind:?} column"))
    }

    fn total_device_table_width(columns: &[DeviceTableColumn]) -> u16 {
        columns
            .iter()
            .map(|column| column.width)
            .sum::<u16>()
            .saturating_add(table_spacing_width(columns.len()))
    }

    fn interface_column_width(columns: &[InterfaceTableColumn], kind: InterfaceColumn) -> u16 {
        columns
            .iter()
            .find(|column| column.kind == kind)
            .map(|column| column.width)
            .unwrap_or_else(|| panic!("missing {kind:?} column"))
    }

    fn total_interface_table_width(columns: &[InterfaceTableColumn]) -> u16 {
        columns
            .iter()
            .map(|column| column.width)
            .sum::<u16>()
            .saturating_add(table_spacing_width(columns.len()))
    }

    fn buffer_to_text(buffer: &Buffer) -> String {
        buffer
            .content()
            .chunks(buffer.area.width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

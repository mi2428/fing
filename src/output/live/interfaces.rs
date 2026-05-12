//! Interface reference panel for the live TUI.
//!
//! Interfaces are context for interpreting scan results, especially when the
//! same address can exist on multiple VLANs or VPNs. The panel is deliberately
//! compact and gives most width to the high-churn device/log views.

use super::{
    layout::{
        PANEL_FRAME_WIDTH, fit_cell, panel_content_width, shrink_widths_to_fit, table_spacing_width,
    },
    theme::NeonTheme,
};
use crate::net::InterfaceInfo;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Cell as TuiCell, Paragraph, Row as TuiRow, Table as TuiTable},
};

const MIN_LIVE_SCAN_PANEL_WIDTH: u16 = 24;
pub(super) const INTERFACE_PANEL_VISIBLE_ROWS: u16 = 6;

#[derive(Debug, Clone, Default)]
pub struct LiveInterfacePanel {
    pub interfaces: Vec<InterfaceInfo>,
    pub default_interface: Option<String>,
    pub scan_interfaces: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InterfaceColumn {
    Use,
    Default,
    Name,
    Ipv4,
    Network,
    Mac,
}

const INTERFACE_COLUMNS_FULL: [InterfaceColumn; 6] = [
    InterfaceColumn::Use,
    InterfaceColumn::Default,
    InterfaceColumn::Name,
    InterfaceColumn::Ipv4,
    InterfaceColumn::Network,
    InterfaceColumn::Mac,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct InterfaceTableColumn {
    pub(super) kind: InterfaceColumn,
    pub(super) width: u16,
}

impl InterfaceTableColumn {
    fn title(self) -> &'static str {
        self.kind.title()
    }

    fn constraint(self) -> Constraint {
        Constraint::Length(self.width)
    }

    fn max_chars(self) -> usize {
        self.width as usize
    }

    fn value(
        self,
        iface: &InterfaceInfo,
        options: super::super::OutputOptions,
        is_scanned: bool,
        is_default: bool,
    ) -> String {
        self.kind.value(iface, options, is_scanned, is_default)
    }
}

impl InterfaceColumn {
    fn title(self) -> &'static str {
        match self {
            Self::Use => "Use",
            Self::Default => "Def",
            Self::Name => "Name",
            Self::Ipv4 => "IPv4",
            Self::Network => "Network",
            Self::Mac => "MAC",
        }
    }

    fn value(
        self,
        iface: &InterfaceInfo,
        options: super::super::OutputOptions,
        is_scanned: bool,
        is_default: bool,
    ) -> String {
        match self {
            Self::Use => {
                if is_scanned {
                    "scan".to_string()
                } else {
                    "-".to_string()
                }
            }
            Self::Default => {
                if is_default {
                    "*".to_string()
                } else {
                    "-".to_string()
                }
            }
            Self::Name => iface.name.clone(),
            Self::Ipv4 => iface.ip.to_string(),
            Self::Network => iface.network.to_string(),
            Self::Mac => super::super::privacy::display_mac(iface.mac.as_deref(), options),
        }
    }
}

pub(super) fn interface_panel_height() -> u16 {
    // The interface panel is reference material rather than a data table. Keep
    // six data slots available regardless of how many NICs the OS reports, so
    // the top row does not jump between laptops, docks, VPNs, and VLAN setups.
    INTERFACE_PANEL_VISIBLE_ROWS + 3
}

pub(super) fn top_panel_height() -> u16 {
    interface_panel_height().max(3)
}

pub(super) fn interface_panel_width(
    available_width: u16,
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) -> u16 {
    let desired = desired_interface_panel_width(interface_column_kinds(), panel, options)
        .max("Interfaces".len() as u16 + 2);
    let max_interface_width = available_width.saturating_sub(MIN_LIVE_SCAN_PANEL_WIDTH);
    if max_interface_width == 0 {
        available_width
    } else {
        desired.min(max_interface_width)
    }
}

pub(super) fn render_interfaces(
    frame: &mut Frame<'_>,
    area: Rect,
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) {
    if panel.interfaces.is_empty() {
        frame.render_widget(
            Paragraph::new("No IPv4 interfaces found")
                .style(
                    Style::default()
                        .fg(NeonTheme::DIM)
                        .bg(NeonTheme::BACKGROUND),
                )
                .block(NeonTheme::block("Interfaces")),
            area,
        );
        return;
    }

    let columns = visible_interface_columns(area.width, panel, options);
    let header = TuiRow::new(columns.iter().map(|column| TuiCell::from(column.title())))
        .style(NeonTheme::table_header());
    let rows = panel
        .interfaces
        .iter()
        .map(|iface| interface_row(iface, &columns, panel, options))
        .collect::<Vec<_>>();
    let table = TuiTable::new(
        rows,
        columns
            .iter()
            .map(|column| column.constraint())
            .collect::<Vec<_>>(),
    )
    .header(header)
    .block(NeonTheme::block("Interfaces"))
    .style(NeonTheme::panel())
    .column_spacing(super::layout::TABLE_COLUMN_SPACING);

    frame.render_widget(table, area);
}

fn interface_row(
    iface: &InterfaceInfo,
    columns: &[InterfaceTableColumn],
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) -> TuiRow<'static> {
    let is_scanned = scans_interface(panel, iface);
    let is_default = default_interface_name(panel) == Some(iface.name.as_str());
    let style = interface_row_style(is_scanned, is_default);

    TuiRow::new(
        columns
            .iter()
            .map(|column| {
                TuiCell::from(fit_cell(
                    column.value(iface, options, is_scanned, is_default),
                    column.max_chars(),
                ))
            })
            .collect::<Vec<_>>(),
    )
    .style(style)
}

fn scans_interface(panel: &LiveInterfacePanel, iface: &InterfaceInfo) -> bool {
    panel.scan_interfaces.iter().any(|name| name == &iface.name)
}

fn default_interface_name(panel: &LiveInterfacePanel) -> Option<&str> {
    panel.default_interface.as_deref()
}

pub(super) fn interface_row_style(is_scanned: bool, is_default: bool) -> Style {
    if is_scanned {
        // Interface rows are scan data. Use a brighter orange for the active
        // target instead of the green reserved for headers and key labels.
        Style::default()
            .fg(NeonTheme::PRIMARY_SOFT)
            .bg(NeonTheme::BACKGROUND)
            .add_modifier(Modifier::BOLD)
    } else if is_default {
        Style::default()
            .fg(NeonTheme::TEXT)
            .bg(NeonTheme::BACKGROUND)
    } else {
        Style::default()
            .fg(NeonTheme::DIM)
            .bg(NeonTheme::BACKGROUND)
    }
}

pub(super) fn interface_column_kinds() -> &'static [InterfaceColumn] {
    &INTERFACE_COLUMNS_FULL
}

pub(super) fn visible_interface_columns(
    width: u16,
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) -> Vec<InterfaceTableColumn> {
    // Interfaces is a reference panel. It should not grow to consume the top
    // row because Live Scan carries the high-churn log stream. Start with all
    // columns at their measured content width, then progressively omit lower
    // value columns only when the terminal is too narrow.
    let without_mac = [
        InterfaceColumn::Use,
        InterfaceColumn::Default,
        InterfaceColumn::Name,
        InterfaceColumn::Ipv4,
        InterfaceColumn::Network,
    ];
    let core_with_default = [
        InterfaceColumn::Use,
        InterfaceColumn::Default,
        InterfaceColumn::Name,
        InterfaceColumn::Ipv4,
    ];
    let core = [
        InterfaceColumn::Use,
        InterfaceColumn::Name,
        InterfaceColumn::Ipv4,
    ];
    let absolute_minimum = [InterfaceColumn::Name, InterfaceColumn::Ipv4];
    let candidates: [&[InterfaceColumn]; 5] = [
        &INTERFACE_COLUMNS_FULL,
        &without_mac,
        &core_with_default,
        &core,
        &absolute_minimum,
    ];

    let kinds = candidates
        .iter()
        .copied()
        .find(|kinds| desired_interface_panel_width(kinds, panel, options) <= width)
        .unwrap_or(candidates[candidates.len() - 1]);
    allocate_interface_columns(width, kinds, panel, options)
}

fn allocate_interface_columns(
    width: u16,
    kinds: &[InterfaceColumn],
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) -> Vec<InterfaceTableColumn> {
    let inner_width = panel_content_width(width).saturating_sub(table_spacing_width(kinds.len()));
    let mut widths = kinds
        .iter()
        .map(|kind| desired_interface_column_width(*kind, panel, options))
        .collect::<Vec<_>>();
    shrink_widths_to_fit(&mut widths, interface_minimum_widths(kinds), inner_width);

    kinds
        .iter()
        .zip(widths)
        .map(|(kind, width)| InterfaceTableColumn { kind: *kind, width })
        .collect()
}

pub(super) fn desired_interface_panel_width(
    kinds: &[InterfaceColumn],
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) -> u16 {
    kinds
        .iter()
        .map(|kind| desired_interface_column_width(*kind, panel, options))
        .sum::<u16>()
        .saturating_add(table_spacing_width(kinds.len()))
        .saturating_add(PANEL_FRAME_WIDTH)
}

fn desired_interface_column_width(
    kind: InterfaceColumn,
    panel: &LiveInterfacePanel,
    options: super::super::OutputOptions,
) -> u16 {
    let title_width = kind.title().chars().count();
    let value_width = panel
        .interfaces
        .iter()
        .map(|iface| {
            kind.value(
                iface,
                options,
                panel.scan_interfaces.iter().any(|name| name == &iface.name),
                panel.default_interface.as_deref() == Some(iface.name.as_str()),
            )
            .chars()
            .count()
        })
        .max()
        .unwrap_or(0);
    title_width.max(value_width).try_into().unwrap_or(u16::MAX)
}

fn interface_minimum_widths(kinds: &[InterfaceColumn]) -> Vec<u16> {
    kinds
        .iter()
        .map(|kind| match kind {
            InterfaceColumn::Use => 3,
            InterfaceColumn::Default => 3,
            InterfaceColumn::Name => 4,
            InterfaceColumn::Ipv4 => 7,
            InterfaceColumn::Network => 7,
            InterfaceColumn::Mac => 8,
        })
        .collect()
}

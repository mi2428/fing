//! Live log and footer rendering.
//!
//! Logs are short operational breadcrumbs for the current scan round. They are
//! styled separately from table data so phase changes and device updates remain
//! readable in a dense terminal layout.

use super::{layout::fit_cell, theme::NeonTheme};
use chrono::{DateTime, Local};
use ratatui::{
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

#[derive(Debug, Clone)]
pub(super) struct LiveLogEntry {
    pub(super) timestamp: DateTime<Local>,
    pub(super) level: LiveLogLevel,
    pub(super) message: String,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum LiveLogLevel {
    Info,
    Device,
    Warning,
}

pub(super) fn log_style(level: LiveLogLevel) -> Style {
    let fg = match level {
        LiveLogLevel::Info => NeonTheme::PRIMARY_SOFT,
        LiveLogLevel::Device => NeonTheme::TEXT,
        LiveLogLevel::Warning => NeonTheme::PRIMARY,
    };
    Style::default().fg(fg).bg(NeonTheme::BACKGROUND)
}

pub(super) fn key_span(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), NeonTheme::label())
}

pub(super) fn value_span(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), NeonTheme::value())
}

fn log_key_style(level: LiveLogLevel) -> Style {
    log_style(level).add_modifier(Modifier::BOLD)
}

pub(super) fn styled_log_line(entry: &LiveLogEntry, max_chars: usize) -> Line<'static> {
    let value_style = log_style(entry.level);
    let key_style = log_key_style(entry.level);

    let timestamp = entry.timestamp.format("%H:%M:%S").to_string();
    let raw = format!("{timestamp} {}", entry.message);
    let fitted = fit_cell(raw, max_chars);
    let mut tokens = fitted.split_whitespace();
    let mut spans = Vec::new();
    if let Some(timestamp) = tokens.next() {
        spans.push(Span::styled(timestamp.to_string(), NeonTheme::DIM));
    }

    for token in tokens {
        spans.push(Span::styled(" ", value_style));
        if let Some((key, value)) = token.split_once('=') {
            // The fixed status line owns the green key color. Live logs stay in
            // the orange phosphor family, but key= is still bold so the terse
            // operational records remain scannable.
            spans.push(Span::styled(format!("{key}="), key_style));
            spans.push(Span::styled(value.to_string(), value_style));
        } else {
            spans.push(Span::styled(token.to_string(), value_style));
        }
    }
    Line::from(spans)
}

pub(super) fn source_legend(width: u16, filter: Option<String>) -> Paragraph<'static> {
    let width = width as usize;
    let line = if let Some(filter) = filter {
        source_footer_line(width, filter)
    } else {
        source_legend_line(width)
    };

    Paragraph::new(line).style(NeonTheme::panel())
}

pub(super) fn help_bar(width: u16, now: DateTime<Local>) -> Paragraph<'static> {
    Paragraph::new(help_line(width as usize, now)).style(NeonTheme::panel())
}

pub(super) fn help_line(width: usize, now: DateTime<Local>) -> Line<'static> {
    if width == 0 {
        return Line::from(Vec::<Span<'static>>::new());
    }
    if width <= 2 {
        return Line::from(vec![Span::styled(" ".repeat(width), NeonTheme::panel())]);
    }

    let content_width = width - 2;
    let now_value = now.format("%H:%M:%S").to_string();
    let now_text_len = "Now=".len() + now_value.chars().count();
    if now_text_len >= content_width {
        let fitted = fit_cell(format!("Now={now_value}"), content_width);
        let fitted_len = fitted.chars().count();
        return Line::from(vec![
            Span::styled(" ", NeonTheme::panel()),
            Span::styled(fitted, NeonTheme::label()),
            Span::styled(
                " ".repeat(content_width.saturating_sub(fitted_len) + 1),
                NeonTheme::panel(),
            ),
        ]);
    }

    let gap = 2;
    let left_width = content_width.saturating_sub(now_text_len + gap);
    let left = fit_cell(help_text(), left_width);
    let left_len = left.chars().count();
    let spaces = content_width.saturating_sub(left_len + now_text_len);

    let mut spans = vec![Span::styled(" ", NeonTheme::panel())];
    spans.extend(help_spans(left));
    spans.push(Span::styled(" ".repeat(spaces), NeonTheme::panel()));
    spans.push(Span::styled("Now=", NeonTheme::label()));
    spans.push(Span::styled(now_value, NeonTheme::value()));
    spans.push(Span::styled(" ", NeonTheme::panel()));
    Line::from(spans)
}

fn help_spans(text: String) -> Vec<Span<'static>> {
    if let Some(rest) = text.strip_prefix("Keys:") {
        vec![
            Span::styled("Keys:", NeonTheme::label()),
            Span::styled(rest.to_string(), NeonTheme::value()),
        ]
    } else if text.is_empty() {
        Vec::new()
    } else {
        vec![Span::styled(text, NeonTheme::value())]
    }
}

fn help_text() -> String {
    "Keys: /=Filter j=Down k=Up Ctrl-D=PageDown Ctrl-U=PageUp Ctrl-Z=Pause Ctrl-C=Quit".to_string()
}

pub(super) fn source_footer_line(width: usize, filter: String) -> Line<'static> {
    if width == 0 {
        return Line::from(Vec::<Span<'static>>::new());
    }
    if width <= 2 {
        return Line::from(vec![Span::styled(" ".repeat(width), NeonTheme::panel())]);
    }

    let content_width = width - 2;
    let filter_len = filter.chars().count();
    if filter_len >= content_width {
        let fitted = fit_cell(filter, content_width);
        let fitted_len = fitted.chars().count();
        return Line::from(vec![
            Span::styled(" ", NeonTheme::panel()),
            Span::styled(fitted, NeonTheme::label()),
            Span::styled(
                " ".repeat(content_width.saturating_sub(fitted_len) + 1),
                NeonTheme::panel(),
            ),
        ]);
    }

    let gap = 2;
    let left_width = content_width.saturating_sub(filter_len + gap);
    let left = fit_cell(source_legend_text(), left_width);
    let left_len = left.chars().count();
    let spaces = content_width.saturating_sub(left_len + filter_len);

    let mut spans = vec![Span::styled(" ", NeonTheme::panel())];
    spans.extend(source_legend_plain_spans(left));
    spans.push(Span::styled(" ".repeat(spaces), NeonTheme::panel()));
    spans.extend(filter_spans(filter));
    spans.push(Span::styled(" ", NeonTheme::panel()));
    Line::from(spans)
}

fn source_legend_line(width: usize) -> Line<'static> {
    if width == 0 {
        return Line::from(Vec::<Span<'static>>::new());
    }

    let left = fit_cell(source_legend_text(), width.saturating_sub(1));
    let mut spans = vec![Span::styled(" ", NeonTheme::panel())];
    spans.extend(source_legend_plain_spans(left));
    Line::from(spans)
}

fn source_legend_text() -> String {
    let mut text = String::from("Sources: ");
    for (index, (code, label)) in super::super::sources::SOURCE_LEGEND.iter().enumerate() {
        if index > 0 {
            text.push_str("  ");
        }
        text.push_str(code);
        text.push('=');
        text.push_str(label);
    }
    text
}

fn source_legend_plain_spans(text: String) -> Vec<Span<'static>> {
    if let Some(rest) = text.strip_prefix("Sources:") {
        vec![
            Span::styled("Sources:", NeonTheme::label()),
            Span::styled(rest.to_string(), NeonTheme::value()),
        ]
    } else if text.is_empty() {
        Vec::new()
    } else {
        vec![Span::styled(text, NeonTheme::value())]
    }
}

fn filter_spans(filter: String) -> Vec<Span<'static>> {
    let Some((key, value)) = filter.split_once('=') else {
        return vec![Span::styled(filter, NeonTheme::label())];
    };

    vec![
        Span::styled(format!("{key}="), NeonTheme::label()),
        Span::styled(value.to_string(), NeonTheme::label()),
    ]
}

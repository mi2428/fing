//! Shared live-TUI color and widget styles.
//!
//! Keeping the palette in one module avoids subtle drift between the live scan,
//! device table, interface panel, and footer when new widgets are added.

use super::layout::PANEL_HORIZONTAL_PADDING;
use ratatui::{
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Padding},
};

pub(super) struct NeonTheme;

impl NeonTheme {
    pub(super) const BACKGROUND: Color = Color::Rgb(26, 10, 2);
    pub(super) const HEADER_BG: Color = Color::Rgb(58, 18, 3);
    pub(super) const SELECTED_BG: Color = Color::Rgb(92, 24, 2);
    pub(super) const PRIMARY: Color = Color::Rgb(240, 144, 58);
    pub(super) const PRIMARY_SOFT: Color = Color::Rgb(255, 170, 68);
    pub(super) const TEXT: Color = Color::Rgb(238, 136, 34);
    pub(super) const ACCENT_GREEN: Color = Color::Rgb(88, 242, 165);
    pub(super) const DIM: Color = Color::Rgb(107, 53, 16);

    pub(super) fn panel() -> Style {
        Style::default().fg(Self::TEXT).bg(Self::BACKGROUND)
    }

    pub(super) fn title() -> Style {
        Style::default()
            .fg(Self::PRIMARY)
            .bg(Self::BACKGROUND)
            .add_modifier(Modifier::BOLD)
    }

    pub(super) fn border() -> Style {
        Style::default().fg(Self::PRIMARY).bg(Self::BACKGROUND)
    }

    pub(super) fn label() -> Style {
        Style::default()
            .fg(Self::ACCENT_GREEN)
            .bg(Self::BACKGROUND)
            .add_modifier(Modifier::BOLD)
    }

    pub(super) fn value() -> Style {
        Style::default().fg(Self::TEXT).bg(Self::BACKGROUND)
    }

    pub(super) fn table_header() -> Style {
        Style::default()
            .fg(Self::ACCENT_GREEN)
            .bg(Self::HEADER_BG)
            .add_modifier(Modifier::BOLD)
    }

    pub(super) fn selected_row() -> Style {
        Style::default()
            .fg(Self::PRIMARY_SOFT)
            .bg(Self::SELECTED_BG)
            .add_modifier(Modifier::BOLD)
    }

    pub(super) fn block(title: &'static str) -> Block<'static> {
        Block::default()
            .borders(Borders::ALL)
            .padding(Padding::horizontal(PANEL_HORIZONTAL_PADDING))
            .title(title)
            .style(Self::panel())
            .border_style(Self::border())
            .title_style(Self::title())
    }
}

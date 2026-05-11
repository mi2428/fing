//! Terminal session lifecycle for the live TUI.
//!
//! Raw mode and alternate-screen setup are kept behind `TuiSession` so early
//! returns and panics during drawing still run the Drop cleanup path.

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Frame, Terminal, backend::CrosstermBackend};
use std::io;

pub(super) struct TuiSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TuiSession {
    pub(super) fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        Ok(Self { terminal })
    }

    pub(super) fn draw<F>(&mut self, f: F) -> io::Result<()>
    where
        F: FnOnce(&mut Frame<'_>),
    {
        self.terminal.draw(f)?;
        Ok(())
    }
}

impl Drop for TuiSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

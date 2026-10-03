//! Terminal session lifecycle for the live TUI.
//!
//! Raw mode and alternate-screen setup are kept behind `TuiSession` so early
//! returns and panics during drawing still run the Drop cleanup path.

use crossterm::{
    cursor::Show,
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Frame, Terminal, backend::CrosstermBackend};
use std::io;

pub(super) struct TuiSession {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    _cleanup: TerminalCleanup<fn()>,
}

impl TuiSession {
    pub(super) fn enter() -> io::Result<Self> {
        let (terminal, cleanup) = enter_terminal(
            enable_raw_mode,
            || execute!(io::stdout(), EnterAlternateScreen),
            || Terminal::new(CrosstermBackend::new(io::stdout())),
            Terminal::clear,
            restore_terminal as fn(),
        )?;
        Ok(Self {
            terminal,
            _cleanup: cleanup,
        })
    }

    pub(super) fn draw<F>(&mut self, f: F) -> io::Result<()>
    where
        F: FnOnce(&mut Frame<'_>),
    {
        self.terminal.draw(f)?;
        Ok(())
    }
}

// Keep the same guard alive during initialization and throughout the session.
struct TerminalCleanup<F: FnMut()>(F);

impl<F: FnMut()> Drop for TerminalCleanup<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

fn enter_terminal<T, F: FnMut()>(
    enable_raw: impl FnOnce() -> io::Result<()>,
    enter_screen: impl FnOnce() -> io::Result<()>,
    create_terminal: impl FnOnce() -> io::Result<T>,
    clear: impl FnOnce(&mut T) -> io::Result<()>,
    restore: F,
) -> io::Result<(T, TerminalCleanup<F>)> {
    enable_raw()?;
    let cleanup = TerminalCleanup(restore);
    enter_screen()?;
    let mut terminal = create_terminal()?;
    clear(&mut terminal)?;
    Ok((terminal, cleanup))
}

fn restore_terminal() {
    restore_terminal_with(
        disable_raw_mode,
        || execute!(io::stdout(), LeaveAlternateScreen),
        || execute!(io::stdout(), Show),
    );
}

fn restore_terminal_with(
    disable_raw: impl FnOnce() -> io::Result<()>,
    leave_screen: impl FnOnce() -> io::Result<()>,
    show_cursor: impl FnOnce() -> io::Result<()>,
) {
    let _ = disable_raw();
    let _ = leave_screen();
    let _ = show_cursor();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn terminal_cleanup_covers_acquisition_errors_and_session_exit() {
        for failure in [
            Some("raw"),
            Some("screen"),
            Some("create"),
            Some("clear"),
            Some("draw"),
            None,
        ] {
            let calls = RefCell::new(Vec::new());
            let step = |name| {
                calls.borrow_mut().push(name);
                if failure == Some(name) {
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, name))
                } else {
                    Ok(())
                }
            };
            let restore = |name| {
                calls.borrow_mut().push(name);
                Err(io::Error::other("cleanup failed"))
            };
            let result = (|| {
                let (_terminal, _cleanup) = enter_terminal(
                    || step("raw"),
                    || step("screen"),
                    || step("create"),
                    |_| step("clear"),
                    || {
                        restore_terminal_with(
                            || restore("disable_raw"),
                            || restore("leave_screen"),
                            || restore("show_cursor"),
                        );
                    },
                )?;
                step("draw")
            })();
            if let Some(failure) = failure {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), failure);
            } else {
                result.unwrap();
            }
            let mut expected = vec!["raw", "screen", "create", "clear", "draw"];
            if let Some(failure) = failure {
                expected.truncate(expected.iter().position(|&step| step == failure).unwrap() + 1);
            }
            if failure != Some("raw") {
                expected.extend(["disable_raw", "leave_screen", "show_cursor"]);
            }
            assert_eq!(*calls.borrow(), expected);
        }
    }
}

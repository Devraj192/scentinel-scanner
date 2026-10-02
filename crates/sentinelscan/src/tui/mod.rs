pub mod app;
pub mod keys;
pub mod screens;
pub mod theme;

use std::io::{self, IsTerminal};
use std::time::Duration;

use anyhow::anyhow;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use self::app::App;
use self::screens::render;

/// Maximum redraw rate: 20 frames per second. Scan events and keys wake the
/// loop early, but drawing itself never exceeds this rate.
const FRAME_BUDGET: Duration = Duration::from_millis(50);

/// Smallest usable terminal. Below this, a message replaces the UI instead
/// of corrupted output.
const MIN_WIDTH: u16 = 60;
const MIN_HEIGHT: u16 = 12;

/// Restore a usable terminal, best effort. Called on normal exit and from the
/// panic hook, so a crash never leaves raw mode behind.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = io::stdout().execute(LeaveAlternateScreen);
}

/// Full-screen UI over the shared engine event stream. Requires a terminal;
/// scripts and pipes keep the classic CLI.
pub async fn launch() -> anyhow::Result<()> {
    if !io::stdin().is_terminal() {
        return Err(anyhow!(
            "the interface needs a terminal; pipe input to the scan command instead"
        ));
    }
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        hook(info);
    }));
    enable_raw_mode().map_err(|e| anyhow!("cannot enter raw mode: {e}"))?;
    let mut stdout = io::stdout();
    stdout
        .execute(EnterAlternateScreen)
        .map_err(|e| anyhow!("cannot enter alternate screen: {e}"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(|e| anyhow!("cannot start terminal: {e}"))?;
    let result = run_app(&mut terminal).await;
    restore_terminal();
    result
}

async fn run_app(terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> anyhow::Result<()> {
    let mut app = App::new().await?;
    let mut last_draw = std::time::Instant::now()
        .checked_sub(FRAME_BUDGET)
        .unwrap_or_else(std::time::Instant::now);
    loop {
        app.drain_scan_events();
        let size = terminal.size().map_err(|e| anyhow!("terminal size: {e}"))?;
        let now = std::time::Instant::now();
        if now.duration_since(last_draw) >= FRAME_BUDGET {
            if size.width < MIN_WIDTH || size.height < MIN_HEIGHT {
                terminal
                    .draw(|frame| {
                        frame.render_widget(
                            ratatui::widgets::Paragraph::new(
                                "Terminal too small: widen to 60x12 or more.",
                            ),
                            frame.area(),
                        );
                    })
                    .map_err(|e| anyhow!("draw: {e}"))?;
            } else {
                terminal
                    .draw(|frame| render(frame, &mut app))
                    .map_err(|e| anyhow!("draw: {e}"))?;
            }
            last_draw = now;
        }
        if event::poll(Duration::from_millis(10)).map_err(|e| anyhow!("input: {e}"))? {
            match event::read().map_err(|e| anyhow!("input: {e}"))? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    if !app.handle_key(key.code, key.modifiers) {
                        return Ok(());
                    }
                    // Keys redraw immediately; the budget still caps scans.
                    last_draw = std::time::Instant::now()
                        .checked_sub(FRAME_BUDGET)
                        .unwrap_or_else(std::time::Instant::now);
                }
                Event::Resize(_, _) => {
                    last_draw = std::time::Instant::now()
                        .checked_sub(FRAME_BUDGET)
                        .unwrap_or_else(std::time::Instant::now);
                }
                _ => {}
            }
        }
    }
}

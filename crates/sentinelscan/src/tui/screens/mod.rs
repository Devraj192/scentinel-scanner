pub mod compare;
pub mod detail;
pub mod help;
pub mod history;
pub mod home;
pub mod live;
pub mod new_scan;
pub mod results;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::app::{App, Screen};
use super::keys;
use crate::tui::theme::Theme;

/// Vertical split: body plus a two-line footer.
pub fn body_and_footer(frame: &Frame) -> (Rect, Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(frame.area());
    (chunks[0], chunks[1])
}

/// Footer with every keybinding, wrapped over two lines. Shown on every screen.
pub fn footer(frame: &mut Frame, area: Rect, _theme: &Theme) {
    let [first, second] = keys::footer_lines();
    let lines = vec![Line::from(Span::raw(first)), Line::from(Span::raw(second))];
    frame.render_widget(Paragraph::new(lines), area);
}

/// Centered rectangle for popups and confirmations.
pub fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let margin_x = area.width.saturating_sub(width) / 2;
    let margin_y = area.height.saturating_sub(height) / 2;
    Rect {
        x: area.x + margin_x,
        y: area.y + margin_y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

/// Panel block with the themed border.
pub fn panel<'a>(theme: &Theme, title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(theme.border())
        .title(title)
}

/// Dispatch to the active screen.
pub fn render(frame: &mut Frame, app: &mut App) {
    match app.screen {
        Screen::Home => home::render(frame, app),
        Screen::NewScan => new_scan::render(frame, app),
        Screen::Live => live::render(frame, app),
        Screen::Results => results::render(frame, app),
        Screen::Detail => detail::render(frame, app),
        Screen::History => history::render(frame, app),
        Screen::Compare => compare::render(frame, app),
        Screen::Help => help::render(frame, app),
    }
}

/// Strip control and escape sequences before rendering: a hostile service
/// must only ever appear as inert text.
pub fn safe(text: &str) -> String {
    sentinelscan_core::results::model::sanitize(text)
}

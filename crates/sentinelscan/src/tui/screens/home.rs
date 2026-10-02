use ratatui::text::Line;
use ratatui::widgets::{List, ListItem, Paragraph};
use ratatui::Frame;

use super::{body_and_footer, footer, panel, safe};
use crate::tui::app::App;

const MENU: &[&str] = &["New scan", "History", "Compare", "Help"];

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let mut lines = vec![Line::from("SentinelScan: authorized scanning only.")];
    lines.push(Line::from(format!("Recent scans: {}", app.history.len())));
    for item in app.history.iter().take(5) {
        lines.push(Line::from(format!(
            "  {} {} {}",
            safe(&item.scan_id),
            item.status,
            safe(&item.targets.join(" "))
        )));
    }
    lines.push(Line::from(safe(&app.doctor_line)));
    if !app.message.is_empty() {
        lines.push(Line::from(safe(&app.message)));
    }
    let menu: Vec<ListItem> = MENU
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let marker = if index == app.home_menu { "> " } else { "  " };
            ListItem::new(format!("{marker}{item}"))
        })
        .collect();
    let chunks = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Length(lines.len() as u16 + 2),
            ratatui::layout::Constraint::Min(4),
        ])
        .split(body);
    frame.render_widget(
        Paragraph::new(lines).block(panel(&theme, "Home (n new, h history, c compare, ? help)")),
        chunks[0],
    );
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(app.home_menu));
    frame.render_stateful_widget(
        List::new(menu)
            .block(panel(&theme, "Menu"))
            .highlight_symbol("> "),
        chunks[1],
        &mut state,
    );
    footer(frame, foot, &theme);
}

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Row, Table, TableState};
use ratatui::Frame;

use super::{body_and_footer, footer, panel, safe};
use crate::tui::app::App;

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(body);
    let rows: Vec<Row> = app
        .history
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let mut marker = if index == app.hist_sel { ">" } else { " " }.to_owned();
            if Some(&item.scan_id) == app.compare_a.as_ref() {
                marker.push('A');
            }
            if Some(&item.scan_id) == app.compare_b.as_ref() {
                marker.push('B');
            }
            Row::new(vec![
                marker,
                safe(&item.scan_id),
                item.status.clone(),
                item.open_port_count.to_string(),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Percentage(50),
            Constraint::Percentage(20),
            Constraint::Percentage(26),
        ],
    )
    .header(Row::new(vec!["", "SCAN", "STATUS", "OPEN"]).style(theme.title()))
    .block(panel(&theme, "Pick scans (a sets A, b sets B)"))
    .row_highlight_style(theme.title())
    .highlight_symbol("> ");
    let mut state = TableState::default();
    state.select(Some(app.hist_sel.min(app.history.len().saturating_sub(1))));
    frame.render_stateful_widget(table, chunks[0], &mut state);
    let mut lines = vec![Line::from(format!(
        "A: {}   B: {}",
        app.compare_a.as_deref().unwrap_or("-"),
        app.compare_b.as_deref().unwrap_or("-")
    ))];
    if let Some(comparison) = &app.comparison {
        for change in comparison
            .added
            .iter()
            .map(|c| format!("added {}:{}", c.host, c.port))
            .chain(
                comparison
                    .removed
                    .iter()
                    .map(|c| format!("removed {}:{}", c.host, c.port)),
            )
            .chain(comparison.changed.iter().map(|c| {
                format!(
                    "changed {}:{} {} -> {}",
                    c.host,
                    c.port,
                    c.old_state.as_deref().unwrap_or("-"),
                    c.new_state.as_deref().unwrap_or("-")
                )
            }))
            .take(20)
        {
            lines.push(Line::from(safe(&change)));
        }
    } else {
        lines.push(Line::from("Select two scans to compare."));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel(&theme, "Differences")),
        chunks[1],
    );
    footer(frame, foot, &theme);
}

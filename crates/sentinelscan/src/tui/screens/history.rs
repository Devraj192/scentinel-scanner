use ratatui::layout::Constraint;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use super::{body_and_footer, footer, panel, safe};
use crate::tui::app::App;

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let rows: Vec<Row> = app
        .history
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let marker = if Some(&item.scan_id) == app.compare_a.as_ref() {
                "A"
            } else if Some(&item.scan_id) == app.compare_b.as_ref() {
                "B"
            } else if index == app.hist_sel {
                ">"
            } else {
                " "
            };
            let status = if item.status == "complete" {
                Cell::from(item.status.clone())
            } else {
                Cell::from(Span::styled(item.status.clone(), theme.warn()))
            };
            Row::new(vec![
                Cell::from(marker.to_owned()),
                Cell::from(safe(&item.scan_id)),
                status,
                Cell::from(safe(&item.targets.join(" "))),
                Cell::from(item.open_port_count.to_string()),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Percentage(30),
            Constraint::Percentage(12),
            Constraint::Percentage(38),
            Constraint::Percentage(17),
        ],
    )
    .header(Row::new(vec!["", "SCAN", "STATUS", "TARGETS", "OPEN"]).style(theme.title()))
    .block(panel(&theme, "History (Enter opens, d deletes, e exports)"))
    .row_highlight_style(theme.title())
    .highlight_symbol("> ");
    let mut state = TableState::default();
    state.select(Some(app.hist_sel.min(app.history.len().saturating_sub(1))));
    frame.render_stateful_widget(table, body, &mut state);
    if app.confirm_delete {
        frame.render_widget(
            Paragraph::new(Line::from("Press d again to delete this scan.")),
            foot,
        );
    } else if app.entering_path.is_some() {
        let kind = format!("{:?}", app.export_kind).to_lowercase();
        let path = app.entering_path.clone().unwrap_or_default();
        frame.render_widget(
            Paragraph::new(Line::from(format!(
                "Export {kind} to: {path} (Tab format, Enter writes)"
            ))),
            foot,
        );
    } else if !app.message.is_empty() {
        frame.render_widget(Paragraph::new(Line::from(safe(&app.message))), foot);
    } else {
        footer(frame, foot, &theme);
    }
}

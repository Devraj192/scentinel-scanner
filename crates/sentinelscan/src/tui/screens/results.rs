use ratatui::layout::Constraint;
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Row, Table, TableState};
use ratatui::Frame;

use super::{body_and_footer, footer, panel, safe};
use crate::tui::app::{App, SortKey};

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let rows_data = app.visible_rows();
    let scan = app.results_scan.clone();
    let rows: Vec<Row> = rows_data
        .iter()
        .map(|(host_index, port_index)| {
            let host = &scan.as_ref().expect("rows imply a scan").hosts[*host_index];
            let port = &host.ports[*port_index];
            Row::new(vec![
                safe(&host.address),
                port.port.to_string(),
                port.state.to_string(),
                safe(port.service.as_deref().unwrap_or("-")),
            ])
            .style(theme.state(&port.state.to_string()))
        })
        .collect();
    let filter = app
        .filter_state
        .map(|state| state.to_string())
        .unwrap_or_else(|| "all".to_owned());
    let sort = match app.sort_key {
        SortKey::Address => "address",
        SortKey::Port => "port",
        SortKey::State => "state",
    };
    let header = format!(
        "Results (filter: {filter}, sort: {sort}, query: {}/{})",
        if app.querying { "typing" } else { "off" },
        safe(&app.query),
    );
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
        ],
    )
    .header(Row::new(vec!["HOST", "PORT", "STATE", "SERVICE"]).style(theme.title()))
    .block(panel(&theme, header.as_str()))
    .row_highlight_style(theme.title())
    .highlight_symbol("> ");
    let mut state = TableState::default();
    state.select(Some(app.results_sel.min(rows_data.len().saturating_sub(1))));
    frame.render_stateful_widget(table, body, &mut state);
    if app.entering_path.is_some() {
        let kind = format!("{:?}", app.export_kind).to_lowercase();
        let path = app.entering_path.clone().unwrap_or_default();
        frame.render_widget(
            Paragraph::new(Line::from(format!(
                "Export {kind} to: {path} (Tab format, Enter writes)"
            ))),
            foot,
        );
    } else {
        footer(frame, foot, &theme);
    }
}

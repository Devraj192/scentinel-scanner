use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Gauge, Paragraph, Row, Table};
use ratatui::Frame;

use super::{body_and_footer, footer, panel, safe};
use crate::tui::app::App;

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let ratio = if app.model.total > 0 {
        (app.model.done as f64 / app.model.total as f64).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let elapsed = app
        .scan_started_at
        .map(|start| start.elapsed().as_secs())
        .unwrap_or(0);
    let rate = app.model.done as u64 / elapsed.max(1);
    let title = if app.paused {
        format!("Live scan {} (PAUSED)", safe(&app.model.scan_id))
    } else {
        format!("Live scan {}", safe(&app.model.scan_id))
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(4),
        ])
        .split(body);
    frame.render_widget(
        Gauge::default()
            .block(panel(&theme, title.as_str()))
            .ratio(ratio)
            .label(format!("{}/{}", app.model.done, app.model.total)),
        chunks[0],
    );
    frame.render_widget(
        Paragraph::new(format!(
            "elapsed {elapsed}s, {rate}/s, {} host(s) found",
            app.model.hosts.len()
        )),
        chunks[1],
    );
    let rows: Vec<Row> = app
        .model
        .hosts
        .iter()
        .map(|host| {
            Row::new(vec![
                safe(&host.address),
                host.status.to_string(),
                host.ports.len().to_string(),
                host.latency_ms.to_string(),
            ])
        })
        .collect();
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(40),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ],
    )
    .header(Row::new(vec!["HOST", "STATUS", "PORTS", "MS"]).style(theme.title()))
    .header(Row::new(vec!["HOST", "STATUS", "PORTS"]).style(theme.title()))
    .block(panel(&theme, "Hosts (p pauses, c cancels)"));
    frame.render_widget(table, chunks[2]);
    footer(frame, foot, &theme);
}

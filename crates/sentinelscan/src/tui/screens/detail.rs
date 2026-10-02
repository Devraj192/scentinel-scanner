use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{body_and_footer, footer, panel, safe};
use crate::tui::app::App;

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let mut lines = Vec::new();
    let selected = app
        .results_scan
        .as_ref()
        .and_then(|scan| scan.hosts.get(app.detail_host))
        .and_then(|host| host.ports.get(app.detail_port).map(|port| (host, port)));
    match selected {
        Some((host, port)) => {
            lines.push(Line::from(format!(
                "{}:{} {}",
                safe(&host.address),
                port.port,
                port.state
            )));
            if let Some((meaning, next)) =
                sentinelscan_core::results::model::explain_state(&port.state.to_string())
            {
                lines.push(Line::from(format!("Meaning: {meaning}")));
                lines.push(Line::from(format!("Next: {next}")));
            }
            lines.push(Line::from(format!(
                "Service: {}",
                safe(port.service.as_deref().unwrap_or("-"))
            )));
            lines.push(Line::from(format!(
                "Version: {}",
                safe(port.version.as_deref().unwrap_or("-"))
            )));
            lines.push(Line::from(format!(
                "Confidence: {}",
                port.confidence
                    .map(|confidence| format!(
                        "{confidence:.2} ({})",
                        sentinelscan_core::results::model::confidence_word(port.confidence)
                    ))
                    .unwrap_or_else(|| "-".to_owned())
            )));
            if let Some(banner) = port.banner.as_ref() {
                lines.push(Line::from("Banner:"));
                for banner_line in safe(&banner.text).lines().take(8) {
                    lines.push(Line::from(format!("  {banner_line}")));
                }
                if banner.truncated {
                    lines.push(Line::from("  [truncated]"));
                }
            }
            if !port.evidence.is_empty() {
                lines.push(Line::from("Evidence:"));
                for evidence in &port.evidence {
                    lines.push(Line::from(format!(
                        "  {:?}: {}",
                        evidence.kind,
                        safe(&evidence.detail)
                    )));
                }
            }
            if let Some(os) = host.os.as_ref() {
                lines.push(Line::from(format!(
                    "OS: {} {} ({:.2})",
                    safe(&os.family),
                    safe(os.version.as_deref().unwrap_or("-")),
                    os.confidence
                )));
            }
        }
        _ => lines.push(Line::from("Nothing selected.")),
    }
    let total = lines.len();
    let scroll = app.detail_scroll.min(total.saturating_sub(1));
    let visible: Vec<Line> = lines.into_iter().skip(scroll).collect();
    frame.render_widget(
        Paragraph::new(visible).block(panel(&theme, "Detail (j/k scrolls, Esc back)")),
        body,
    );
    footer(frame, foot, &theme);
}

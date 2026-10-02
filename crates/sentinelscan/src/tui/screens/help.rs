use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{body_and_footer, footer, panel};
use crate::tui::app::App;
use crate::tui::keys::BINDINGS;

const GLOSSARY: &[(&str, &str)] = &[
    (
        "open",
        "something accepted the connection; a service is listening.",
    ),
    (
        "closed",
        "the host answered and refused; nothing is listening.",
    ),
    (
        "filtered",
        "no answer; a firewall or network issue is likely hiding it.",
    ),
    (
        "unknown",
        "the scanner could not tell; try again or lower the rate.",
    ),
    (
        "confidence",
        "high/medium/low/unknown words for detector scores.",
    ),
];

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let mut lines: Vec<Line> = vec![Line::from("Keys:")];
    for (key, action) in BINDINGS {
        lines.push(Line::from(format!("  {key}: {action}")));
    }
    lines.push(Line::from("Glossary:"));
    for (term, meaning) in GLOSSARY {
        lines.push(Line::from(format!("  {term}: {meaning}")));
    }
    lines.push(Line::from(
        "Authorized use only: scan targets you own or may test.",
    ));
    let total = lines.len();
    let scroll = app.help_scroll.min(total.saturating_sub(1));
    let visible: Vec<Line> = lines.into_iter().skip(scroll).collect();
    frame.render_widget(
        Paragraph::new(visible).block(panel(&theme, "Help (j/k scrolls, Esc back)")),
        body,
    );
    footer(frame, foot, &theme);
}

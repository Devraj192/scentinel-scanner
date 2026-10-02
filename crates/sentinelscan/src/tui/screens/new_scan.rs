use ratatui::text::Line;
use ratatui::widgets::{Clear, Paragraph};
use ratatui::Frame;

use super::{body_and_footer, centered, footer, panel, safe};
use crate::tui::app::App;

fn row(label: &str, value: &str, focused: bool) -> String {
    let marker = if focused { "> " } else { "  " };
    format!("{marker}{label}: {value}")
}

pub fn render(frame: &mut Frame, app: &mut App) {
    let (body, foot) = body_and_footer(frame);
    let theme = app.theme;
    let form = &app.form;
    let profile = format!("{:?}", form.profile()).to_lowercase();
    let mut lines = vec![
        Line::from(row("Target", &form.target, form.focus == 0)),
        Line::from(row("Ports", &form.ports, form.focus == 1)),
        Line::from(format!(
            "{}Profile: {profile} (Space cycles)",
            if form.focus == 2 { "> " } else { "  " }
        )),
        Line::from(row("Concurrency", &form.concurrency, form.focus == 3)),
        Line::from(row("Rate", &form.rate, form.focus == 4)),
        Line::from(format!(
            "{}Detect services: [{}]",
            if form.focus == 5 { "> " } else { "  " },
            if form.detect { "x" } else { " " }
        )),
        Line::from(format!(
            "{}OS estimate: [{}]",
            if form.focus == 6 { "> " } else { "  " },
            if form.os { "x" } else { " " }
        )),
        Line::from(format!(
            "{}Skip discovery: [{}]",
            if form.focus == 7 { "> " } else { "  " },
            if form.skip_discovery { "x" } else { " " }
        )),
        Line::from(format!(
            "{}[ Confirm scan ]",
            if form.focus == 8 { "> " } else { "  " }
        )),
        Line::from(""),
        Line::from(safe(&form.preview)),
    ];
    if !form.message.is_empty() {
        lines.push(Line::from(safe(&form.message)));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel(&theme, "New scan (Tab moves, Enter confirms)")),
        body,
    );
    if form.confirming {
        let area = centered(body, 64, 10);
        frame.render_widget(Clear, area);
        let text = vec![
            Line::from("Start this scan?"),
            Line::from(safe(&form.preview)),
            Line::from("Authorized targets only."),
            Line::from("Enter starts, Esc goes back to editing."),
        ];
        frame.render_widget(Paragraph::new(text).block(panel(&theme, "Confirm")), area);
    }
    footer(frame, foot, &theme);
}

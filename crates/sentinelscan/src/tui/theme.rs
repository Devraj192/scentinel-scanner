use ratatui::style::{Color, Style};
use ratatui::widgets::BorderType;

/// Terminal theme. Color dies under `NO_COLOR` or on dumb terminals; the
/// ASCII switch drops rounded borders for plain ones. States never rely on
/// color alone — every view also prints the state word.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub color: bool,
    pub ascii: bool,
}

impl Theme {
    /// Detect from the environment.
    pub fn current() -> Self {
        let dumb = std::env::var("TERM")
            .map(|term| term == "dumb")
            .unwrap_or(false);
        Self {
            color: std::env::var_os("NO_COLOR").is_none() && !dumb,
            ascii: dumb || std::env::var_os("SENTINELSCAN_ASCII").is_some(),
        }
    }

    /// Border style for panels.
    pub fn border(&self) -> BorderType {
        if self.ascii {
            BorderType::Plain
        } else {
            BorderType::Rounded
        }
    }

    fn colored(&self, color: Color) -> Style {
        if self.color {
            Style::default().fg(color)
        } else {
            Style::default()
        }
    }

    /// Style for a port state word.
    pub fn state(&self, state: &str) -> Style {
        match state {
            "open" => self.colored(Color::Green),
            "closed" => self.colored(Color::Gray),
            "filtered" => self.colored(Color::Yellow),
            _ => self.colored(Color::Red),
        }
    }

    /// Style for titles and highlights.
    pub fn title(&self) -> Style {
        self.colored(Color::Cyan)
    }

    /// Style for warnings and errors.
    pub fn warn(&self) -> Style {
        self.colored(Color::Red)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_theme_has_no_borders_or_color() {
        let theme = Theme {
            color: false,
            ascii: true,
        };
        assert_eq!(theme.border(), BorderType::Plain);
        assert_eq!(theme.state("open"), Style::default());
    }
}

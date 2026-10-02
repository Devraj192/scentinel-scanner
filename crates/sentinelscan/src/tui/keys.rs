/// Every keybinding, shown in a footer on every screen. Single source of
/// truth: the footer builder and the handler read this list.
pub const BINDINGS: &[(&str, &str)] = &[
    ("↑/↓ or j/k", "move"),
    ("Enter", "open"),
    ("Esc", "back"),
    ("/", "filter"),
    ("s", "sort"),
    ("p", "pause"),
    ("c", "cancel scan"),
    ("e", "export"),
    ("?", "help"),
    ("q", "quit"),
];

/// Footer lines with every keybinding, wrapped for narrow terminals.
pub fn footer_lines() -> [String; 2] {
    let items: Vec<String> = BINDINGS
        .iter()
        .map(|(key, action)| format!("{key} {action}"))
        .collect();
    let mid = items.len() / 2;
    [items[..mid].join("  "), items[mid..].join("  ")]
}

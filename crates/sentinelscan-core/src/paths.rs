use std::path::PathBuf;

/// User home directory, or `None` when the platform does not expose one.
pub fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .or_else(|| {
                let drive = std::env::var_os("HOMEDRIVE")?;
                let path = std::env::var_os("HOMEPATH")?;
                let mut home = PathBuf::from(drive);
                home.push(path);
                Some(home)
            })
    }
    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// XDG data dir (`XDG_DATA_HOME`, else `~/.local/share`).
pub fn data_home() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg));
        }
    }
    home_dir().map(|home| home.join(".local/share"))
}

/// XDG config dir (`XDG_CONFIG_HOME`, else `~/.config`, else `%APPDATA%`).
pub fn config_home() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg));
        }
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return Some(PathBuf::from(appdata));
        }
    }
    home_dir().map(|home| home.join(".config"))
}

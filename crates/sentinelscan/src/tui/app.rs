use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use crossterm::event::{KeyCode, KeyModifiers};
use sentinelscan_core::config::Config;
use sentinelscan_core::events::{ScanEvent, CHANNEL_CAPACITY};
use sentinelscan_core::os::OsGuess;
use sentinelscan_core::pipeline::{execute, ScanPlan};
use sentinelscan_core::results::model::{HostStatus, PortResult, PortState, Scan};
use sentinelscan_core::safety::ports::parse_ports;
use sentinelscan_core::safety::scope::{parse_targets, ScopeGuard};
use sentinelscan_core::storage::{Comparison, ScanSummary};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::theme::Theme;
use crate::cli::commands::{config_source, open_storage};
use crate::doctor::run as run_doctor;

/// Screens of the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    NewScan,
    Live,
    Results,
    Detail,
    History,
    Compare,
    Help,
}

/// One host as the live view sees it.
#[derive(Debug, Clone)]
pub struct HostView {
    pub address: String,
    pub status: HostStatus,
    pub latency_ms: u64,
    pub ports: Vec<PortResult>,
    pub os: Option<OsGuess>,
}

/// Live scan state, reduced purely from [`ScanEvent`]s.
#[derive(Debug, Default)]
pub struct TuiModel {
    pub scan_id: String,
    pub targets: Vec<String>,
    pub hosts: Vec<HostView>,
    pub done: usize,
    pub total: usize,
    pub truncated: bool,
    pub peak: usize,
    pub finished: Option<Scan>,
}

/// Fold one engine event into the live model. Pure: no I/O, no sockets.
pub fn reduce(model: &mut TuiModel, event: &ScanEvent) {
    match event {
        ScanEvent::Started {
            scan_id, targets, ..
        } => {
            model.scan_id = scan_id.clone();
            model.targets = targets.clone();
        }
        ScanEvent::HostDiscovered {
            address,
            status,
            latency_ms,
        } => model.hosts.push(HostView {
            address: address.clone(),
            status: *status,
            latency_ms: *latency_ms,
            ports: Vec::new(),
            os: None,
        }),
        ScanEvent::PortProbed { address, port } => {
            if let Some(host) = model.hosts.iter_mut().find(|host| &host.address == address) {
                if !host.ports.iter().any(|known| known.port == port.port) {
                    host.ports.push(port.clone());
                    host.ports.sort_by_key(|known| known.port);
                }
            }
        }
        ScanEvent::ServiceDetected {
            address,
            port,
            service,
            version,
            confidence,
            evidence,
            banner,
        } => {
            if let Some(known) = model
                .hosts
                .iter_mut()
                .find(|host| &host.address == address)
                .and_then(|host| host.ports.iter_mut().find(|known| known.port == *port))
            {
                known.service.clone_from(service);
                known.version.clone_from(version);
                known.confidence = *confidence;
                known.evidence.clone_from(evidence);
                known.banner.clone_from(banner);
            }
        }
        ScanEvent::OsEstimated { address, os } => {
            if let Some(host) = model.hosts.iter_mut().find(|host| &host.address == address) {
                host.os.clone_from(os);
            }
        }
        ScanEvent::Progress { done, total } => {
            model.done = *done;
            model.total = *total;
        }
        ScanEvent::Warning { .. } => model.truncated = true,
        ScanEvent::Completed { scan } => {
            model.finished = Some(scan.clone());
            model.truncated = scan.meta.truncated;
            model.peak = scan.meta.peak_active_probes;
        }
        ScanEvent::Error { .. } => {}
    }
}

/// New-scan form state.
pub struct ScanForm {
    pub target: String,
    pub ports: String,
    pub profile_idx: usize,
    pub concurrency: String,
    pub rate: String,
    pub detect: bool,
    pub os: bool,
    pub skip_discovery: bool,
    /// Focused row: 0-7 inputs, 8 = confirm button.
    pub focus: usize,
    pub preview: String,
    pub confirming: bool,
    pub message: String,
}

impl Default for ScanForm {
    fn default() -> Self {
        Self {
            target: String::new(),
            ports: "standard".to_owned(),
            profile_idx: 1,
            concurrency: String::new(),
            rate: String::new(),
            detect: true,
            os: true,
            skip_discovery: false,
            focus: 0,
            preview: String::new(),
            confirming: false,
            message: String::new(),
        }
    }
}

impl ScanForm {
    pub const FIELDS: usize = 9;

    pub fn profile(&self) -> sentinelscan_core::config::profiles::Profile {
        use sentinelscan_core::config::profiles::Profile;
        match self.profile_idx {
            0 => Profile::Quick,
            2 => Profile::Custom,
            _ => Profile::Standard,
        }
    }

    /// Recompute the scope preview (or the first parse error) from the form.
    /// Pure over core parsers; sends nothing.
    pub fn refresh_preview(&mut self) {
        use sentinelscan_core::safety::ports::parse_ports;
        use sentinelscan_core::safety::scope::{host_count, parse_targets};
        if self.target.is_empty() {
            self.preview = "Enter a target above.".to_owned();
            return;
        }
        let targets = match parse_targets(std::slice::from_ref(&self.target), true, 65536) {
            Ok(targets) => targets,
            Err(e) => {
                self.preview = format!("Target: {e}");
                return;
            }
        };
        let spec = if self.ports.is_empty() {
            "standard"
        } else {
            self.ports.as_str()
        };
        let ports = match parse_ports(spec, 65535) {
            Ok(ports) => ports,
            Err(e) => {
                self.preview = format!("Ports: {e}");
                return;
            }
        };
        self.preview = format!(
            "Scope: {} host(s), {} port(s), profile {:?}.",
            host_count(&targets),
            ports.len(),
            self.profile()
        );
    }
}

/// What the export prompt will write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportKind {
    Json,
    Csv,
    Text,
}

/// Sort order for the results table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Address,
    Port,
    State,
}

pub struct App {
    pub screen: Screen,
    pub help_from: Screen,
    pub theme: Theme,
    pub form: ScanForm,
    pub model: TuiModel,
    pub results_scan: Option<Scan>,
    pub results_sel: usize,
    pub filter_state: Option<PortState>,
    pub sort_key: SortKey,
    pub querying: bool,
    pub query: String,
    pub detail_host: usize,
    pub detail_port: usize,
    pub detail_scroll: usize,
    pub history: Vec<ScanSummary>,
    pub hist_sel: usize,
    pub confirm_delete: bool,
    pub compare_a: Option<String>,
    pub compare_b: Option<String>,
    pub comparison: Option<Comparison>,
    pub entering_path: Option<String>,
    pub export_kind: ExportKind,
    pub home_menu: usize,
    pub help_scroll: usize,
    pub message: String,
    pub paused: bool,
    pub pause_flag: Arc<AtomicBool>,
    pub scan_rx: Option<mpsc::Receiver<ScanEvent>>,
    pub scan_task: Option<JoinHandle<anyhow::Result<Scan>>>,
    pub scan_started_at: Option<Instant>,
    pub last_scan_id: Option<String>,
    pub doctor_line: String,
    pub confirm_quit: bool,
    pub storage: sentinelscan_core::storage::Storage,
}

impl App {
    /// Load history and a one-shot doctor summary for the home screen.
    pub async fn new() -> anyhow::Result<Self> {
        let storage = open_storage(&None)?;
        let history = storage.list_scans().unwrap_or_default();
        let doctor = run_doctor().await;
        let (pass, warn, fail) = doctor.checks.iter().fold((0, 0, 0), |(p, w, f), check| {
            use crate::doctor::Status;
            match check.status {
                Status::Pass => (p + 1, w, f),
                Status::Warn => (p, w + 1, f),
                Status::Fail => (p, w, f + 1),
            }
        });
        Ok(Self {
            screen: Screen::Home,
            help_from: Screen::Home,
            theme: Theme::current(),
            form: ScanForm::default(),
            model: TuiModel::default(),
            results_scan: None,
            results_sel: 0,
            filter_state: None,
            sort_key: SortKey::Address,
            querying: false,
            query: String::new(),
            detail_host: 0,
            detail_port: 0,
            detail_scroll: 0,
            history,
            hist_sel: 0,
            confirm_delete: false,
            compare_a: None,
            compare_b: None,
            comparison: None,
            entering_path: None,
            export_kind: ExportKind::Json,
            home_menu: 0,
            help_scroll: 0,
            message: String::new(),
            paused: false,
            pause_flag: Arc::new(AtomicBool::new(false)),
            scan_rx: None,
            scan_task: None,
            scan_started_at: None,
            last_scan_id: None,
            doctor_line: format!("doctor: {pass} pass, {warn} warn, {fail} fail"),
            confirm_quit: false,
            storage,
        })
    }

    /// Drain pending engine events into the live model.
    pub fn drain_scan_events(&mut self) {
        let mut saw_finished = false;
        if let Some(rx) = self.scan_rx.as_mut() {
            while let Ok(event) = rx.try_recv() {
                saw_finished |= matches!(event, ScanEvent::Completed { .. });
                reduce(&mut self.model, &event);
            }
        }
        if saw_finished {
            self.on_scan_finished();
        }
        if let Some(task) = self.scan_task.as_mut() {
            if task.is_finished() {
                self.scan_task = None;
            }
        }
    }

    fn on_scan_finished(&mut self) {
        self.scan_rx = None;
        if let Some(scan) = self.model.finished.clone() {
            let storage = self.storage.clone();
            let id = scan.meta.scan_id.clone();
            let truncated = scan.meta.truncated;
            // Persistence already happened in the engine; finish the row unless
            // the run was cut short, exactly like the CLI.
            if !truncated {
                let _ = storage.finish_scan(&id, false, scan.meta.peak_active_probes);
            }
            self.last_scan_id = Some(id.clone());
            self.message = if truncated {
                format!("Scan stopped early; resume with: sentinelscan scan --resume {id} --yes")
            } else {
                format!("Scan {id} complete and stored.")
            };
            self.results_scan = Some(scan);
            self.results_sel = 0;
            if self.screen == Screen::Live {
                self.screen = Screen::Results;
            }
        }
    }

    /// Abort the running scan, if any. Partial results stay persisted and
    /// resumable, same as Ctrl-C on the CLI.
    pub fn cancel_scan(&mut self) {
        if let Some(task) = self.scan_task.take() {
            task.abort();
        }
        self.scan_rx = None;
        self.pause_flag.store(false, Ordering::SeqCst);
        self.paused = false;
        if let Some(id) = self
            .last_scan_id
            .clone()
            .or(Some(self.model.scan_id.clone()))
        {
            if !id.is_empty() {
                self.message =
                    format!("Scan cancelled; resume with: sentinelscan scan --resume {id} --yes");
            }
        }
    }

    /// Visible rows of the results table after filter, search, and sort.
    pub fn visible_rows(&self) -> Vec<(usize, usize)> {
        let Some(scan) = &self.results_scan else {
            return Vec::new();
        };
        let mut rows = Vec::new();
        for (host_index, host) in scan.hosts.iter().enumerate() {
            for (port_index, port) in host.ports.iter().enumerate() {
                if let Some(state) = self.filter_state {
                    if port.state != state {
                        continue;
                    }
                }
                if !self.query.is_empty() {
                    let haystack = format!(
                        "{} {} {} {}",
                        host.address,
                        port.port,
                        port.service.as_deref().unwrap_or(""),
                        port.reason
                    );
                    if !haystack.to_lowercase().contains(&self.query.to_lowercase()) {
                        continue;
                    }
                }
                rows.push((host_index, port_index));
            }
        }
        match self.sort_key {
            SortKey::Address => rows.sort_by(|a, b| {
                scan.hosts[a.0].address.cmp(&scan.hosts[b.0].address).then(
                    scan.hosts[a.0].ports[a.1]
                        .port
                        .cmp(&scan.hosts[b.0].ports[b.1].port),
                )
            }),
            SortKey::Port => rows.sort_by(|a, b| {
                scan.hosts[a.0].ports[a.1]
                    .port
                    .cmp(&scan.hosts[b.0].ports[b.1].port)
                    .then(scan.hosts[a.0].address.cmp(&scan.hosts[b.0].address))
            }),
            SortKey::State => rows.sort_by(|a, b| {
                format!("{:?}", scan.hosts[a.0].ports[a.1].state)
                    .cmp(&format!("{:?}", scan.hosts[b.0].ports[b.1].state))
                    .then(scan.hosts[a.0].address.cmp(&scan.hosts[b.0].address))
            }),
        }
        rows
    }
}

impl App {
    /// True while a scan task is alive.
    pub fn scan_running(&self) -> bool {
        self.scan_task.is_some()
    }

    /// Feed one character into the active text input. Returns true when some
    /// input consumed it.
    fn type_into(&mut self, code: KeyCode) -> bool {
        let field: Option<&mut String> = if let Some(path) = self.entering_path.as_mut() {
            Some(path)
        } else if self.screen == Screen::Results && self.querying {
            Some(&mut self.query)
        } else if self.screen == Screen::NewScan && !self.form.confirming {
            match self.form.focus {
                0 => Some(&mut self.form.target),
                1 => Some(&mut self.form.ports),
                3 => Some(&mut self.form.concurrency),
                4 => Some(&mut self.form.rate),
                _ => None,
            }
        } else {
            None
        };
        let Some(field) = field else {
            return false;
        };
        match code {
            KeyCode::Char(c) => {
                field.push(c);
                if self.screen == Screen::NewScan {
                    self.form.refresh_preview();
                }
                true
            }
            KeyCode::Backspace => {
                field.pop();
                if self.screen == Screen::NewScan {
                    self.form.refresh_preview();
                }
                true
            }
            _ => false,
        }
    }

    /// Start the scan described by the form. False keeps the form open with
    /// the reason in its message line; no socket opens before parsing passes.
    pub fn start_scan(&mut self) -> bool {
        let config = match Config::load(config_source(&None).as_deref()) {
            Ok(config) => config,
            Err(e) => {
                self.form.message = format!("Config: {e}");
                return false;
            }
        };
        let mut limits = config.limits.clone();
        if !self.form.concurrency.is_empty() {
            match self.form.concurrency.parse::<usize>() {
                Ok(n) if n > 0 && n <= 5000 => limits.max_concurrency = n,
                _ => {
                    self.form.message = "Concurrency must be 1-5000.".to_owned();
                    return false;
                }
            }
        }
        if !self.form.rate.is_empty() {
            match self.form.rate.parse::<u64>() {
                Ok(n) if n > 0 && n <= 100_000 => limits.max_rate = n,
                _ => {
                    self.form.message = "Rate must be 1-100000.".to_owned();
                    return false;
                }
            }
        }
        let targets = match parse_targets(
            std::slice::from_ref(&self.form.target),
            true,
            limits.max_hosts,
        ) {
            Ok(targets) => targets,
            Err(e) => {
                self.form.message = format!("Target: {e}");
                return false;
            }
        };
        let spec = if self.form.ports.is_empty() {
            "standard"
        } else {
            self.form.ports.as_str()
        };
        let ports = match parse_ports(spec, limits.max_ports) {
            Ok(ports) => ports,
            Err(e) => {
                self.form.message = format!("Ports: {e}");
                return false;
            }
        };
        let guard = ScopeGuard::from_targets(&targets);
        let storage = self.storage.clone();
        let pause = Arc::clone(&self.pause_flag);
        let scan_id = ulid::Ulid::new().to_string();
        let plan = ScanPlan {
            scan_id: scan_id.clone(),
            targets,
            ports,
            limits,
            guard,
            skip_discovery: self.form.skip_discovery,
            detect: self.form.detect,
            os_enabled: self.form.os,
            storage,
            pause,
        };
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        self.model = TuiModel {
            scan_id,
            ..TuiModel::default()
        };
        self.scan_rx = Some(rx);
        self.scan_started_at = Some(Instant::now());
        self.paused = false;
        self.pause_flag.store(false, Ordering::SeqCst);
        // Confirmation already happened on the form; resolution inside
        // execute() is the first network I/O, exactly like the CLI.
        self.scan_task = Some(tokio::spawn(async move { execute(&plan, None, &tx).await }));
        self.screen = Screen::Live;
        self.form.confirming = false;
        true
    }
}

impl App {
    /// Handle one key. Returns false when the app should quit.
    pub fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> bool {
        if modifiers.contains(KeyModifiers::CONTROL) {
            match code {
                KeyCode::Char('c') => return self.quit_or_confirm(),
                _ => return true,
            }
        }
        // Text inputs eat characters before shortcuts.
        if self.entering_path.is_some() || self.querying {
            match code {
                KeyCode::Esc => {
                    self.entering_path = None;
                    self.querying = false;
                    return true;
                }
                KeyCode::Enter if self.entering_path.is_some() => {
                    self.confirm_export();
                    return true;
                }
                _ => {
                    self.type_into(code);
                    return true;
                }
            }
        }
        match code {
            KeyCode::Char('q') => return self.quit_or_confirm(),
            KeyCode::Char('?') => {
                self.help_from = self.screen;
                self.screen = Screen::Help;
                self.confirm_quit = false;
                return true;
            }
            _ => {}
        }
        self.confirm_quit = false;
        match self.screen {
            Screen::Home => self.home_key(code),
            Screen::NewScan => self.form_key(code),
            Screen::Live => self.live_key(code),
            Screen::Results => self.results_key(code),
            Screen::Detail => self.detail_key(code),
            Screen::History => self.history_key(code),
            Screen::Compare => self.compare_key(code),
            Screen::Help => self.help_key(code),
        }
        true
    }

    fn quit_or_confirm(&mut self) -> bool {
        if self.scan_running() && !self.confirm_quit {
            self.confirm_quit = true;
            self.message = "Scan running: press q again to quit, c cancels the scan.".to_owned();
            return true;
        }
        false
    }

    fn home_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('n') => {
                self.form = ScanForm::default();
                self.form.refresh_preview();
                self.screen = Screen::NewScan;
            }
            KeyCode::Char('h') => {
                self.refresh_history();
                self.screen = Screen::History;
            }
            KeyCode::Char('c') => {
                self.refresh_history();
                self.screen = Screen::Compare;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.home_menu > 0 {
                    self.home_menu -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.home_menu = (self.home_menu + 1).min(3);
            }
            KeyCode::Enter => match self.home_menu {
                0 => {
                    self.form = ScanForm::default();
                    self.form.refresh_preview();
                    self.screen = Screen::NewScan;
                }
                1 => {
                    self.refresh_history();
                    self.screen = Screen::History;
                }
                2 => {
                    self.refresh_history();
                    self.screen = Screen::Compare;
                }
                _ => {
                    self.help_from = Screen::Home;
                    self.screen = Screen::Help;
                }
            },
            _ => {}
        }
    }

    fn form_key(&mut self, code: KeyCode) {
        if self.form.confirming {
            match code {
                KeyCode::Enter => {
                    self.start_scan();
                }
                KeyCode::Esc => self.form.confirming = false,
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Tab => {
                self.form.focus = (self.form.focus + 1) % ScanForm::FIELDS;
            }
            KeyCode::Up => {
                self.form.focus = self.form.focus.saturating_sub(1);
            }
            KeyCode::Down => {
                self.form.focus = (self.form.focus + 1).min(ScanForm::FIELDS - 1);
            }
            KeyCode::Enter => match self.form.focus {
                5..=7 => {
                    // Toggles live here so Space is not required.
                    match self.form.focus {
                        5 => self.form.detect = !self.form.detect,
                        6 => self.form.os = !self.form.os,
                        _ => self.form.skip_discovery = !self.form.skip_discovery,
                    }
                }
                8 => self.form.confirming = true,
                _ => {
                    self.form.focus = (self.form.focus + 1) % ScanForm::FIELDS;
                }
            },
            KeyCode::Char(' ') => match self.form.focus {
                2 => {
                    self.form.profile_idx = (self.form.profile_idx + 1) % 3;
                    self.form.refresh_preview();
                }
                5 => self.form.detect = !self.form.detect,
                6 => self.form.os = !self.form.os,
                7 => self.form.skip_discovery = !self.form.skip_discovery,
                _ => {
                    self.type_into(code);
                }
            },
            KeyCode::Left | KeyCode::Right if self.form.focus == 2 => {
                self.form.profile_idx = (self.form.profile_idx + 1) % 3;
                self.form.refresh_preview();
            }
            _ => {
                self.type_into(code);
            }
        }
    }

    fn live_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                self.pause_flag.store(self.paused, Ordering::SeqCst);
                self.message = if self.paused {
                    "Paused: no new probes start. Press p to resume.".to_owned()
                } else {
                    String::new()
                };
            }
            KeyCode::Char('c') | KeyCode::Esc => {
                self.cancel_scan();
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn results_key(&mut self, code: KeyCode) {
        let rows = self.visible_rows().len();
        match code {
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Up | KeyCode::Char('k') => {
                self.results_sel = self.results_sel.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if rows > 0 {
                    self.results_sel = (self.results_sel + 1).min(rows - 1);
                }
            }
            KeyCode::Enter => {
                if let Some((host, port)) = self.visible_rows().get(self.results_sel).copied() {
                    self.detail_host = host;
                    self.detail_port = port;
                    self.detail_scroll = 0;
                    self.screen = Screen::Detail;
                }
            }
            KeyCode::Char('/') => {
                self.querying = true;
                self.query.clear();
            }
            KeyCode::Char('s') => {
                self.sort_key = match self.sort_key {
                    SortKey::Address => SortKey::Port,
                    SortKey::Port => SortKey::State,
                    SortKey::State => SortKey::Address,
                };
            }
            KeyCode::Char('e') => {
                if self.results_scan.is_some() {
                    self.export_kind = ExportKind::Json;
                    self.entering_path = Some(String::new());
                    self.message = "Export path (Tab switches format):".to_owned();
                }
            }
            KeyCode::Tab if self.entering_path.is_some() => {
                self.export_kind = match self.export_kind {
                    ExportKind::Json => ExportKind::Csv,
                    ExportKind::Csv => ExportKind::Text,
                    ExportKind::Text => ExportKind::Json,
                };
            }
            _ => {}
        }
    }

    fn detail_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.screen = Screen::Results,
            KeyCode::Up | KeyCode::Char('k') => {
                self.detail_scroll = self.detail_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.detail_scroll = self.detail_scroll.saturating_add(1);
            }
            _ => {}
        }
    }

    fn history_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.confirm_delete = false;
                self.screen = Screen::Home;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.hist_sel = self.hist_sel.saturating_sub(1);
                self.confirm_delete = false;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.history.is_empty() {
                    self.hist_sel = (self.hist_sel + 1).min(self.history.len() - 1);
                    self.confirm_delete = false;
                }
            }
            KeyCode::Enter => self.open_history_selection(),
            KeyCode::Char('d') => {
                if self.confirm_delete {
                    self.delete_history_selection();
                } else {
                    self.confirm_delete = true;
                    self.message = "Press d again to delete this scan.".to_owned();
                }
            }
            KeyCode::Char('e') => {
                if self.history.get(self.hist_sel).is_some() {
                    self.export_kind = ExportKind::Json;
                    self.entering_path = Some(String::new());
                    self.message = "Export path (Tab switches format):".to_owned();
                }
            }
            KeyCode::Tab if self.entering_path.is_some() => {
                self.export_kind = match self.export_kind {
                    ExportKind::Json => ExportKind::Csv,
                    ExportKind::Csv => ExportKind::Text,
                    ExportKind::Text => ExportKind::Json,
                };
            }
            _ => {}
        }
    }

    fn compare_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Up | KeyCode::Char('k') => {
                self.hist_sel = self.hist_sel.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.history.is_empty() {
                    self.hist_sel = (self.hist_sel + 1).min(self.history.len() - 1);
                }
            }
            KeyCode::Char('a') => {
                self.compare_a = self
                    .history
                    .get(self.hist_sel)
                    .map(|item| item.scan_id.clone());
                self.refresh_comparison();
            }
            KeyCode::Char('b') => {
                self.compare_b = self
                    .history
                    .get(self.hist_sel)
                    .map(|item| item.scan_id.clone());
                self.refresh_comparison();
            }
            _ => {}
        }
    }

    fn help_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.screen = self.help_from,
            KeyCode::Up | KeyCode::Char('k') => {
                self.help_scroll = self.help_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.help_scroll = self.help_scroll.saturating_add(1);
            }
            _ => {}
        }
    }

    fn refresh_history(&mut self) {
        self.history = self.storage.list_scans().unwrap_or_default();
        self.hist_sel = 0;
        self.confirm_delete = false;
    }

    fn open_history_selection(&mut self) {
        let Some(item) = self.history.get(self.hist_sel) else {
            return;
        };
        match self.storage.load_full_scan(&item.scan_id) {
            Ok(scan) => {
                self.results_scan = Some(scan);
                self.results_sel = 0;
                self.screen = Screen::Results;
            }
            Err(e) => {
                self.message = format!("Cannot open scan: {e}");
            }
        }
    }

    fn delete_history_selection(&mut self) {
        let Some(item) = self.history.get(self.hist_sel) else {
            return;
        };
        match self.storage.delete_scan(&item.scan_id) {
            Ok(()) => {
                self.message = format!("Deleted {}.", item.scan_id);
                self.refresh_history();
            }
            Err(e) => {
                self.message = format!("Cannot delete: {e}");
            }
        }
    }

    fn refresh_comparison(&mut self) {
        let (Some(a), Some(b)) = (self.compare_a.clone(), self.compare_b.clone()) else {
            self.comparison = None;
            return;
        };
        match (
            self.storage.load_full_scan(&a),
            self.storage.load_full_scan(&b),
        ) {
            (Ok(older), Ok(newer)) => {
                self.comparison = Some(sentinelscan_core::storage::compare(&older, &newer));
            }
            (Err(e), _) | (_, Err(e)) => {
                self.message = format!("Cannot compare: {e}");
                self.comparison = None;
            }
        }
    }

    /// Write the pending export (results scan, history selection, or
    /// comparison) to the confirmed path.
    fn confirm_export(&mut self) {
        let Some(path) = self.entering_path.take() else {
            return;
        };
        if path.is_empty() {
            self.message = "Export cancelled: empty path.".to_owned();
            return;
        }
        let result = match self.screen {
            Screen::Results => self
                .results_scan
                .as_ref()
                .map(|scan| export_scan(scan, self.export_kind, &path)),
            Screen::History => self.history.get(self.hist_sel).and_then(|item| {
                self.storage
                    .load_full_scan(&item.scan_id)
                    .ok()
                    .map(|scan| export_scan(&scan, self.export_kind, &path))
            }),
            Screen::Compare => self.comparison.as_ref().map(|comparison| {
                let text = serde_json::to_string_pretty(comparison).unwrap_or_default();
                std::fs::write(&path, text).map_err(|e| anyhow::anyhow!("{e}"))
            }),
            _ => None,
        };
        self.message = match result {
            Some(Ok(())) => format!("Exported to {path}."),
            Some(Err(e)) => format!("Export failed: {e}"),
            None => "Nothing to export.".to_owned(),
        };
    }
}

/// Write one scan in the requested format. Pure file I/O on an already-built
/// model; shared by every screen that exports.
pub fn export_scan(
    scan: &sentinelscan_core::results::model::Scan,
    kind: ExportKind,
    path: &str,
) -> anyhow::Result<()> {
    use sentinelscan_core::results::model;
    let text = match kind {
        ExportKind::Json => model::to_json(scan),
        ExportKind::Csv => model::to_csv(scan),
        ExportKind::Text => format!(
            "{}{}{}",
            model::terminal_table(scan),
            model::os_lines(scan),
            model::summary(scan, None),
        ),
    };
    std::fs::write(path, text).map_err(|e| anyhow::anyhow!("cannot write {path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use sentinelscan_core::events::ScanEvent;
    use sentinelscan_core::results::model::{Banner, HostStatus, PortResult, PortState, Scan};

    pub fn test_app() -> App {
        // Unique per test: the suite runs threads in parallel against these.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("sentinelscan-tui-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let storage = open_storage(&Some(dir.join("h.db").to_str().expect("utf8").to_owned()))
            .expect("storage");
        App {
            screen: Screen::Home,
            help_from: Screen::Home,
            theme: Theme {
                color: false,
                ascii: true,
            },
            form: ScanForm::default(),
            model: TuiModel::default(),
            results_scan: None,
            results_sel: 0,
            filter_state: None,
            sort_key: SortKey::Address,
            querying: false,
            query: String::new(),
            detail_host: 0,
            detail_port: 0,
            detail_scroll: 0,
            history: Vec::new(),
            hist_sel: 0,
            confirm_delete: false,
            compare_a: None,
            compare_b: None,
            comparison: None,
            entering_path: None,
            export_kind: ExportKind::Json,
            home_menu: 0,
            help_scroll: 0,
            message: String::new(),
            paused: false,
            pause_flag: Arc::new(AtomicBool::new(false)),
            scan_rx: None,
            scan_task: None,
            scan_started_at: None,
            last_scan_id: None,
            doctor_line: String::new(),
            confirm_quit: false,
            storage,
        }
    }

    fn port_fixture(port: u16, state: PortState, service: Option<&str>) -> PortResult {
        PortResult {
            port,
            protocol: "tcp".to_owned(),
            state,
            reason: "handshake".to_owned(),
            latency_ms: 1,
            service: service.map(str::to_owned),
            version: None,
            confidence: Some(0.9),
            evidence: Vec::new(),
            banner: None,
        }
    }

    fn scan_fixture() -> Scan {
        let mut scan = Scan::start("01TUI".to_owned(), vec!["127.0.0.1".to_owned()]);
        scan.hosts
            .push(sentinelscan_core::results::model::HostResult {
                address: "127.0.0.1".to_owned(),
                status: HostStatus::Up,
                latency_ms: 1,
                ports: vec![
                    port_fixture(22, PortState::Closed, None),
                    port_fixture(80, PortState::Open, Some("http")),
                ],
                os: None,
            });
        scan.finish();
        scan
    }

    #[test]
    fn reducer_folds_a_full_run() {
        let mut model = TuiModel::default();
        let scan = scan_fixture();
        reduce(
            &mut model,
            &ScanEvent::Started {
                scan_id: scan.meta.scan_id.clone(),
                targets: scan.targets.clone(),
                ports: vec![22, 80],
            },
        );
        reduce(
            &mut model,
            &ScanEvent::HostDiscovered {
                address: "127.0.0.1".to_owned(),
                status: HostStatus::Up,
                latency_ms: 1,
            },
        );
        for port in &scan.hosts[0].ports {
            reduce(
                &mut model,
                &ScanEvent::PortProbed {
                    address: "127.0.0.1".to_owned(),
                    port: port.clone(),
                },
            );
        }
        // Duplicate probes never duplicate rows.
        reduce(
            &mut model,
            &ScanEvent::PortProbed {
                address: "127.0.0.1".to_owned(),
                port: scan.hosts[0].ports[0].clone(),
            },
        );
        reduce(&mut model, &ScanEvent::Progress { done: 2, total: 2 });
        reduce(&mut model, &ScanEvent::Completed { scan: scan.clone() });
        assert_eq!(model.hosts.len(), 1);
        assert_eq!(model.hosts[0].ports.len(), 2);
        assert_eq!((model.done, model.total), (2, 2));
        assert!(model.finished.is_some());
    }

    #[test]
    fn every_footer_binding_has_a_handler() {
        let mut app = test_app();
        app.results_scan = Some(scan_fixture());
        app.screen = Screen::Results;
        assert!(app.handle_key(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.results_sel, 1);
        assert!(app.handle_key(KeyCode::Char('k'), KeyModifiers::NONE));
        assert!(app.handle_key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(app.screen, Screen::Detail);
        assert!(app.handle_key(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.screen, Screen::Results);
        assert!(app.handle_key(KeyCode::Char('/'), KeyModifiers::NONE));
        assert!(app.querying);
        assert!(app.handle_key(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.handle_key(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(app.sort_key, SortKey::Port);
        assert!(app.handle_key(KeyCode::Char('e'), KeyModifiers::NONE));
        assert!(app.entering_path.is_some());
        assert!(app.handle_key(KeyCode::Esc, KeyModifiers::NONE));
        app.screen = Screen::Home;
        assert!(app.handle_key(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_eq!(app.screen, Screen::NewScan);
        assert!(app.handle_key(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.screen, Screen::Help);
        assert!(app.handle_key(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.screen, Screen::NewScan);
        app.screen = Screen::Live;
        assert!(app.handle_key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(app.paused);
        assert!(app.pause_flag.load(Ordering::SeqCst));
        assert!(app.handle_key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(!app.paused);
        app.scan_task = None;
        assert!(!app.handle_key(KeyCode::Char('q'), KeyModifiers::NONE));
    }

    #[test]
    fn form_edits_and_confirms() {
        let mut app = test_app();
        app.screen = Screen::NewScan;
        assert!(app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE));
        assert!(app.handle_key(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.form.focus, 1);
        assert!(app.form.target.contains('1'));
        app.form.focus = 5;
        let before = app.form.detect;
        assert!(app.handle_key(KeyCode::Char(' '), KeyModifiers::NONE));
        assert_eq!(app.form.detect, !before);
    }

    fn export_dir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::env::temp_dir().join(format!("sentinelscan-exp-{}-{n}", std::process::id()))
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn every_screen_renders_header_and_footer() {
        let mut app = test_app();
        app.results_scan = Some(scan_fixture());
        app.history = app.storage.list_scans().expect("history reads back");
        for screen in [
            Screen::Home,
            Screen::NewScan,
            Screen::Live,
            Screen::Results,
            Screen::Detail,
            Screen::History,
            Screen::Compare,
            Screen::Help,
        ] {
            app.screen = screen;
            let backend = TestBackend::new(80, 24);
            let mut terminal = Terminal::new(backend).expect("test terminal");
            terminal
                .draw(|frame| super::super::screens::render(frame, &mut app))
                .expect("draw");
            let text = buffer_text(&terminal);
            assert!(text.contains("q quit"), "{screen:?} misses the footer");
        }
    }

    #[test]
    fn hostile_banner_renders_inert() {
        let mut app = test_app();
        let mut scan = scan_fixture();
        scan.hosts[0].ports[1].banner = Some(Banner {
            text: "\u{1b}[2J\u{1b}]0;pwned\u{7}evil".to_owned(),
            encoding: "utf8".to_owned(),
            truncated: false,
            raw: vec![0x1b],
        });
        app.results_scan = Some(scan);
        app.screen = Screen::Detail;
        app.detail_host = 0;
        app.detail_port = 1;
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| super::super::screens::render(frame, &mut app))
            .expect("draw");
        let text = buffer_text(&terminal);
        assert!(text.contains("evil"), "banner content stays visible");
    }

    #[test]
    fn exports_write_all_formats() {
        let scan = scan_fixture();
        let dir = export_dir();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        for (kind, name, check) in [
            (ExportKind::Json, "out.json", "\"open\""),
            (ExportKind::Csv, "out.csv", "scan_id,host,port"),
            (ExportKind::Text, "out.txt", "HOST"),
        ] {
            let path = dir.join(name);
            export_scan(&scan, kind, path.to_str().expect("utf8")).expect("export");
            let text = std::fs::read_to_string(&path).expect("read back");
            assert!(text.contains(check), "{name} misses {check}");
        }
        let back: Scan = serde_json::from_str(
            &std::fs::read_to_string(dir.join("out.json")).expect("read back"),
        )
        .expect("json parses");
        assert_eq!(back.hosts.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

use clap::{CommandFactory as _, Parser};

mod cli;
mod doctor;
mod hints;
mod tui;

use crate::cli::args::Cli;
use crate::cli::commands::run;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let Some(command) = &cli.command else {
        // No subcommand: open the TUI on a terminal, print help otherwise.
        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            if let Err(error) = tui::launch().await {
                eprintln!("Error: {error:#}");
                std::process::exit(1);
            }
            return;
        }
        Cli::command().print_help().expect("help renders");
        println!();
        return;
    };
    if let Err(error) = run(command).await {
        eprintln!("Error: {error:#}");
        if let Some(fix) = hints::hint_for(&error) {
            eprintln!("Fix: {fix}");
        }
        std::process::exit(1);
    }
}

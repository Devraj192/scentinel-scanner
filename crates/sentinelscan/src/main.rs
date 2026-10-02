use clap::Parser;

mod cli;
mod doctor;
mod hints;

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
    if let Err(error) = run(&cli.command).await {
        eprintln!("Error: {error:#}");
        if let Some(fix) = hints::hint_for(&error) {
            eprintln!("Fix: {fix}");
        }
        std::process::exit(1);
    }
}

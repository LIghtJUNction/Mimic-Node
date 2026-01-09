mod cli;
mod commands;
mod config;
mod paths;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use paths::Paths;

#[tokio::main]
async fn main() -> Result<()> {
    let paths = Paths::new();

    // Ensure environment is ready (OverlayFS)
    utils::check_overlay(&paths)?;

    let args = Cli::parse();

    match args.command {
        Commands::GenKeys => commands::keys::generate(&paths)?,
        Commands::Add { emails, level } => commands::user::add(&paths, emails, level)?,
        Commands::Del { targets } => commands::user::del(&paths, targets)?,
        Commands::ResetUser { email } => commands::user::reset(&paths, email)?,
        Commands::Reset { keep_users } => commands::system::reset(&paths, keep_users)?,
        Commands::Discard { items, force } => commands::system::discard(&paths, items, force)?,
        Commands::Sni { domain, file } => commands::net::sni(&paths, domain, file).await?,
        Commands::Completions { shell, apply } => commands::net::completions(shell, apply)?,
        Commands::Link {
            email,
            addresses,
            v4,
            v6,
        } => commands::net::link(&paths, email, addresses, v4, v6).await?,
        Commands::List { filter } => commands::user::list(&paths, filter)?,
        Commands::Info { email } => commands::user::info(&paths, email)?,
        Commands::Show => commands::system::show(&paths)?,
        Commands::Apply => commands::system::apply(&paths)?,
        Commands::Check => commands::system::check(&paths)?,
    }

    Ok(())
}

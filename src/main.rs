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
    let args = Cli::parse();

    let paths = Paths::new();

    // Ensure environment is ready (OverlayFS), unless command doesn't need it
    let need_overlay = !matches!(
        &args.command,
        Commands::Completions { .. }
            | Commands::Verify {
                config: Some(_),
                ..
            }
    );

    if need_overlay {
        utils::check_overlay(&paths)?;
    }

    match args.command {
        Commands::GenKeys => commands::keys::generate(&paths)?,
        Commands::Add { emails, level } => commands::user::add(&paths, emails, level)?,
        Commands::Del {
            targets,
            dry_run,
            apply,
        } => commands::user::del(&paths, targets, dry_run, apply)?,
        Commands::ResetUser {
            targets,
            dry_run,
            apply,
        } => commands::user::reset(&paths, targets, dry_run, apply)?,
        Commands::Update {
            targets,
            level,
            email,
            email_replace,
            regex,
            replace_first,
            dry_run,
            apply,
        } => commands::user::update(
            &paths,
            targets,
            level,
            email,
            email_replace,
            regex,
            replace_first,
            dry_run,
            apply,
        )?,
        Commands::Reset { keep_users } => commands::system::reset(&paths, keep_users)?,
        Commands::Discard { items, force } => commands::system::discard(&paths, items, force)?,
        Commands::Sni { domain, file } => commands::net::sni(&paths, domain, file).await?,
        Commands::Completions { shell, apply } => commands::net::completions(shell, apply)?,
        Commands::Link {
            email,
            addresses,
            v4,
            v6,
            interface,
        } => commands::net::link(&paths, email, addresses, v4, v6, interface).await?,
        Commands::List { filter, json } => commands::user::list(&paths, filter, json)?,
        Commands::Info { targets, json } => commands::user::info(&paths, targets, json)?,
        Commands::Show => commands::system::show(&paths)?,
        Commands::Apply => commands::system::apply(&paths)?,
        Commands::Check => commands::system::check(&paths)?,
        Commands::Verify {
            verbose,
            config,
            link,
        } => commands::verify::verify(&paths, verbose, config, link)?,
    }

    Ok(())
}

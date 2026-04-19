mod cli;
mod commands;
mod config;
mod paths;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, DnsCommands, Hysteria2Commands, SkillCommands};
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
            | Commands::Hysteria2 {
                command: Hysteria2Commands::Setup { dry_run: true, .. }
                    | Hysteria2Commands::AddUser { dry_run: true, .. },
            }
            | Commands::Dns {
                command: DnsCommands::SetupDoH3 { dry_run: true, .. }
                    | DnsCommands::AddServer { dry_run: true, .. },
            }
            | Commands::Upgrade {
                dry_run: true,
                ..
            }
            | Commands::Diagnose { .. }
            | Commands::Skill { .. }
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
        Commands::Hysteria2 { command } => match command {
            Hysteria2Commands::Setup {
                port,
                password,
                masquerade,
                domain,
                cert_path,
                key_path,
                up_mbps,
                down_mbps,
                obfs,
                http2_idle_timeout,
                http2_keep_alive_period,
                http2_max_concurrent_streams,
                quic_initial_packet_size,
                quic_disable_path_mtu_discovery,
                dry_run,
            } => commands::hysteria2::setup(
                &paths,
                port,
                password,
                masquerade,
                domain,
                cert_path,
                key_path,
                up_mbps,
                down_mbps,
                obfs,
                http2_idle_timeout,
                http2_keep_alive_period,
                http2_max_concurrent_streams,
                quic_initial_packet_size,
                quic_disable_path_mtu_discovery,
                dry_run,
            )?,
            Hysteria2Commands::AddUser { name, password, dry_run } => {
                commands::hysteria2::add_user(&paths, name, password, dry_run)?
            }
            Hysteria2Commands::Link { name } => {
                commands::hysteria2::link(&paths, name)?
            }
        },
        Commands::Dns { command } => match command {
            DnsCommands::SetupDoH3 { dry_run } => {
                commands::dns::setup(&paths, dry_run)?
            }
            DnsCommands::AddServer {
                tag,
                server,
                server_type,
                port,
                path,
                dry_run,
            } => commands::dns::add_server(
                &paths,
                tag,
                server,
                server_type,
                port,
                path,
                dry_run,
            )?,
        },
        Commands::Completions { shell, apply } => commands::net::completions(shell, apply)?,
        Commands::Link {
            email,
            addresses,
            v4,
            v6,
            interface,
            assign,
            assign_v4,
            strict,
            num,
        } => {
            commands::net::link(
                &paths, email, addresses, v4, v6, interface, num, assign, assign_v4, strict,
            )
            .await?
        }
        Commands::FromLink {
            out,
            socks,
            tun,
            selector_tag,
        } => commands::net::from_link(&paths, out, socks, tun, selector_tag).await?,
        Commands::List { filter, json } => commands::user::list(&paths, filter, json)?,
        Commands::Info { targets, json } => commands::user::info(&paths, targets, json)?,
        Commands::Show => commands::system::show(&paths)?,
        Commands::Diff => commands::system::diff(&paths)?,
        Commands::Apply => commands::system::apply(&paths)?,
        Commands::Check => commands::system::check(&paths)?,
        Commands::Protect { unprotect } => commands::protect::protect(&paths, unprotect)?,
        Commands::Upgrade { auto, dry_run } => {
            commands::update::upgrade(&paths, auto, dry_run)?
        }
        Commands::Setup => {
            commands::setup::interactive(&paths)?
        }
        Commands::Diagnose { verbose } => {
            commands::diagnose::run(&paths, verbose)?
        }
        Commands::Verify {
            verbose,
            config,
            link,
        } => commands::verify::verify(&paths, verbose, config, link)?,
        Commands::Skill { command } => match command {
            SkillCommands::Install { project, force } => {
                commands::skill::install(project, force)?
            }
            SkillCommands::Uninstall { project } => commands::skill::uninstall(project)?,
            SkillCommands::Status => commands::skill::status()?,
        },
    }

    Ok(())
}

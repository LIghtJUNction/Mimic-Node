mod cli;
mod commands;
mod config;
mod paths;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, DnsCommands, GistCommands, Hysteria2Commands, SkillCommands};
use paths::Paths;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let paths = Paths::new();

    let no_staged_changes = matches!(&args.command, Commands::Apply)
        && !paths.staging.exists()
        && !paths.staging_pubkey.exists();
    if requires_overlay(&args.command) && !no_staged_changes {
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
                obfs_password,
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
                obfs_password,
                http2_idle_timeout,
                http2_keep_alive_period,
                http2_max_concurrent_streams,
                quic_initial_packet_size,
                quic_disable_path_mtu_discovery,
                dry_run,
            )?,
            Hysteria2Commands::AddUser {
                name,
                password,
                dry_run,
            } => commands::hysteria2::add_user(&paths, name, password, dry_run)?,
            Hysteria2Commands::Link { name } => commands::hysteria2::link(&paths, name)?,
        },
        Commands::Dns { command } => match command {
            DnsCommands::SetupDoH3 { dry_run } => commands::dns::setup(&paths, dry_run)?,
            DnsCommands::AddServer {
                tag,
                server,
                server_type,
                port,
                path,
                dry_run,
            } => commands::dns::add_server(&paths, tag, server, server_type, port, path, dry_run)?,
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
        Commands::Upgrade { auto, dry_run } => commands::update::upgrade(&paths, auto, dry_run)?,
        Commands::Setup => commands::setup::interactive(&paths)?,
        Commands::Diagnose { verbose } => commands::diagnose::run(&paths, verbose)?,
        Commands::Verify {
            verbose,
            config,
            link,
        } => commands::verify::verify(&paths, verbose, config, link)?,
        Commands::Skill { command } => match command {
            SkillCommands::Install { project, force } => commands::skill::install(project, force)?,
            SkillCommands::Uninstall { project } => commands::skill::uninstall(project)?,
            SkillCommands::Status => commands::skill::status()?,
        },
        Commands::Gist { command } => match command {
            GistCommands::Setup {
                gist_id,
                username,
                remark,
                node_name,
                convert_type,
                cron,
            } => commands::gist::setup(
                gist_id.as_deref(),
                &username,
                remark.as_deref(),
                node_name.as_deref(),
                convert_type.as_deref(),
                cron.as_deref(),
            )?,
            GistCommands::Sync { include_hy2 } => commands::gist::sync(include_hy2)?,
            GistCommands::Revoke { gist_id } => commands::gist::revoke(gist_id.as_deref())?,
            GistCommands::List => commands::gist::list()?,
            GistCommands::Rm { gist_id } => commands::gist::rm(gist_id.as_deref())?,
        },
    }

    Ok(())
}

/// Reading a configuration, checking it or converting a client link must never
/// start services or mount a filesystem on the caller's machine.
fn requires_overlay(command: &Commands) -> bool {
    matches!(
        command,
        Commands::GenKeys
            | Commands::Add { .. }
            | Commands::Reset { .. }
            | Commands::Discard { .. }
            | Commands::Sni { .. }
            | Commands::Diff
            | Commands::Apply
            | Commands::Protect { .. }
            | Commands::Setup
            | Commands::Del { dry_run: false, .. }
            | Commands::ResetUser { dry_run: false, .. }
            | Commands::Update { dry_run: false, .. }
            | Commands::Upgrade { dry_run: false, .. }
            | Commands::Hysteria2 {
                command: Hysteria2Commands::Setup { dry_run: false, .. }
                    | Hysteria2Commands::AddUser { dry_run: false, .. }
            }
            | Commands::Dns {
                command: DnsCommands::SetupDoH3 { dry_run: false }
                    | DnsCommands::AddServer { dry_run: false, .. }
            }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_and_preview_commands_never_mount_overlay() {
        for args in [
            vec!["mimictl", "from-link"],
            vec!["mimictl", "verify"],
            vec!["mimictl", "verify", "--link", "vless://example"],
            vec!["mimictl", "list"],
            vec!["mimictl", "info", "alice"],
            vec!["mimictl", "link", "alice"],
            vec!["mimictl", "show"],
            vec!["mimictl", "check"],
            vec!["mimictl", "diagnose"],
            vec!["mimictl", "del", "alice", "--dry-run"],
            vec!["mimictl", "reset-user", "alice", "--dry-run"],
            vec!["mimictl", "update", "alice", "--level", "1", "--dry-run"],
            vec!["mimictl", "hysteria2", "setup", "--dry-run"],
            vec!["mimictl", "dns", "setup-do-h3", "--dry-run"],
        ] {
            let cli =
                Cli::try_parse_from(&args).unwrap_or_else(|error| panic!("{args:?}: {error}"));
            assert!(
                !requires_overlay(&cli.command),
                "{args:?} should be read-only"
            );
        }
    }

    #[test]
    fn configuration_writes_require_overlay() {
        for args in [
            vec!["mimictl", "apply"],
            vec!["mimictl", "add", "alice"],
            vec!["mimictl", "gen-keys"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(requires_overlay(&cli.command));
        }
    }
}

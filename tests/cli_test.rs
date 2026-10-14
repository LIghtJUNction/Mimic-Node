mod common;

use common::{Sandbox, assert_failure, assert_success};

#[test]
fn command_help_is_available_without_a_system_installation() {
    let sandbox = Sandbox::new();
    let cases: &[(&[&str], &[&str])] = &[
        (&["--help"], &["mimictl", "Usage:"]),
        (&["completions", "--help"], &["shell"]),
        (&["gen-keys", "--help"], &["Usage:"]),
        (&["add", "--help"], &["EMAILS", "level"]),
        (&["del", "--help"], &["TARGETS", "dry-run"]),
        (&["update", "--help"], &["TARGETS", "email"]),
        (&["reset-user", "--help"], &["TARGETS", "dry-run"]),
        (&["hysteria2", "--help"], &["setup", "add-user"]),
        (
            &["hysteria2", "setup", "--help"],
            &["port", "password", "domain"],
        ),
        (&["hysteria2", "add-user", "--help"], &["password"]),
        (&["dns", "--help"], &["setup-do-h3", "add-server"]),
        (&["dns", "add-server", "--help"], &["tag", "server"]),
        (&["dns", "setup-do-h3", "--help"], &["dry-run"]),
        (&["list", "--help"], &["json"]),
        (&["info", "--help"], &["TARGETS", "json"]),
        (&["verify", "--help"], &["verbose", "config"]),
        (&["upgrade", "--help"], &["auto", "dry-run"]),
        (&["diagnose", "--help"], &["verbose"]),
        (&["link", "--help"], &["EMAIL", "ADDRESSES"]),
        (&["from-link", "--help"], &["out", "socks", "tun"]),
        (&["sni", "--help"], &["domain", "file"]),
        (&["discard", "--help"], &["ITEM", "force"]),
        (&["show", "--help"], &["Usage:"]),
        (&["diff", "--help"], &["Usage:"]),
        (&["check", "--help"], &["Usage:"]),
        (&["apply", "--help"], &["Usage:"]),
        (&["reset", "--help"], &["keep-user"]),
    ];
    for (args, expected) in cases {
        let output = sandbox.run(args);
        assert_success(&output);
        let help = String::from_utf8_lossy(&output.stdout);
        for text in *expected {
            assert!(help.contains(text), "{args:?} help is missing {text:?}");
        }
    }
    assert!(!sandbox.path("etc/sing-box/config.json").exists());
}

#[test]
fn cli_rejects_unknown_commands_and_missing_required_arguments() {
    let sandbox = Sandbox::new();
    assert_failure(
        &sandbox.run(&["invalid-command"]),
        "unrecognized subcommand",
    );
    for command in ["add", "del", "info", "update", "reset-user", "link"] {
        let output = sandbox.run(&[command]);
        assert_eq!(output.status.code(), Some(2), "{command}: {output:?}");
        assert_failure(&output, "required arguments");
    }
    assert!(!sandbox.path("etc/sing-box/config.new").exists());
}

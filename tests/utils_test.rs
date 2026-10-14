mod common;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{Sandbox, assert_failure, assert_success, output_json};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

const CONFIG: &str = "etc/sing-box/config.json";
const STAGING: &str = "etc/sing-box/config.new";

#[test]
fn user_lifecycle_stages_changes_and_synchronizes_reality_ids() {
    let sandbox = Sandbox::new();
    sandbox.stub_validator();
    let original = sandbox.seed_config();
    assert_eq!(
        output_json(&sandbox.run(&["list", "--json"])),
        serde_json::json!([])
    );

    assert_success(&sandbox.run(&[
        "add",
        "alice@example.com",
        "bob@example.com",
        "--level",
        "1",
    ]));
    assert_eq!(
        sandbox.read_json(CONFIG),
        original,
        "add must leave active config intact"
    );
    let added = sandbox.read_json(STAGING);
    let users = added["inbounds"][0]["users"].as_array().unwrap();
    assert_eq!(users.len(), 2);
    for user in users {
        assert!(uuid::Uuid::parse_str(user["uuid"].as_str().unwrap()).is_ok());
        let parts: Vec<_> = user["name"].as_str().unwrap().split(':').collect();
        assert_eq!(parts[2], "1");
        assert_eq!(parts[1].len(), 16);
        assert!(parts[1].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(user["flow"], "xtls-rprx-vision");
    }
    assert_eq!(
        added["inbounds"][0]["tls"]["reality"]["short_id"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let listed = output_json(&sandbox.run(&["list", "alice", "--json"]));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let info =
        output_json(&sandbox.run(&["info", "alice@example.com", "alice@example.com", "--json"]));
    assert_eq!(info, listed, "overlapping targets must not duplicate users");

    assert_success(&sandbox.run(&[
        "update",
        "alice@example.com",
        "--email",
        "carol@example.com",
        "--level",
        "10",
    ]));
    let updated = output_json(&sandbox.run(&["info", "carol@example.com", "--json"]));
    assert!(
        updated[0]["name"]
            .as_str()
            .unwrap()
            .starts_with("carol@example.com:")
    );
    assert!(updated[0]["name"].as_str().unwrap().ends_with(":10"));
    assert_eq!(updated[0]["uuid"], listed[0]["uuid"]);

    assert_success(&sandbox.run(&["reset-user", "carol@example.com"]));
    let reset = output_json(&sandbox.run(&["info", "carol@example.com", "--json"]));
    assert_ne!(reset[0]["uuid"], updated[0]["uuid"]);
    assert_ne!(reset[0]["name"], updated[0]["name"]);
    assert_success(&sandbox.run(&["verify"]));

    assert_success(&sandbox.run(&["del", "*@example.com"]));
    let deleted = sandbox.read_json(STAGING);
    assert!(
        deleted["inbounds"][0].get("users").is_none()
            || deleted["inbounds"][0]["users"] == serde_json::json!([])
    );
    assert_eq!(
        output_json(&sandbox.run(&["list", "--json"])),
        serde_json::json!([])
    );
    assert_eq!(
        deleted["inbounds"][0]["tls"]["reality"]["short_id"],
        serde_json::json!([])
    );
    assert_eq!(
        sandbox.read_json(CONFIG),
        original,
        "lifecycle must only alter staging"
    );
}

#[test]
fn dry_runs_do_not_create_or_modify_staging() {
    let sandbox = Sandbox::new();
    sandbox.seed_config();
    assert_success(&sandbox.run(&["add", "alice@example.com"]));
    let active = fs::read(sandbox.path(STAGING)).unwrap();
    fs::rename(sandbox.path(STAGING), sandbox.path(CONFIG)).unwrap();
    for args in [
        vec!["del", "alice@example.com", "--dry-run"],
        vec!["reset-user", "alice@example.com", "--dry-run"],
        vec!["update", "alice@example.com", "--level", "99", "--dry-run"],
    ] {
        assert_success(&sandbox.run(&args));
        assert!(
            !sandbox.path(STAGING).exists(),
            "dry-run created staging: {args:?}"
        );
        assert_eq!(fs::read(sandbox.path(CONFIG)).unwrap(), active);
    }
    assert_success(&sandbox.run(&["add", "bob@example.com"]));
    let staged = fs::read(sandbox.path(STAGING)).unwrap();
    assert_success(&sandbox.run(&["del", "bob@example.com", "--dry-run"]));
    assert_eq!(fs::read(sandbox.path(STAGING)).unwrap(), staged);
}

#[test]
fn discard_removes_only_requested_staged_files() {
    let sandbox = Sandbox::new();
    let original = sandbox.seed_config();
    assert_success(&sandbox.run(&["add", "alice@example.com"]));
    fs::write(sandbox.path("etc/sing-box/PUBKEY.new"), "staged-key").unwrap();
    assert_success(&sandbox.run(&["discard", "--item", "config", "--force"]));
    assert!(!sandbox.path(STAGING).exists());
    assert!(sandbox.path("etc/sing-box/PUBKEY.new").exists());
    assert_eq!(sandbox.read_json(CONFIG), original);
    assert_success(&sandbox.run(&["discard", "--item", "pubkey", "--force"]));
    assert!(!sandbox.path("etc/sing-box/PUBKEY.new").exists());
    assert!(sandbox.path("etc/sing-box/PUBKEY").exists());
}

#[test]
fn missing_config_and_unmatched_users_have_actionable_failures() {
    let sandbox = Sandbox::new();
    assert_failure(&sandbox.run(&["list", "--json"]), "Failed to read config");
    let original = sandbox.seed_config();
    for command in ["info", "del", "reset-user"] {
        assert_failure(
            &sandbox.run(&[command, "missing@example.com"]),
            "No users matched",
        );
    }
    assert_failure(
        &sandbox.run(&["update", "missing@example.com"]),
        "No update action specified",
    );
    assert_failure(
        &sandbox.run(&["discard", "--item", "invalid", "--force"]),
        "Unknown discard item",
    );
    assert!(!sandbox.path(STAGING).exists());
    assert_eq!(sandbox.read_json(CONFIG), original);
}

#[test]
fn explicit_address_links_round_trip_to_a_client_config_without_network() {
    let sandbox = Sandbox::new();
    sandbox.seed_config();
    assert_success(&sandbox.run(&["add", "alice@example.com"]));
    let user = output_json(&sandbox.run(&["info", "alice@example.com", "--json"]));
    for address in ["192.0.2.10", "2001:db8::10"] {
        let links = sandbox.run(&["link", "alice@example.com", address]);
        let parsed_links = output_json(&links);
        assert_eq!(parsed_links.as_array().unwrap().len(), 1);
        let client = output_json(&sandbox.run_with_input(&["from-link", "--socks"], &links.stdout));
        let outbound = client["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["type"] == "vless")
            .unwrap();
        assert_eq!(outbound["server"], address);
        assert_eq!(outbound["server_port"], 443);
        assert_eq!(outbound["uuid"], user[0]["uuid"]);
        assert_eq!(outbound["tls"]["server_name"], "example.com");
        assert_eq!(client["inbounds"][0]["type"], "socks");
        assert_eq!(client["route"]["final"], outbound["tag"]);
    }
}

#[test]
fn client_import_rejects_empty_and_incomplete_links() {
    let sandbox = Sandbox::new();
    assert_failure(
        &sandbox.run(&["from-link"]),
        "No VLESS links found on stdin",
    );
    let invalid =
        b"vless://00000000-0000-4000-8000-000000000000@192.0.2.10:443?sni=example.com&sid=abcd";
    assert_failure(
        &sandbox.run_with_input(&["from-link"], invalid),
        "missing 'pbk' parameter",
    );
}

#[test]
fn verify_rejects_a_missing_custom_file_and_a_mismatched_public_key() {
    let sandbox = Sandbox::new();
    sandbox.stub_validator();
    let missing = sandbox.path("missing.json");
    assert_failure(
        &sandbox.run(&["verify", "--config", missing.to_str().unwrap()]),
        "Custom config file not found",
    );
    sandbox.seed_config();
    assert_success(&sandbox.run(&["verify"]));
    fs::write(sandbox.path("etc/sing-box/PUBKEY"), "invalid").unwrap();
    assert_failure(&sandbox.run(&["verify"]), "Stored PUBKEY is invalid");
}

#[test]
fn verify_accepts_hysteria_only_configs_and_explains_reality_link_mismatch() {
    let sandbox = Sandbox::new();
    sandbox.stub_validator();
    let config = serde_json::json!({
        "inbounds": [{
            "type": "hysteria2", "tag": "hy2-in", "listen": "::", "listen_port": 443,
            "users": [{"name": "alice", "password": "test-password"}],
            "tls": {"enabled": true, "certificate_path": "test-cert.pem", "key_path": "test-key.pem"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    fs::write(sandbox.path(CONFIG), serde_json::to_vec(&config).unwrap()).unwrap();
    assert_success(&sandbox.run(&["verify"]));
    let link = "vless://00000000-0000-4000-8000-000000000000@192.0.2.10:443";
    assert_failure(
        &sandbox.run(&["verify", "--link", link]),
        "No VLESS inbound with enabled TLS and Reality found",
    );
    assert_eq!(sandbox.read_json(CONFIG), config);
    assert!(!sandbox.path(STAGING).exists());
}

#[test]
fn hysteria_preview_uses_absolute_certificate_paths_and_preserves_renewal_symlinks() {
    let sandbox = Sandbox::new();
    let original = sandbox.seed_config();
    fs::create_dir_all(sandbox.path("certificates/archive")).unwrap();
    fs::create_dir_all(sandbox.path("certificates/live")).unwrap();
    fs::write(
        sandbox.path("certificates/archive/cert-v1.pem"),
        "-----BEGIN CERTIFICATE-----\ntest fixture\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    fs::write(
        sandbox.path("certificates/archive/key-v1.pem"),
        "-----BEGIN PRIVATE KEY-----\ntest fixture\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../archive/cert-v1.pem",
        sandbox.path("certificates/live/fullchain.pem"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../archive/key-v1.pem",
        sandbox.path("certificates/live/privkey.pem"),
    )
    .unwrap();
    let preview = output_json(&sandbox.run(&[
        "hysteria2",
        "setup",
        "--dry-run",
        "--password",
        "test-password",
        "--cert",
        "certificates/live/fullchain.pem",
        "--key",
        "certificates/live/privkey.pem",
    ]));
    let hy2 = preview["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|inbound| inbound["type"] == "hysteria2")
        .unwrap();
    assert_eq!(
        hy2["tls"]["certificate_path"],
        sandbox
            .path("certificates/live/fullchain.pem")
            .to_str()
            .unwrap()
    );
    assert_eq!(
        hy2["tls"]["key_path"],
        sandbox
            .path("certificates/live/privkey.pem")
            .to_str()
            .unwrap()
    );
    assert_eq!(
        fs::read_link(sandbox.path("certificates/live/fullchain.pem")).unwrap(),
        std::path::Path::new("../archive/cert-v1.pem")
    );
    assert_eq!(sandbox.read_json(CONFIG), original);
    assert!(!sandbox.path(STAGING).exists());
}

#[test]
fn key_generation_without_external_tools_stages_a_real_keypair() {
    let sandbox = Sandbox::new();
    let original = sandbox.seed_config();
    let output = sandbox.run(&["gen-keys"]);
    assert_success(&output);
    let staged = sandbox.read_json(STAGING);
    let private_key = staged["inbounds"][0]["tls"]["reality"]["private_key"]
        .as_str()
        .unwrap();
    let private: [u8; 32] = URL_SAFE_NO_PAD
        .decode(private_key)
        .unwrap()
        .try_into()
        .unwrap();
    let public = fs::read_to_string(sandbox.path("etc/sing-box/PUBKEY.new")).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&public).unwrap(),
        x25519(private, X25519_BASEPOINT_BYTES)
    );
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), public);
    assert_eq!(sandbox.read_json(CONFIG), original);
    assert_eq!(
        fs::metadata(sandbox.path(STAGING))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(sandbox.path("etc/sing-box/PUBKEY.new"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn isolated_apply_validates_and_installs_without_calling_system_services() {
    let sandbox = Sandbox::new();
    let original = sandbox.seed_config();
    sandbox.helper(
        "systemctl",
        "#!/bin/sh\n: > systemctl-was-called\nexit 99\n",
    );
    sandbox.helper("sing-box", "#!/bin/sh\n[ \"$1\" = check ] || exit 91\n[ \"$2\" = -c ] || exit 92\n[ -f \"$3\" ] || exit 93\n: > validated-config\nexit 0\n");
    assert_success(&sandbox.run(&["apply"]));
    assert!(
        !sandbox.path("validated-config").exists(),
        "no-op apply must skip validation"
    );
    assert_success(&sandbox.run(&["add", "alice@example.com"]));
    let staged = sandbox.read_json(STAGING);
    assert_ne!(staged, original);
    assert_success(&sandbox.run(&["apply"]));
    assert!(sandbox.path("validated-config").exists());
    assert!(!sandbox.path("systemctl-was-called").exists());
    assert!(!sandbox.path(STAGING).exists());
    assert_eq!(sandbox.read_json(CONFIG), staged);
    assert_eq!(
        fs::metadata(sandbox.path(CONFIG))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn apply_derives_the_rotated_public_key_after_staged_pubkey_is_discarded() {
    let sandbox = Sandbox::new();
    sandbox.seed_config();
    sandbox.stub_validator();
    let old_public = fs::read_to_string(sandbox.path("etc/sing-box/PUBKEY")).unwrap();
    assert_success(&sandbox.run(&["add", "alice@example.com"]));
    assert_success(&sandbox.run(&["gen-keys"]));
    let expected_public = fs::read_to_string(sandbox.path("etc/sing-box/PUBKEY.new")).unwrap();
    let staged = sandbox.read_json(STAGING);
    assert_ne!(old_public, expected_public);
    assert_success(&sandbox.run(&["discard", "--item", "pubkey", "--force"]));
    assert!(!sandbox.path("etc/sing-box/PUBKEY.new").exists());
    assert_success(&sandbox.run(&["apply"]));
    assert_eq!(
        fs::read_to_string(sandbox.path("etc/sing-box/PUBKEY")).unwrap(),
        expected_public
    );
    assert_eq!(sandbox.read_json(CONFIG), staged);
    assert!(!sandbox.path(STAGING).exists());
    assert!(!sandbox.path("etc/sing-box/PUBKEY.new").exists());
    assert_success(&sandbox.run(&["verify"]));
}

#[test]
fn hysteria_only_apply_does_not_require_or_create_a_reality_public_key() {
    let sandbox = Sandbox::new();
    sandbox.stub_validator();
    let staged = serde_json::json!({"inbounds": [{"type": "hysteria2"}], "outbounds": []});
    fs::write(sandbox.path(STAGING), serde_json::to_vec(&staged).unwrap()).unwrap();
    assert_success(&sandbox.run(&["apply"]));
    assert_eq!(sandbox.read_json(CONFIG), staged);
    assert!(!sandbox.path("etc/sing-box/PUBKEY").exists());
}

#[test]
fn apply_cannot_report_success_when_the_derived_public_key_cannot_be_installed() {
    let sandbox = Sandbox::new();
    let original = sandbox.seed_config();
    sandbox.stub_validator();
    assert_success(&sandbox.run(&["gen-keys"]));
    assert_success(&sandbox.run(&["discard", "--item", "pubkey", "--force"]));
    fs::remove_file(sandbox.path("etc/sing-box/PUBKEY")).unwrap();
    fs::create_dir(sandbox.path("etc/sing-box/PUBKEY")).unwrap();
    let output = sandbox.run(&["apply"]);
    assert!(
        !output.status.success(),
        "apply reported success without installing PUBKEY"
    );
    assert_eq!(sandbox.read_json(CONFIG), original);
    assert!(sandbox.path(STAGING).exists());
}

#[test]
fn failed_apply_preserves_active_and_staged_configurations() {
    let sandbox = Sandbox::new();
    let original = sandbox.seed_config();
    assert_success(&sandbox.run(&["add", "alice@example.com"]));
    let staged = fs::read(sandbox.path(STAGING)).unwrap();
    sandbox.helper("sing-box", "#!/bin/sh\nexit 1\n");
    assert_failure(&sandbox.run(&["apply"]), "staged files were preserved");
    assert_eq!(sandbox.read_json(CONFIG), original);
    assert_eq!(fs::read(sandbox.path(STAGING)).unwrap(), staged);
    let leftovers: Vec<_> = fs::read_dir(sandbox.path("etc/sing-box"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name.to_string_lossy().starts_with(".mimictl-check-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "validation snapshot must be removed after failure"
    );
}

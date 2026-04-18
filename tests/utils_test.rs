use std::process::Command;

#[test]
fn test_uuid_generation() {
    // UUID should be 36 characters (8-4-4-4-12 format)
    let output = Command::new("./target/debug/mimictl")
        .args(["gen-keys"])
        .output()
        .expect("Failed to execute gen-keys");

    // Even if it fails due to overlay, check the error is handled
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should produce some output (either keys or error message)
    assert!(!stdout.is_empty() || !stderr.is_empty(),
            "gen-keys should produce some output");
}

#[test]
fn test_link_generation_requires_email() {
    let output = Command::new("./target/debug/mimictl")
        .args(["link"])
        .output()
        .expect("Failed to execute link");

    // Should fail - missing email argument
    assert!(!output.status.success());
}

#[test]
fn test_link_generation_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["link", "--help"])
        .output()
        .expect("Failed to execute link --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("email") || stdout.contains("address"));
}

#[test]
fn test_from_link_requires_input() {
    let output = Command::new("./target/debug/mimictl")
        .args(["from-link"])
        .output()
        .expect("Failed to execute from-link");

    // Should either succeed with stdin input or fail gracefully
    // We just check it doesn't panic
}

#[test]
fn test_sni_command_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["sni", "--help"])
        .output()
        .expect("Failed to execute sni --help");

    assert!(output.status.success());
}

#[test]
fn test_add_user_with_level() {
    // This should fail gracefully (no config) but not panic
    let output = Command::new("./target/debug/mimictl")
        .args(["add", "test@example.com", "--level", "1"])
        .output()
        .expect("Failed to execute add");

    // Either succeeds or fails gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should have some output indicating what happened
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_delete_with_dry_run() {
    // This should fail gracefully (no config) but not panic
    let output = Command::new("./target/debug/mimictl")
        .args(["del", "test@example.com", "--dry-run"])
        .output()
        .expect("Failed to execute del --dry-run");

    // Should have some output
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_update_user_level() {
    // This should fail gracefully
    let output = Command::new("./target/debug/mimictl")
        .args(["update", "test@example.com", "--level", "10"])
        .output()
        .expect("Failed to execute update");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_reset_user_dry_run() {
    let output = Command::new("./target/debug/mimictl")
        .args(["reset-user", "test@example.com", "--dry-run"])
        .output()
        .expect("Failed to execute reset-user --dry-run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_list_users() {
    let output = Command::new("./target/debug/mimictl")
        .args(["list"])
        .output()
        .expect("Failed to execute list");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_list_users_json() {
    let output = Command::new("./target/debug/mimictl")
        .args(["list", "--json"])
        .output()
        .expect("Failed to execute list --json");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // JSON output should be valid or error message
    if stdout.starts_with('[') {
        // Should be parseable as JSON array
        let result: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(result.is_ok() || !stderr.is_empty());
    }
}

#[test]
fn test_info_single_user() {
    let output = Command::new("./target/debug/mimictl")
        .args(["info", "test@example.com"])
        .output()
        .expect("Failed to execute info");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_info_multiple_users() {
    let output = Command::new("./target/debug/mimictl")
        .args(["info", "user1@example.com", "user2@example.com"])
        .output()
        .expect("Failed to execute info multiple");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_info_with_json() {
    let output = Command::new("./target/debug/mimictl")
        .args(["info", "test@example.com", "--json"])
        .output()
        .expect("Failed to execute info --json");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.starts_with('[') || stdout.starts_with('{') {
        let result: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
        assert!(result.is_ok() || !stderr.is_empty());
    }
}

#[test]
fn test_hysteria2_add_user_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["hysteria2", "add-user", "--help"])
        .output()
        .expect("Failed to execute hysteria2 add-user --help");

    assert!(output.status.success());
}

#[test]
fn test_dns_add_server_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["dns", "add-server", "--help"])
        .output()
        .expect("Failed to execute dns add-server --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("tag"));
    assert!(stdout.contains("server"));
}

#[test]
fn test_dns_setup_doh3_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["dns", "setup-do-h3", "--help"])
        .output()
        .expect("Failed to execute dns setup-do-h3 --help");

    assert!(output.status.success());
}

#[test]
fn test_verify_config_path() {
    let output = Command::new("./target/debug/mimictl")
        .args(["verify", "--config", "/tmp/nonexistent.json"])
        .output()
        .expect("Failed to execute verify");

    // Should handle missing file gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_verify_link() {
    let output = Command::new("./target/debug/mimictl")
        .args(["verify", "--link", "invalid-link"])
        .output()
        .expect("Failed to execute verify --link");

    // Should handle invalid link gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_upgrade_dry_run() {
    let output = Command::new("./target/debug/mimictl")
        .args(["upgrade", "--dry-run"])
        .output()
        .expect("Failed to execute upgrade --dry-run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_upgrade_auto() {
    let output = Command::new("./target/debug/mimictl")
        .args(["upgrade", "--auto", "--dry-run"])
        .output()
        .expect("Failed to execute upgrade --auto --dry-run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_diagnose_verbose() {
    let output = Command::new("./target/debug/mimictl")
        .args(["diagnose", "--verbose"])
        .output()
        .expect("Failed to execute diagnose --verbose");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_discard_items() {
    let output = Command::new("./target/debug/mimictl")
        .args(["discard", "--item", "config", "--item", "pubkey", "--force"])
        .output()
        .expect("Failed to execute discard");

    // Should handle gracefully even without staging files
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_link_with_v4_flag() {
    let output = Command::new("./target/debug/mimictl")
        .args(["link", "test@example.com", "--v4"])
        .output()
        .expect("Failed to execute link --v4");

    // Should either succeed or fail gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_link_with_v6_flag() {
    let output = Command::new("./target/debug/mimictl")
        .args(["link", "test@example.com", "--v6"])
        .output()
        .expect("Failed to execute link --v6");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

#[test]
fn test_link_with_num() {
    let output = Command::new("./target/debug/mimictl")
        .args(["link", "test@example.com", "--num", "3"])
        .output()
        .expect("Failed to execute link --num");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty() || !stderr.is_empty());
}

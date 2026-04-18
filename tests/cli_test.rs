use std::process::Command;

#[test]
fn test_cli_help() {
    let output = Command::new("./target/debug/mimictl")
        .arg("--help")
        .output()
        .expect("Failed to execute mimictl");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("mimictl"));
    assert!(stdout.contains("Usage:"));
}

#[test]
fn test_cli_completions_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["completions", "--help"])
        .output()
        .expect("Failed to execute mimictl completions");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("shell"));
}

#[test]
fn test_cli_gen_keys_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["gen-keys", "--help"])
        .output()
        .expect("Failed to execute mimictl gen-keys");

    assert!(output.status.success());
}

#[test]
fn test_cli_add_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["add", "--help"])
        .output()
        .expect("Failed to execute mimictl add");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMAILS"));
    assert!(stdout.contains("level"));
}

#[test]
fn test_cli_del_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["del", "--help"])
        .output()
        .expect("Failed to execute mimictl del");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TARGETS"));
}

#[test]
fn test_cli_update_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["update", "--help"])
        .output()
        .expect("Failed to execute mimictl update");

    assert!(output.status.success());
}

#[test]
fn test_cli_reset_user_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["reset-user", "--help"])
        .output()
        .expect("Failed to execute mimictl reset-user");

    assert!(output.status.success());
}

#[test]
fn test_cli_hysteria2_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["hysteria2", "--help"])
        .output()
        .expect("Failed to execute mimictl hysteria2");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("setup"));
    assert!(stdout.contains("add-user"));
}

#[test]
fn test_cli_hysteria2_setup_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["hysteria2", "setup", "--help"])
        .output()
        .expect("Failed to execute mimictl hysteria2 setup");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("port"));
    assert!(stdout.contains("password"));
    assert!(stdout.contains("domain"));
}

#[test]
fn test_cli_dns_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["dns", "--help"])
        .output()
        .expect("Failed to execute mimictl dns");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("setup-do-h3"));
    assert!(stdout.contains("add-server"));
}

#[test]
fn test_cli_list_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["list", "--help"])
        .output()
        .expect("Failed to execute mimictl list");

    assert!(output.status.success());
}

#[test]
fn test_cli_info_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["info", "--help"])
        .output()
        .expect("Failed to execute mimictl info");

    assert!(output.status.success());
}

#[test]
fn test_cli_verify_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["verify", "--help"])
        .output()
        .expect("Failed to execute mimictl verify");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verbose"));
    assert!(stdout.contains("config"));
}

#[test]
fn test_cli_upgrade_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["upgrade", "--help"])
        .output()
        .expect("Failed to execute mimictl upgrade");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("auto"));
    assert!(stdout.contains("dry-run"));
}

#[test]
fn test_cli_diagnose_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["diagnose", "--help"])
        .output()
        .expect("Failed to execute mimictl diagnose");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("verbose"));
}

#[test]
fn test_cli_link_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["link", "--help"])
        .output()
        .expect("Failed to execute mimictl link");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("EMAIL"));
    assert!(stdout.contains("ADDRESSES"));
}

#[test]
fn test_cli_from_link_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["from-link", "--help"])
        .output()
        .expect("Failed to execute mimictl from-link");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("out"));
    assert!(stdout.contains("socks"));
    assert!(stdout.contains("tun"));
}

#[test]
fn test_cli_sni_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["sni", "--help"])
        .output()
        .expect("Failed to execute mimictl sni");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("domain"));
    assert!(stdout.contains("file"));
}

#[test]
fn test_cli_discard_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["discard", "--help"])
        .output()
        .expect("Failed to execute mimictl discard");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ITEM"));
    assert!(stdout.contains("force"));
}

#[test]
fn test_cli_show_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["show", "--help"])
        .output()
        .expect("Failed to execute mimictl show");

    assert!(output.status.success());
}

#[test]
fn test_cli_diff_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["diff", "--help"])
        .output()
        .expect("Failed to execute mimictl diff");

    assert!(output.status.success());
}

#[test]
fn test_cli_check_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["check", "--help"])
        .output()
        .expect("Failed to execute mimictl check");

    assert!(output.status.success());
}

#[test]
fn test_cli_apply_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["apply", "--help"])
        .output()
        .expect("Failed to execute mimictl apply");

    assert!(output.status.success());
}

#[test]
fn test_cli_reset_help() {
    let output = Command::new("./target/debug/mimictl")
        .args(["reset", "--help"])
        .output()
        .expect("Failed to execute mimictl reset");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("keep-user"));
}

#[test]
fn test_invalid_command() {
    let output = Command::new("./target/debug/mimictl")
        .args(["invalid-command"])
        .output()
        .expect("Failed to execute mimictl");

    // Should fail with error
    assert!(!output.status.success());
}

#[test]
fn test_add_requires_email() {
    let output = Command::new("./target/debug/mimictl")
        .args(["add"])
        .output()
        .expect("Failed to execute mimictl add");

    // Should fail - missing required argument
    assert!(!output.status.success());
}

#[test]
fn test_del_requires_targets() {
    let output = Command::new("./target/debug/mimictl")
        .args(["del"])
        .output()
        .expect("Failed to execute mimictl del");

    // Should fail - missing required argument
    assert!(!output.status.success());
}

#[test]
fn test_info_requires_targets() {
    let output = Command::new("./target/debug/mimictl")
        .args(["info"])
        .output()
        .expect("Failed to execute mimictl info");

    // Should fail - missing required argument
    assert!(!output.status.success());
}

#[test]
fn test_update_requires_targets() {
    let output = Command::new("./target/debug/mimictl")
        .args(["update"])
        .output()
        .expect("Failed to execute mimictl update");

    // Should fail - missing required argument
    assert!(!output.status.success());
}

#[test]
fn test_reset_user_requires_targets() {
    let output = Command::new("./target/debug/mimictl")
        .args(["reset-user"])
        .output()
        .expect("Failed to execute mimictl reset-user");

    // Should fail - missing required argument
    assert!(!output.status.success());
}

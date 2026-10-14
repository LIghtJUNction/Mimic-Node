#![allow(dead_code)]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

/// Every CLI invocation gets its own root and no access to host helper binaries.
/// Keep fixtures under target so Cargo's ignored output directory owns them.
pub struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-roots")
            .join(format!("{}-{}", std::process::id(), uuid::Uuid::new_v4()));
        for dir in ["etc/sing-box", "empty-bin", "home", "config"] {
            fs::create_dir_all(root.join(dir)).expect("create isolated test root");
        }
        Self { root }
    }

    pub fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    /// Install a controlled shell fixture; it never delegates to host programs.
    pub fn helper(&self, name: &str, script: &str) {
        let path = self.path(&format!("empty-bin/{name}"));
        fs::write(&path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// Schema validation itself is exercised by the real sing-box smoke suite.
    /// CLI integrity tests use this checked invocation fixture to stay offline.
    pub fn stub_validator(&self) {
        self.helper(
            "sing-box",
            "#!/bin/sh\n[ \"$1\" = check ] || exit 91\n[ \"$2\" = -c ] || exit 92\n[ -f \"$3\" ] || exit 93\nexit 0\n",
        );
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mimictl"));
        command
            .env_clear()
            .env("MIMIC_NODE_ROOT", &self.root)
            .env("HOME", self.path("home"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("PATH", self.path("empty-bin"))
            .env("SING_BOX_BIN", self.path("empty-bin/sing-box"))
            .env("NO_COLOR", "1")
            .current_dir(&self.root)
            .stdin(Stdio::null());
        command
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("execute mimictl")
    }

    pub fn run_with_input(&self, args: &[&str], input: &[u8]) -> Output {
        let mut child = self
            .command()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("execute mimictl with stdin");
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().expect("wait for mimictl")
    }

    pub fn seed_config(&self) -> Value {
        let private_key = [42_u8; 32];
        let public_key = URL_SAFE_NO_PAD.encode(x25519(private_key, X25519_BASEPOINT_BYTES));
        let config = json!({
            "log": {"level": "warn", "timestamp": true},
            "inbounds": [{
                "type": "vless", "tag": "vless-in", "listen": "::", "listen_port": 443,
                "users": [],
                "tls": {
                    "enabled": true, "server_name": "example.com",
                    "reality": {
                        "enabled": true,
                        "private_key": URL_SAFE_NO_PAD.encode(private_key),
                        "short_id": [],
                        "handshake": {"server": "example.com", "server_port": 443}
                    }
                }
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"}
        });
        fs::write(
            self.path("etc/sing-box/config.json"),
            serde_json::to_vec_pretty(&config).unwrap(),
        )
        .unwrap();
        fs::write(self.path("etc/sing-box/PUBKEY"), public_key).unwrap();
        config
    }

    pub fn read_json(&self, relative: &str) -> Value {
        serde_json::from_slice(&fs::read(self.path(relative)).unwrap()).unwrap()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove isolated test root");
    }
}

pub fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "mimictl failed with {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn assert_failure(output: &Output, message: &str) {
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "missing diagnostic {message:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn output_json(output: &Output) -> Value {
    assert_success(output);
    serde_json::from_slice(&output.stdout).expect("valid JSON output")
}

use anyhow::{Context, Result, bail};
use colored::*;
use serde_json::Value;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use crate::paths::Paths;

fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|_| {
            let idx = rand::random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_obfs_password() -> String {
    generate_password(16)
}

fn certificate_domain(hy2_inbound: &Value) -> Option<String> {
    let tls = hy2_inbound.get("tls")?;
    if let Some(name) = tls
        .get("server_name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        return Some(name.to_string());
    }
    // The domain follows /etc/letsencrypt/live/, not a fixed slash index.
    let certificate = tls.get("certificate_path")?.as_str()?;
    let domain = Path::new(certificate)
        .strip_prefix("/etc/letsencrypt/live")
        .ok()?
        .components()
        .next()?
        .as_os_str()
        .to_str()?;
    match url::Host::parse(domain).ok()? {
        url::Host::Domain(name) if !name.is_empty() => Some(name),
        _ => None,
    }
}

fn read_pem(path: &str, key: bool) -> Result<()> {
    let contents = std::fs::read_to_string(path).with_context(|| {
        format!(
            "Cannot read TLS {} at '{path}'",
            if key { "private key" } else { "certificate" }
        )
    })?;
    let is_pem = if key {
        [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
        ]
        .iter()
        .any(|header| contents.contains(header))
    } else {
        contents.contains("-----BEGIN CERTIFICATE-----")
    };
    if !is_pem {
        bail!(
            "TLS {} at '{path}' must be in unencrypted PEM format",
            if key { "private key" } else { "certificate" }
        );
    }
    Ok(())
}

fn stage(paths: &Paths, config: &Value, dry_run: bool) -> Result<()> {
    let contents = serde_json::to_string_pretty(config)?;
    if dry_run {
        eprintln!(
            "{} [DRY RUN] Changes previewed (not written)",
            "[WARN]".yellow()
        );
        println!("{contents}");
    } else {
        crate::utils::write_private_file(&paths.staging, contents.as_bytes())?;
        eprintln!(
            "{} Hysteria2 config staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );
    }
    Ok(())
}

// Keep the command handler aligned with the explicit CLI options.
#[allow(clippy::too_many_arguments)]
pub fn setup(
    paths: &Paths,
    port: u16,
    password: Option<String>,
    masquerade: Option<String>,
    domain: Option<String>,
    certificate_path: Option<String>,
    key_path: Option<String>,
    up_mbps: Option<u32>,
    down_mbps: Option<u32>,
    obfs: bool,
    obfs_password: Option<String>,
    http2_idle_timeout: Option<String>,
    http2_keep_alive_period: Option<String>,
    http2_max_concurrent_streams: Option<u32>,
    quic_initial_packet_size: Option<u32>,
    quic_disable_path_mtu_discovery: bool,
    dry_run: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config_str = std::fs::read_to_string(input_path)?;
    let mut config_json: Value = serde_json::from_str(&config_str)?;

    if !obfs && obfs_password.is_some() {
        bail!("--obfs-password requires --obfs");
    }
    let pwd = password.clone().unwrap_or_else(|| generate_password(32));
    let obfs_pwd = if obfs {
        Some(obfs_password.unwrap_or_else(generate_obfs_password))
    } else {
        None
    };

    if port == 0 {
        bail!("Hysteria2 listen port must be between 1 and 65535");
    }
    if pwd.is_empty() {
        bail!("Hysteria2 authentication password must not be empty");
    }
    if obfs_pwd.as_deref() == Some("") {
        bail!("Hysteria2 obfuscation password must not be empty");
    }
    if up_mbps == Some(0) || down_mbps == Some(0) {
        bail!("Bandwidth limits must be greater than zero; omit --up/--down for no limit");
    }
    let domain = domain
        .map(|domain| -> Result<String> {
            match url::Host::parse(&domain).context("Invalid TLS domain")? {
                url::Host::Domain(name) if !name.is_empty() && !name.contains('*') => Ok(name),
                _ => bail!("--domain must be a DNS hostname"),
            }
        })
        .transpose()?;
    let (cert, key) = match (certificate_path, key_path) {
        (Some(cert), Some(key)) => (cert, key),
        (None, None) => {
            let domain = domain.as_deref().context("TLS requires --cert and --key, or --domain with an existing Let's Encrypt certificate. Obtain certificates separately before setup.")?;
            let live = paths.root.join("etc/letsencrypt/live").join(domain);
            (
                live.join("fullchain.pem").to_string_lossy().into_owned(),
                live.join("privkey.pem").to_string_lossy().into_owned(),
            )
        }
        _ => bail!("--cert and --key must be provided together"),
    };
    // Certificate issuance is deliberately separate from config staging, including dry runs.
    read_pem(&cert, false)?;
    read_pem(&key, true)?;
    // Resolve against the caller's directory without dereferencing renewal symlinks.
    let cert = std::path::absolute(cert)?.to_string_lossy().into_owned();
    let key = std::path::absolute(key)?.to_string_lossy().into_owned();

    eprintln!("{} Setting up Hysteria2 inbound...", "[INFO]".green());
    eprintln!("  {}: {}", "Port".cyan(), port);
    eprintln!(
        "{}: {}",
        "Password".cyan(),
        if password.is_some() {
            "(provided)".to_string()
        } else {
            "(auto-generated)".to_string()
        }
    );
    eprintln!(
        "{}: {}",
        "Masquerade".cyan(),
        masquerade.as_deref().unwrap_or("https://microsoft.com")
    );
    if let Some(ref m) = masquerade {
        eprintln!("  {}: {}", "Masquerade".cyan(), m);
    }
    if let Some(ref d) = domain {
        eprintln!("  {}: {}", "Domain".cyan(), d);
    }
    if let (Some(up), Some(down)) = (up_mbps, down_mbps) {
        eprintln!(
            "  {}: {} Mbps  {}: {} Mbps",
            "up_mbps".cyan(),
            up,
            "down_mbps".cyan(),
            down
        );
    }
    if obfs_pwd.is_some() {
        eprintln!("  {}: enabled (salamander)", "Obfs".cyan());
    }

    let masquerade_val = masquerade.unwrap_or_else(|| "https://microsoft.com".to_string());
    let masquerade_val = if masquerade_val.contains("://") {
        masquerade_val
    } else {
        format!("https://{masquerade_val}")
    };
    let masquerade_url = url::Url::parse(&masquerade_val).context("Invalid masquerade URL")?;
    if !matches!(masquerade_url.scheme(), "https" | "http" | "file") {
        bail!("Masquerade URL must use http, https or file");
    }

    // Build the new hy2 inbound JSON with standard structure
    let mut hy2_json = serde_json::json!({
        "type": "hysteria2",
        "tag": "hy2-in",
        "listen": "::",
        "listen_port": port,
        "users": [
            {
                "name": "admin",
                "password": pwd
            }
        ],
        "ignore_client_bandwidth": false,
        "tls": {
            "enabled": true,
            "alpn": ["h3"],
            "certificate_path": cert,
            "key_path": key
        },
        "masquerade": masquerade_val,
    });

    if let Some(domain) = domain {
        hy2_json["tls"]["server_name"] = serde_json::json!(domain);
    }
    if let Some(up) = up_mbps {
        hy2_json["up_mbps"] = serde_json::json!(up);
    }
    if let Some(down) = down_mbps {
        hy2_json["down_mbps"] = serde_json::json!(down);
    }
    // sing-box 1.14 uses shared QUIC/HTTP2 fields on the inbound, not TLS.
    if let Some(initial_size) = quic_initial_packet_size {
        hy2_json["initial_packet_size"] = serde_json::json!(initial_size);
    }
    if quic_disable_path_mtu_discovery {
        hy2_json["disable_path_mtu_discovery"] = serde_json::json!(true);
    }
    if let Some(idle) = http2_idle_timeout {
        hy2_json["idle_timeout"] = serde_json::json!(idle);
    }
    if let Some(keepalive) = http2_keep_alive_period {
        hy2_json["keep_alive_period"] = serde_json::json!(keepalive);
    }
    if let Some(streams) = http2_max_concurrent_streams {
        hy2_json["max_concurrent_streams"] = serde_json::json!(streams);
    }

    // Add obfs if enabled
    if let Some(ref obfs_pass) = obfs_pwd {
        hy2_json["obfs"] = serde_json::json!({
            "type": "salamander",
            "password": obfs_pass
        });
    }

    let inbounds = config_json
        .as_object_mut()
        .context("Configuration must be a JSON object")?
        .entry("inbounds")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .context("inbounds must be an array")?;
    inbounds.retain(|inbound| inbound["tag"].as_str() != Some("hy2-in"));
    let insert_idx = inbounds
        .iter()
        .position(|i| i["type"].as_str() == Some("vless"))
        .map(|i| i + 1)
        .unwrap_or(inbounds.len());
    inbounds.insert(insert_idx, hy2_json);
    super::dns::ensure_default_resolver(&mut config_json)?;
    stage(paths, &config_json, dry_run)
}

pub fn add_user(
    paths: &Paths,
    name: Option<String>,
    password: Option<String>,
    dry_run: bool,
) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config_str = std::fs::read_to_string(input_path)?;
    let mut config_json: Value = serde_json::from_str(&config_str)?;

    let user_name = name.unwrap_or_else(|| "admin".to_string());
    let pwd = password.clone().unwrap_or_else(|| generate_password(32));

    if user_name.trim().is_empty() || pwd.is_empty() {
        bail!("Hysteria2 user name and password must not be empty");
    }
    let inbound = config_json
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|inbounds| {
            inbounds
                .iter_mut()
                .find(|i| i["tag"].as_str() == Some("hy2-in"))
        })
        .context("Hysteria2 inbound 'hy2-in' not found. Run 'mimictl hysteria2 setup' first.")?;
    if inbound["type"].as_str() != Some("hysteria2") {
        bail!("Inbound 'hy2-in' is not a Hysteria2 inbound");
    }
    let users = inbound
        .get_mut("users")
        .and_then(Value::as_array_mut)
        .context("Hysteria2 inbound users must be an array")?;
    if users.iter().any(|u| u["name"].as_str() == Some(&user_name)) {
        bail!("Hysteria2 user '{user_name}' already exists");
    }
    users.push(serde_json::json!({"name": user_name, "password": pwd}));
    stage(paths, &config_json, dry_run)
}

fn detect_server_address(inbound: &Value) -> Result<String> {
    if let Ok(address) = std::env::var("MIMIC_SERVER_IP")
        && !address.trim().is_empty()
    {
        return Ok(address.trim().to_string());
    }
    if let Some(domain) = certificate_domain(inbound) {
        return Ok(domain);
    }
    // Bound network discovery and only accept an actual IP address.
    if let Ok(output) = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--max-time",
            "5",
            "-4",
            "https://ifconfig.me/ip",
        ])
        .output()
        && output.status.success()
        && let Ok(address) = String::from_utf8(output.stdout)
        && let Ok(ip) = address.trim().parse::<IpAddr>()
    {
        return Ok(ip.to_string());
    }
    bail!("Cannot detect server address. Set MIMIC_SERVER_IP to the public IP or hostname.")
}

fn encode_component(value: &str) -> String {
    // RFC 3986 unreserved bytes; notably ':' is encoded to preserve a plain password.
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

fn share_link(inbound: &Value, name: Option<&str>, address: &str) -> Result<String> {
    let port = inbound
        .get("listen_port")
        .and_then(Value::as_u64)
        .filter(|p| *p > 0 && *p <= u16::MAX as u64)
        .context("Hysteria2 listen_port must be between 1 and 65535")?;
    let users = inbound
        .get("users")
        .and_then(Value::as_array)
        .context("No users found in Hysteria2 inbound")?;
    let user = match name {
        Some(name) => users
            .iter()
            .find(|u| u["name"].as_str() == Some(name))
            .with_context(|| format!("User '{name}' not found"))?,
        None => users.first().context("No users configured")?,
    };
    let password = user["password"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("User has no password")?;
    let address = address.trim_matches(['[', ']']);
    let host = match address.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("[{ip}]"),
        Ok(IpAddr::V4(ip)) => ip.to_string(),
        Err(_) if !address.is_empty() => url::Host::parse(address)
            .context("Invalid server hostname")?
            .to_string(),
        Err(_) => bail!("Server address must not be empty"),
    };
    let mut query = Vec::new();
    if let Some(obfs) = inbound.get("obfs") {
        let obfs_type = obfs["type"]
            .as_str()
            .context("Hysteria2 obfs has no type")?;
        if !matches!(obfs_type, "salamander" | "gecko") {
            bail!("Unsupported Hysteria2 obfuscation type '{obfs_type}'");
        }
        let secret = obfs["password"]
            .as_str()
            .filter(|s| !s.is_empty())
            .context("Hysteria2 obfs has no password")?;
        query.push(format!("obfs={obfs_type}"));
        query.push(format!("obfs-password={}", encode_component(secret)));
    }
    if let Some(domain) = certificate_domain(inbound) {
        query.push(format!("sni={}", encode_component(&domain)));
    }
    // Bandwidth limits are client-specific and excluded by the Hysteria URI spec.
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", query.join("&"))
    };
    Ok(format!(
        "hysteria2://{}@{host}:{port}/{query}#hy2",
        encode_component(password)
    ))
}

pub fn link(paths: &Paths, name: Option<String>) -> Result<()> {
    let config_str = std::fs::read_to_string(paths.get_input_config_path())?;
    let config: Value = serde_json::from_str(&config_str)?;
    let inbound = config
        .get("inbounds")
        .and_then(Value::as_array)
        .and_then(|inbounds| {
            inbounds
                .iter()
                .find(|i| i["tag"].as_str() == Some("hy2-in"))
        })
        .context("Hysteria2 inbound 'hy2-in' not found")?;
    if inbound["type"].as_str() != Some("hysteria2") {
        bail!("Inbound 'hy2-in' is not a Hysteria2 inbound");
    }
    println!(
        "{}",
        share_link(inbound, name.as_deref(), &detect_server_address(inbound)?)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn link_encodes_plain_auth_and_obfs_secret_separately_with_ipv6() {
        let inbound = json!({"listen_port": 8443, "up_mbps": 100, "down_mbps": 200,
            "users": [{"name": "admin", "password": "auth:@/?#% 密码"}],
            "obfs": {"type": "salamander", "password": "obfs&+ secret"},
            "tls": {"server_name": "hy.example.com"}});
        let link = share_link(&inbound, None, "2001:db8::1").unwrap();
        assert!(link.starts_with(
            "hysteria2://auth%3A%40%2F%3F%23%25%20%E5%AF%86%E7%A0%81@[2001:db8::1]:8443/"
        ));
        assert!(link.contains("obfs-password=obfs%26%2B%20secret"));
        assert!(link.contains("sni=hy.example.com"));
        assert!(!link.contains("up="));
        assert!(!link.contains("down="));
        let parsed = url::Url::parse(&link).unwrap();
        assert_eq!(parsed.host_str(), Some("[2001:db8::1]"));
    }

    #[test]
    fn certificate_domain_is_taken_after_live_directory() {
        let inbound = json!({"tls": {"certificate_path": "/etc/letsencrypt/live/hy.example.com/fullchain.pem"}});
        assert_eq!(
            certificate_domain(&inbound).as_deref(),
            Some("hy.example.com")
        );
        assert!(
            certificate_domain(
                &json!({"tls": {"certificate_path": "/tmp/cert.example.com/cert.pem"}})
            )
            .is_none()
        );
    }

    #[test]
    fn link_rejects_missing_user_bad_port_and_missing_obfs_secret() {
        let mut inbound =
            json!({"listen_port": 443, "users": [{"name": "one", "password": "secret"}]});
        assert!(share_link(&inbound, Some("other"), "example.com").is_err());
        inbound["obfs"] = json!({"type": "salamander"});
        assert!(share_link(&inbound, None, "example.com").is_err());
        inbound.as_object_mut().unwrap().remove("obfs");
        inbound["listen_port"] = json!(65536);
        assert!(share_link(&inbound, None, "example.com").is_err());
    }
}

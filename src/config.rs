use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SingBoxConfig {
    #[serde(default)]
    pub inbounds: Vec<Inbound>,
    #[serde(default)]
    pub outbounds: Vec<Value>,
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Inbound {
    #[serde(rename = "type")]
    pub protocol_type: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub listen: String,

    #[serde(default, skip_serializing_if = "is_zero")]
    pub listen_port: u16,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    // Capture other fields to avoid losing data when serializing back
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,

    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RealityConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub handshake: HandshakeConfig,

    #[serde(default)]
    pub private_key: String,

    #[serde(default)]
    pub short_id: Vec<String>,

    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct HandshakeConfig {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub server_port: u16,

    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

fn is_zero(value: &u16) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn roundtrip_preserves_tun_schema_and_reality_dial_options() {
        let input = json!({
            "inbounds": [
                {"type": "tun", "tag": "tun-in", "address": ["172.16.0.1/30"], "auto_route": true},
                {"type": "vless", "tls": {"enabled": true, "reality": {
                    "enabled": true, "private_key": "key", "short_id": [],
                    "handshake": {"server": "example.com", "server_port": 443, "bind_interface": "eth0"}
                }}}
            ], "outbounds": []
        });
        let parsed: SingBoxConfig = serde_json::from_value(input).unwrap();
        let output = serde_json::to_value(parsed).unwrap();
        let tun = &output["inbounds"][0];
        assert!(tun.get("listen").is_none());
        assert!(tun.get("listen_port").is_none());
        assert!(tun.get("users").is_none());
        assert!(tun.get("tls").is_none());
        assert_eq!(
            output["inbounds"][1]["tls"]["reality"]["handshake"]["bind_interface"],
            "eth0"
        );
    }
}

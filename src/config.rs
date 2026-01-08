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

    #[serde(default)]
    pub listen: String,

    #[serde(default)]
    pub listen_port: u16,

    #[serde(default)]
    pub users: Vec<User>,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    // Capture other fields to avoid losing data when serializing back
    #[serde(flatten)]
    pub other: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub name: String,
    pub uuid: String,
    pub flow: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub server_name: String,

    #[serde(default)]
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
}

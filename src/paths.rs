use std::path::PathBuf;

pub struct Paths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub staging: PathBuf,
    pub pubkey: PathBuf,
    pub staging_pubkey: PathBuf,
    pub sni_list: PathBuf,
    pub default_config: PathBuf,
}

impl Paths {
    pub fn new() -> Self {
        let root_str = std::env::var("MIMIC_NODE_ROOT").unwrap_or_else(|_| "/".to_string());
        let root = PathBuf::from(root_str);

        let etc_singbox = root.join("etc/sing-box");
        let usr_share = root.join("usr/share/mimic-node");

        Self {
            config: etc_singbox.join("config.json"),
            staging: etc_singbox.join("config.new"),
            pubkey: etc_singbox.join("PUBKEY"),
            staging_pubkey: etc_singbox.join("PUBKEY.new"),
            sni_list: usr_share.join("sni.txt"),
            default_config: usr_share.join("default/config.json"),
            root,
        }
    }

    pub fn get_input_config_path(&self) -> &PathBuf {
        if self.staging.exists() {
            &self.staging
        } else {
            &self.config
        }
    }
}

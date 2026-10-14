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
        let root = std::env::var_os("MIMIC_NODE_ROOT")
            .filter(|root| !root.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        Self::from_root(root)
    }

    pub fn from_root(root: PathBuf) -> Self {
        // Resolve existing aliases of / as well as existing relative roots. A spelling
        // such as /./ must not bypass the system-root safeguards.
        let root = root.canonicalize().unwrap_or(root);

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

    pub fn is_system_root(&self) -> bool {
        self.root
            .canonicalize()
            .is_ok_and(|root| root == std::path::Path::new("/"))
    }

    pub fn get_input_config_path(&self) -> &PathBuf {
        if self.staging.exists() {
            &self.staging
        } else {
            &self.config
        }
    }
}

use anyhow::Result;
use colored::*;
use std::fs;

use crate::paths::Paths;
use crate::utils::{generate_keypair, load_config, save_config};

pub fn generate(paths: &Paths) -> Result<()> {
    eprintln!("{} Generating reality keypair...", "[INFO]".green());
    let (priv_key, pub_key) = generate_keypair()?;

    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first_mut() {
        if let Some(tls) = inbound.tls.as_mut() {
            if let Some(reality) = tls.reality.as_mut() {
                reality.private_key = priv_key;
            }
        }
    }

    save_config(&paths.staging, &config)?;
    fs::write(&paths.staging_pubkey, &pub_key)?;

    eprintln!(
        "{} Keypair staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );
    println!("{}", pub_key);

    Ok(())
}

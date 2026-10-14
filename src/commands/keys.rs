use anyhow::Result;
use colored::*;

use crate::paths::Paths;
use crate::utils::{generate_keypair, load_config, save_config, write_private_file};

pub fn generate(paths: &Paths) -> Result<()> {
    eprintln!("{} Generating reality keypair...", "[INFO]".green());
    let (priv_key, pub_key) = generate_keypair()?;

    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    let index = crate::commands::user::managed_vless_inbound_index(&config)?;
    if let Some(inbound) = config.inbounds.get_mut(index)
        && let Some(tls) = inbound.tls.as_mut()
        && let Some(reality) = tls.reality.as_mut()
    {
        reality.private_key = priv_key;
    }

    write_private_file(&paths.staging_pubkey, pub_key.as_bytes())?;
    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Keypair staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );
    println!("{}", pub_key);

    Ok(())
}

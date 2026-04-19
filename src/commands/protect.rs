use anyhow::Result;
use colored::*;

use crate::paths::Paths;
use crate::utils::{protect_all, unprotect_all};

pub fn protect(paths: &Paths, unprotect: bool) -> Result<()> {
    if unprotect {
        eprintln!("{}", "[INFO] Removing protection from important files...".yellow());
        eprintln!("{} Files can now be modified or deleted", "[WARN]".yellow());
        eprintln!("{} Remember to re-protect after editing: sudo mimictl protect", "[INFO]".cyan());
        unprotect_all(paths)?;
    } else {
        protect_all(paths)?;
        eprintln!();
        eprintln!("{}", "[INFO] Protection enabled!".green());
        eprintln!("  {} Protected: PUBKEY, config.json", "[*]".cyan());
        eprintln!();
        eprintln!("  {} To modify protected files:", "[INFO]".cyan());
        eprintln!("  {} 1. sudo mimictl protect --unprotect", "[>]".dimmed());
        eprintln!("  {} 2. Edit the files manually", "[>]".dimmed());
        eprintln!("  {} 3. sudo mimictl protect (re-protect)", "[>]".dimmed());
        eprintln!();
        eprintln!("  {} Or use mimictl commands which auto-handle protection", "[>]".dimmed());
    }
    Ok(())
}

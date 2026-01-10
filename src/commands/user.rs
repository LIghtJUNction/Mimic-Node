use anyhow::{Result, anyhow};
use colored::*;
use regex::Regex;
use std::collections::HashSet;
use std::fs;

use crate::config;
use crate::paths::Paths;
use crate::utils::{generate_keypair, generate_sid, generate_uuid, load_config, save_config};

const FLOW_TYPE: &str = "xtls-rprx-vision";

/// Helper to synchronize reality.short_id list with active users
fn sync_short_ids(config: &mut config::SingBoxConfig) {
    if let Some(inbound) = config.inbounds.first_mut() {
        let mut active_sids = Vec::new();

        // Extract SIDs from all users
        for user in &inbound.users {
            let parts: Vec<&str> = user.name.split(':').collect();
            // Format is email:sid:level. We need the SID (second to last)
            if parts.len() >= 3
                && let Some(sid) = parts.get(parts.len() - 2)
                && !sid.is_empty()
            {
                active_sids.push(sid.to_string());
            }
        }

        // Sort and dedup
        active_sids.sort();
        active_sids.dedup();

        // Update config
        if let Some(tls) = inbound.tls.as_mut()
            && let Some(reality) = tls.reality.as_mut()
        {
            reality.short_id = active_sids;
        }
    }
}

/// Find matching user indices for a given target (uuid, anchored email, glob, or substring)
pub(crate) fn find_matching_indices(users: &[config::User], target: &str) -> Result<Vec<usize>> {
    // If target looks like a UUID, try exact uuid match first
    if uuid::Uuid::parse_str(target).is_ok() {
        let exact: Vec<usize> = users
            .iter()
            .enumerate()
            .filter(|(_i, u)| u.uuid == target)
            .map(|(i, _)| i)
            .collect();

        if !exact.is_empty() {
            return Ok(exact);
        }

        // Substring fallback (uuid, full name or local email part)
        let local = target.split('@').next().unwrap_or(target).to_string();
        let substr: Vec<usize> = users
            .iter()
            .enumerate()
            .filter(|(_i, u)| {
                u.uuid.contains(target) || u.name.contains(target) || u.name.contains(&local)
            })
            .map(|(i, _)| i)
            .collect();

        return Ok(substr);
    }

    // Build regex for anchored email prefix match if target contains glob chars or not
    let pattern = if target.contains('*') || target.contains('?') {
        regex::escape(target)
            .replace("\\*", ".*")
            .replace("\\?", ".")
    } else {
        regex::escape(target)
    };

    let regex_str = format!("^{}:", pattern);
    let re = Regex::new(&regex_str)?;
    let anchored: Vec<usize> = users
        .iter()
        .enumerate()
        .filter(|(_i, u)| re.is_match(&u.name))
        .map(|(i, _)| i)
        .collect();

    if !anchored.is_empty() {
        return Ok(anchored);
    }

    // Fallback to substring (name/uuid/local-part)
    let local = target.split('@').next().unwrap_or(target).to_string();
    let substr: Vec<usize> = users
        .iter()
        .enumerate()
        .filter(|(_i, u)| {
            u.name.contains(target) || u.name.contains(&local) || u.uuid.contains(target)
        })
        .map(|(i, _)| i)
        .collect();

    Ok(substr)
}

pub fn add(paths: &Paths, emails: Vec<String>, level: u32) -> Result<()> {
    // Check for private key first
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // Quick check if private key is present in loaded config
    let has_key = config
        .inbounds
        .first()
        .and_then(|i| i.tls.as_ref())
        .and_then(|t| t.reality.as_ref())
        .map(|r| !r.private_key.is_empty())
        .unwrap_or(false);

    if !has_key {
        eprintln!(
            "{}",
            "[WARN] No private key found; generating one now.".yellow()
        );
        // Generate keys in place into `config` object
        let (priv_key, pub_key) = generate_keypair()?;
        if let Some(inbound) = config.inbounds.first_mut() {
            if inbound.tls.is_none() {
                return Err(anyhow!("Config structure invalid: missing tls"));
            }
            if let Some(tls) = inbound.tls.as_mut() {
                if tls.reality.is_none() {
                    return Err(anyhow!("Config structure invalid: missing reality"));
                }
                if let Some(reality) = tls.reality.as_mut() {
                    reality.private_key = priv_key;
                }
            }
        }
        // Save pubkey immediately to staging path if we are generating it
        fs::write(&paths.staging_pubkey, &pub_key)?;
    }

    for email in emails {
        let uuid = generate_uuid();
        let sid = generate_sid();
        let name = format!("{}:{}:{}", email, sid, level);

        let user = config::User {
            name: name.clone(),
            uuid: uuid.clone(),
            flow: FLOW_TYPE.to_string(),
        };

        if let Some(inbound) = config.inbounds.first_mut() {
            inbound.users.push(user);
        }

        eprintln!(
            "{} Prepared user: {} (uuid: {})",
            "[INFO]".green(),
            name,
            uuid
        );
        println!("uuid: {}\nsid: {}", uuid, sid);
    }

    // Sync SIDs
    sync_short_ids(&mut config);

    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Users staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

pub fn del(paths: &Paths, targets: Vec<String>, dry_run: bool, apply: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first_mut() {
        // Collect matches per target and unique indices to delete
        let mut to_delete: HashSet<usize> = HashSet::new();
        let mut per_target_matches: Vec<(String, Vec<usize>)> = Vec::new();

        for target in targets {
            let indices = find_matching_indices(&inbound.users, &target)?;
            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }
            per_target_matches.push((target.clone(), indices.clone()));
            for idx in indices {
                to_delete.insert(idx);
            }
        }

        if to_delete.is_empty() {
            return Err(anyhow!("No users matched the provided target(s)."));
        }

        // Dry-run: just show which users would be deleted
        if dry_run {
            eprintln!(
                "{} Dry-run: the following users would be deleted:",
                "[INFO]".green()
            );
            let mut printed: HashSet<usize> = HashSet::new();
            for (target, indices) in &per_target_matches {
                let mut printed_here = 0usize;
                for idx in indices {
                    if printed.insert(*idx) {
                        let u = &inbound.users[*idx];
                        println!("{}\t{}", u.name, u.uuid);
                        printed_here += 1;
                    }
                }
                if printed_here > 0 {
                    eprintln!(
                        "{} Would delete {} user(s) for target: {}",
                        "[INFO]".green(),
                        printed_here,
                        target
                    );
                } else {
                    eprintln!(
                        "{} No users matched for target: {}",
                        "[WARN]".yellow(),
                        target
                    );
                }
            }
            eprintln!(
                "{} Total unique users matched: {}",
                "[INFO]".green(),
                to_delete.len()
            );
            return Ok(());
        }

        // Report per-target deletions (deduped)
        let mut seen: HashSet<usize> = HashSet::new();
        for (target, indices) in &per_target_matches {
            let new_count = indices.iter().filter(|i| !seen.contains(i)).count();
            for idx in indices {
                seen.insert(*idx);
            }
            if new_count > 0 {
                eprintln!(
                    "{} Deleted {} user(s) for target: {}",
                    "[INFO]".green(),
                    new_count,
                    target
                );
            } else {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
            }
        }

        // Perform deletion
        let before = inbound.users.len();
        let mut kept: Vec<config::User> = Vec::with_capacity(inbound.users.len());
        for (i, u) in inbound.users.iter().enumerate() {
            if !to_delete.contains(&i) {
                kept.push(u.clone());
            }
        }
        inbound.users = kept;
        let deleted_total = before - inbound.users.len();

        if deleted_total == 0 {
            return Err(anyhow!("No users matched the provided target(s)."));
        }

        // Persist changes
        sync_short_ids(&mut config);
        save_config(&paths.staging, &config)?;

        eprintln!(
            "{} Deletion(s) staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );

        // Optionally apply immediately
        if apply {
            eprintln!("{} Applying staged changes...", "[INFO]".green());
            crate::commands::system::apply(paths)?;
        }

        Ok(())
    } else {
        Err(anyhow!("No inbound configuration present."))
    }
}

/// Reset uuid and sid for matched user(s) - supports batch/patterns
pub fn reset(paths: &Paths, targets: Vec<String>, dry_run: bool, apply: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // Plan resets first (to support dry-run and conflict-free application)
    // planned: (idx, old_name, old_uuid, new_name, new_sid)
    let mut planned: Vec<(usize, String, String, String, String)> = Vec::new();

    if let Some(inbound) = config.inbounds.first_mut() {
        let mut seen: HashSet<usize> = HashSet::new();

        for target in &targets {
            let indices = find_matching_indices(&inbound.users, target)?;

            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }

            for idx in indices {
                if seen.contains(&idx) {
                    // already planned via a previous target
                    continue;
                }

                let user = &inbound.users[idx];
                let old_name = user.name.clone();
                let old_uuid = user.uuid.clone();
                let parts: Vec<&str> = old_name.split(':').collect();
                if parts.len() < 3 {
                    eprintln!(
                        "{} Skipping malformed user name: {}",
                        "[WARN]".yellow(),
                        old_name
                    );
                    continue;
                }

                let email = parts[..parts.len() - 2].join(":");
                let level = parts.last().unwrap_or(&"0");

                let new_sid = generate_sid();
                let new_name = format!("{}:{}:{}", email, new_sid, level);

                planned.push((idx, old_name, old_uuid, new_name, new_sid));
                seen.insert(idx);
            }
        }
    }

    if planned.is_empty() {
        return Err(anyhow!("No users matched the provided target(s)."));
    }

    // Dry-run: show planned changes and do not write staging
    if dry_run {
        eprintln!(
            "{} Dry-run: {} reset(s) planned.",
            "[INFO]".green(),
            planned.len()
        );
        for (_idx, old_name, old_uuid, new_name, new_sid) in &planned {
            eprintln!(
                "{} Would reset: {} -> {} (uuid: {} -> <new>, sid: {})",
                "[INFO]".green(),
                old_name,
                new_name,
                old_uuid,
                new_sid
            );
        }
        return Ok(());
    }

    // Apply resets
    if let Some(inbound) = config.inbounds.first_mut() {
        for (idx, old_name, old_uuid, new_name, new_sid) in planned {
            let user = &mut inbound.users[idx];
            let new_uuid = generate_uuid();

            user.name = new_name.clone();
            user.uuid = new_uuid.clone();

            eprintln!(
                "{} Reset user: {} -> {} (uuid: {} -> {})",
                "[INFO]".green(),
                old_name,
                new_name,
                old_uuid,
                new_uuid
            );

            println!("uuid: {}\nsid: {}", new_uuid, new_sid);
        }
    }

    // Persist changes to staging
    sync_short_ids(&mut config);
    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Reset(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    if apply {
        eprintln!("{}", "[INFO] Applying staged changes...".green());
        crate::commands::system::apply(paths)?;
    }

    Ok(())
}

pub fn list(paths: &Paths, filter: Option<String>, json: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if json {
        // Collect matching users and output as JSON array
        let mut out: Vec<config::User> = Vec::new();
        if let Some(inbound) = config.inbounds.first() {
            for user in &inbound.users {
                if let Some(f) = &filter
                    && !user.name.contains(f)
                {
                    continue;
                }
                out.push(user.clone());
            }
        }
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }

    if let Some(inbound) = config.inbounds.first() {
        for user in &inbound.users {
            if let Some(f) = &filter
                && !user.name.contains(f)
            {
                continue;
            }
            println!("{}\t{}\t{}", user.name, user.uuid, user.flow);
        }
    }
    Ok(())
}

/// Show info for one or multiple targets (patterns supported)
/// When `json` is true, outputs a JSON array (compact) of matched users for scripts.
pub fn info(paths: &Paths, targets: Vec<String>, json: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    let mut any_matched = false;
    if let Some(inbound) = config.inbounds.first() {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut result: Vec<config::User> = Vec::new();

        for target in targets {
            let indices = find_matching_indices(&inbound.users, &target)?;

            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }

            for idx in indices {
                if seen.insert(idx) {
                    if json {
                        result.push(inbound.users[idx].clone());
                    } else {
                        println!("{}", serde_json::to_string_pretty(&inbound.users[idx])?);
                    }
                    any_matched = true;
                }
            }
        }

        if json && any_matched {
            println!("{}", serde_json::to_string(&result)?);
            return Ok(());
        }

        if any_matched {
            return Ok(());
        }
    }

    Err(anyhow!("No users matched the provided target(s)."))
}

/// Update user properties in batch (supports --level, --email, --email-replace, --regex, --replace-first, --dry-run, --apply)
///
/// - `--level N` will set the level for all matched users.
/// - `--email foo@example.com` will set the email for a single matched user (only allowed when exactly one user matches).
/// - `--email-replace FROM TO` will replace substrings in the email part for all matched users; use `--regex` to treat FROM as a regex.
/// - `--replace-first` will perform only the first match replacement (default replaces all matches).
/// - `--dry-run` will show planned changes without writing staging.
/// - `--apply` will apply staged changes immediately after saving.
pub fn update(
    paths: &Paths,
    targets: Vec<String>,
    level: Option<u32>,
    email: Option<String>,
    email_replace: Option<Vec<String>>,
    regex: bool,
    replace_first: bool,
    dry_run: bool,
    apply: bool,
) -> Result<()> {
    // Basic validations
    if level.is_none() && email.is_none() && email_replace.is_none() {
        return Err(anyhow!(
            "No update action specified. Use --level and/or --email/--email-replace."
        ));
    }
    if email.is_some() && email_replace.is_some() {
        return Err(anyhow!(
            "--email and --email-replace are mutually exclusive."
        ));
    }
    if regex && email_replace.is_none() {
        return Err(anyhow!("--regex requires --email-replace to be provided."));
    }
    if let Some(ref repl) = email_replace
        && repl.len() != 2
    {
        return Err(anyhow!(
            "--email-replace requires two arguments: FROM and TO."
        ));
    }

    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // planned updates: (index, old_name, new_name)
    let mut planned: Vec<(usize, String, String)> = Vec::new();

    if let Some(inbound) = config.inbounds.first_mut() {
        for target in &targets {
            let indices = find_matching_indices(&inbound.users, target)?;

            if indices.is_empty() {
                eprintln!(
                    "{} No users matched for target: {}",
                    "[WARN]".yellow(),
                    target
                );
                continue;
            }

            // If --email is used it must be unambiguous per-target
            if email.is_some() && indices.len() > 1 {
                return Err(anyhow!(
                    "Email rename ambiguous for target '{}': {} users matched. Rename is only allowed when exactly one user is matched.",
                    target,
                    indices.len()
                ));
            }

            for idx in indices {
                // avoid double-planning for the same user across multiple targets
                if planned.iter().any(|(i, _old, _)| *i == idx) {
                    continue;
                }

                let user = &inbound.users[idx];
                let old_name = user.name.clone();
                let parts: Vec<&str> = old_name.split(':').collect();
                if parts.len() < 3 {
                    return Err(anyhow!(
                        "Invalid user name format encountered: {}",
                        old_name
                    ));
                }

                let cur_email = parts[..parts.len() - 2].join(":");
                let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();
                let cur_level = parts.last().unwrap_or(&"0").to_string();
                let new_level = level.map(|l| l.to_string()).unwrap_or(cur_level);

                // Compute new email (support replace-first and regex backrefs)
                let new_email = if let Some(e) = &email {
                    e.clone()
                } else if let Some(repl) = &email_replace {
                    let from = &repl[0];
                    let to = &repl[1];
                    if regex {
                        let re = Regex::new(from)?;
                        if replace_first {
                            // replace first regex match
                            re.replace(&cur_email, to.as_str()).to_string()
                        } else {
                            // replace all
                            re.replace_all(&cur_email, to.as_str()).to_string()
                        }
                    } else {
                        if replace_first {
                            // replace first literal occurrence
                            cur_email.replacen(from, to, 1)
                        } else {
                            // replace all literal occurrences
                            cur_email.replace(from, to)
                        }
                    }
                } else {
                    cur_email
                };

                let new_name = format!("{}:{}:{}", new_email, sid, new_level);
                planned.push((idx, old_name, new_name));
            }
        }

        if planned.is_empty() {
            return Err(anyhow!("No users matched the provided target(s)."));
        }

        // If email rename (explicit) was requested, ensure exactly one user will be modified overall
        if email.is_some() {
            let uniq: HashSet<usize> = planned.iter().map(|(i, _, _)| *i).collect();
            if uniq.len() != 1 {
                return Err(anyhow!("Email rename requires exactly one matched user."));
            }
        }

        // Validate planned changes for conflicts
        let planned_idxs: HashSet<usize> = planned.iter().map(|(i, _, _)| *i).collect();
        let existing_names: HashSet<String> = inbound
            .users
            .iter()
            .enumerate()
            .filter(|(i, _)| !planned_idxs.contains(i))
            .map(|(_, u)| u.name.clone())
            .collect();

        let mut seen_new: HashSet<String> = HashSet::new();
        for (_idx, _old, new_name) in &planned {
            if existing_names.contains(new_name) {
                return Err(anyhow!(
                    "Planned update would conflict with existing user: {}",
                    new_name
                ));
            }
            if !seen_new.insert(new_name.clone()) {
                return Err(anyhow!(
                    "Planned update would create duplicate user name: {}",
                    new_name
                ));
            }
        }

        // Dry run: print planned changes and return without writing staging
        if dry_run {
            eprintln!(
                "{} Dry-run: {} planned update(s)",
                "[INFO]".green(),
                planned.len()
            );
            for (_idx, old_name, new_name) in &planned {
                eprintln!("{} {} -> {}", "[INFO]".green(), old_name, new_name);
            }
            return Ok(());
        }

        // Apply planned changes
        let mut applied = 0usize;
        for (idx, old_name, new_name) in planned {
            if old_name == new_name {
                eprintln!("{} No change for user: {}", "[INFO]".green(), old_name);
                continue;
            }

            let user = &mut inbound.users[idx];
            user.name = new_name.clone();
            applied += 1;

            eprintln!(
                "{} Updated user: {} -> {}",
                "[INFO]".green(),
                old_name,
                new_name
            );
        }

        if applied == 0 {
            return Err(anyhow!("No changes were necessary."));
        }

        // Persist
        sync_short_ids(&mut config);
        save_config(&paths.staging, &config)?;

        eprintln!(
            "{} Update(s) staged. Run 'mimictl apply' to activate.",
            "[INFO]".green()
        );

        if apply {
            eprintln!("{} Applying staged changes...", "[INFO]".green());
            crate::commands::system::apply(paths)?;
        }

        Ok(())
    } else {
        Err(anyhow!("No inbound configuration present."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    use uuid::Uuid;
    // Use the global test PATH lock defined in `utils` (TEST_PATH_LOCK) to serialize tests
    // that modify PATH. This avoids races across test modules.

    fn make_user(name: &str, uuid: &str) -> crate::config::User {
        crate::config::User {
            name: name.to_string(),
            uuid: uuid.to_string(),
            flow: FLOW_TYPE.to_string(),
        }
    }

    #[test]
    fn test_find_matching_indices_uuid_exact() {
        let users = vec![
            make_user(
                "alice@example.com:SID1:0",
                "11111111-1111-1111-1111-111111111111",
            ),
            make_user(
                "bob@example.com:SID2:0",
                "22222222-2222-2222-2222-222222222222",
            ),
        ];
        let idxs = find_matching_indices(&users, "11111111-1111-1111-1111-111111111111").unwrap();
        assert_eq!(idxs, vec![0]);
    }

    #[test]
    fn test_find_matching_indices_uuid_substring() {
        let users = vec![
            make_user("alice@example.com:SID1:0", "abc-111"),
            make_user("bob@example.com:SID2:0", "abc-222"),
        ];
        let idxs = find_matching_indices(&users, "abc").unwrap();
        assert_eq!(idxs, vec![0, 1]);
    }

    #[test]
    fn test_find_matching_indices_anchored_email() {
        let users = vec![
            make_user("alice@example.com:SID1:0", "1"),
            make_user("bob@example.com:SID2:0", "2"),
        ];
        let idxs = find_matching_indices(&users, "alice@example.com").unwrap();
        assert_eq!(idxs, vec![0]);
    }

    #[test]
    fn test_find_matching_indices_glob() {
        let users = vec![
            make_user("alice@example.com:SID1:0", "1"),
            make_user("a.smith@example.com:SID2:0", "2"),
            make_user("bob@example.com:SID3:0", "3"),
        ];
        let idxs = find_matching_indices(&users, "a*example.com").unwrap();
        // anchored pattern '^a*example.com:' becomes '^a.*example\.com:'
        // Matches first two users (names starting with 'alice...' and 'a.smith...')
        assert_eq!(idxs, vec![0, 1]);
    }

    #[test]
    fn test_find_matching_indices_substring_local_part() {
        let users = vec![
            make_user("alice+tag@example.com:SID1:0", "1"),
            make_user("bob@example.com:SID2:0", "2"),
        ];
        let idxs = find_matching_indices(&users, "alice+tag").unwrap();
        assert_eq!(idxs, vec![0]);
    }

    // ---------------------------------------------------------------------
    // New tests: update with email replace (non-regex) and dry-run behavior
    // ---------------------------------------------------------------------
    #[test]
    fn test_update_email_replace_non_regex() {
        // setup temp paths
        let tmp = env::temp_dir();
        let dir = tmp.join(format!("mimic_node_test_update_{}", Uuid::new_v4()));
        let etc = dir.join("etc").join("sing-box");
        let usr = dir
            .join("usr")
            .join("share")
            .join("mimic-node")
            .join("default");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(&usr).unwrap();

        let paths = crate::paths::Paths {
            root: dir.clone(),
            config: etc.join("config.json"),
            staging: etc.join("config.new"),
            pubkey: etc.join("PUBKEY"),
            staging_pubkey: etc.join("PUBKEY.new"),
            sni_list: usr.join("sni.txt"),
            default_config: usr.join("default/config.json"),
        };

        // Minimal config with one user to be replaced
        let cfg = serde_json::json!({
            "inbounds": [
                {
                    "type": "vless",
                    "users": [
                        { "name": "bob@old.com:SID2:0", "uuid": "2222", "flow": "xtls" },
                        { "name": "alice@example.com:SID1:0", "uuid": "1111", "flow": "xtls" }
                    ]
                }
            ]
        });
        fs::write(&paths.config, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        // Run update with replace FROM=@old.com TO=@new.com
        update(
            &paths,
            vec!["*@old.com".to_string()],
            None,
            None,
            Some(vec!["@old.com".to_string(), "@new.com".to_string()]),
            false, // regex
            false, // replace_first
            false, // dry_run
            false, // apply
        )
        .expect("update should succeed");

        // Confirm staging contains updated name for bob
        let staged = fs::read_to_string(&paths.staging).unwrap();
        assert!(staged.contains("bob@new.com:SID2:0"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn test_update_email_replace_dry_run() {
        // setup temp paths
        let tmp = env::temp_dir();
        let dir = tmp.join(format!("mimic_node_test_update_dry_{}", Uuid::new_v4()));
        let etc = dir.join("etc").join("sing-box");
        let usr = dir
            .join("usr")
            .join("share")
            .join("mimic-node")
            .join("default");
        fs::create_dir_all(&etc).unwrap();
        fs::create_dir_all(&usr).unwrap();

        let paths = crate::paths::Paths {
            root: dir.clone(),
            config: etc.join("config.json"),
            staging: etc.join("config.new"),
            pubkey: etc.join("PUBKEY"),
            staging_pubkey: etc.join("PUBKEY.new"),
            sni_list: usr.join("sni.txt"),
            default_config: usr.join("default/config.json"),
        };

        let cfg = serde_json::json!({
            "inbounds": [
                {
                    "type": "vless",
                    "users": [
                        { "name": "bob@old.com:SID2:0", "uuid": "2222", "flow": "xtls" }
                    ]
                }
            ]
        });
        fs::write(&paths.config, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

        // Dry run: should not create staging file
        update(
            &paths,
            vec!["*@old.com".to_string()],
            None,
            None,
            Some(vec!["@old.com".to_string(), "@new.com".to_string()]),
            false, // regex
            false, // replace_first
            true,  // dry_run
            false, // apply
        )
        .expect("dry-run update should succeed");

        assert!(
            !paths.staging.exists(),
            "staging should not be created in dry-run"
        );

        fs::remove_dir_all(dir).unwrap();
    }

    // Test removed: this test invoked `apply()` which can trigger privileged systemctl calls.
    // Removed to avoid running privileged operations during package installation/tests.

    // Test removed: this test invoked `apply()` which can trigger privileged systemctl calls.
    // Removed to avoid running privileged operations during package installation/tests.
}

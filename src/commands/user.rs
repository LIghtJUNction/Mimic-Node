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
fn find_matching_indices(users: &[config::User], target: &str) -> Result<Vec<usize>> {
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

pub fn del(paths: &Paths, targets: Vec<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // Track total deletions across all targets
    let mut total_deleted: usize = 0;

    for target in targets {
        let mut deleted_here: usize = 0;

        if let Some(inbound) = config.inbounds.first_mut() {
            // 1) If target is a UUID, try exact UUID match first
            if uuid::Uuid::parse_str(&target).is_ok() {
                let before = inbound.users.len();
                inbound.users.retain(|u| u.uuid != target);
                deleted_here = before - inbound.users.len();

                // If no exact UUID match, try substring fallback (name or uuid or local part of email)
                if deleted_here == 0 {
                    let before2 = inbound.users.len();
                    let local = target.split('@').next().unwrap_or(&target).to_string();
                    inbound.users.retain(|u| {
                        !(u.uuid.contains(&target)
                            || u.name.contains(&target)
                            || u.name.contains(&local))
                    });
                    deleted_here = before2 - inbound.users.len();
                }
            } else {
                // 2) Handle wildcard or anchored email/specific name match
                let pattern = if target.contains('*') || target.contains('?') {
                    regex::escape(&target)
                        .replace("\\*", ".*")
                        .replace("\\?", ".")
                } else {
                    regex::escape(&target)
                };

                // Try anchored-match (email:sid:level prefix)
                let regex_str = format!("^{}:", pattern);
                let re = Regex::new(&regex_str)?;
                let before = inbound.users.len();
                inbound.users.retain(|u| !re.is_match(&u.name));
                deleted_here = before - inbound.users.len();

                // 3) If nothing matched, do a substring fallback on name/uuid/local part
                if deleted_here == 0 {
                    let before2 = inbound.users.len();
                    let local = target.split('@').next().unwrap_or(&target).to_string();
                    inbound.users.retain(|u| {
                        !(u.name.contains(&target)
                            || u.name.contains(&local)
                            || u.uuid.contains(&target))
                    });
                    deleted_here = before2 - inbound.users.len();
                }
            }
        }

        if deleted_here > 0 {
            total_deleted += deleted_here;
            eprintln!(
                "{} Deleted {} user(s) for target: {}",
                "[INFO]".green(),
                deleted_here,
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

    if total_deleted == 0 {
        return Err(anyhow!("No users matched the provided target(s)."));
    }

    // Only sync and persist when we actually deleted something
    sync_short_ids(&mut config);
    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Deletion(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

/// Reset uuid and sid for matched user(s) - supports batch/patterns
pub fn reset(paths: &Paths, targets: Vec<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    let mut total_reset = 0usize;

    if let Some(inbound) = config.inbounds.first_mut() {
        // Avoid resetting the same user twice in one run
        let mut changed_indices: HashSet<usize> = HashSet::new();

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
                if changed_indices.contains(&idx) {
                    continue;
                }

                let user = &mut inbound.users[idx];
                let parts: Vec<&str> = user.name.split(':').collect();
                if parts.len() < 3 {
                    eprintln!(
                        "{} Skipping malformed user name: {}",
                        "[WARN]".yellow(),
                        user.name
                    );
                    continue;
                }

                let email = parts[..parts.len() - 2].join(":");
                let level = parts.last().unwrap_or(&"0");
                let old_sid = parts.get(parts.len() - 2).unwrap_or(&"");

                let new_sid = generate_sid();
                let new_uuid = generate_uuid();
                let new_name = format!("{}:{}:{}", email, new_sid, level);

                eprintln!(
                    "{} Resetting user {} (Level: {})",
                    "[INFO]".green(),
                    email,
                    level
                );
                eprintln!(
                    "{} Old SID: {} -> New SID: {}",
                    "[INFO]".green(),
                    old_sid,
                    new_sid
                );

                user.name = new_name;
                user.uuid = new_uuid.clone();

                println!("uuid: {}\nsid: {}", new_uuid, new_sid);

                changed_indices.insert(idx);
                total_reset += 1;
            }
        }
    }

    if total_reset == 0 {
        return Err(anyhow!("No users matched the provided target(s)."));
    }

    // Persist
    sync_short_ids(&mut config);
    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Reset(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

pub fn list(paths: &Paths, filter: Option<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

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
pub fn info(paths: &Paths, targets: Vec<String>) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let config = load_config(input_path)?;

    if let Some(inbound) = config.inbounds.first() {
        let mut matched_any = false;
        let mut seen: HashSet<usize> = HashSet::new();

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
                    println!("{}", serde_json::to_string_pretty(&inbound.users[idx])?);
                    matched_any = true;
                }
            }
        }

        if matched_any {
            return Ok(());
        }
    }

    Err(anyhow!("User not found for provided target(s)."))
}

/// Update user properties in batch (currently supports updating level and single-user email rename)
/// - `--level N` will set level for all matched users
/// - `--email new@example.com` must match exactly one user (to avoid accidental duplicates)
pub fn update(
    paths: &Paths,
    targets: Vec<String>,
    level: Option<u32>,
    email: Option<String>,
) -> Result<()> {
    if level.is_none() && email.is_none() {
        return Err(anyhow!(
            "No update action specified. Use --level and/or --email."
        ));
    }

    let input_path = paths.get_input_config_path();
    let mut config = load_config(input_path)?;

    // Planned updates: (index, new_name)
    let mut planned: Vec<(usize, String)> = Vec::new();

    if let Some(inbound) = config.inbounds.first_mut() {
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

            if email.is_some() && indices.len() > 1 {
                return Err(anyhow!(
                    "Email rename ambiguous for target '{}': {} users matched. Rename is only allowed when exactly one user is matched.",
                    target,
                    indices.len()
                ));
            }

            for idx in indices {
                if planned.iter().any(|(i, _)| *i == idx) {
                    continue;
                }

                let user = &inbound.users[idx];
                let parts: Vec<&str> = user.name.split(':').collect();
                if parts.len() < 3 {
                    return Err(anyhow!(
                        "Invalid user name format encountered: {}",
                        user.name
                    ));
                }

                let cur_email = parts[..parts.len() - 2].join(":");
                let sid = parts.get(parts.len() - 2).unwrap_or(&"").to_string();
                let cur_level = parts.last().unwrap_or(&"0").to_string();

                let new_level = level.map(|l| l.to_string()).unwrap_or(cur_level);
                let new_email = email.clone().unwrap_or(cur_email);

                let new_name = format!("{}:{}:{}", new_email, sid, new_level);
                planned.push((idx, new_name));
            }
        }

        if planned.is_empty() {
            return Err(anyhow!("No users matched or nothing to do."));
        }

        // Validate planned changes for conflicts
        let planned_idxs: HashSet<usize> = planned.iter().map(|(i, _)| *i).collect();
        let existing_names: HashSet<String> = inbound
            .users
            .iter()
            .enumerate()
            .filter(|(i, _)| !planned_idxs.contains(i))
            .map(|(_, u)| u.name.clone())
            .collect();

        let mut seen_new: HashSet<String> = HashSet::new();
        for (_idx, new_name) in &planned {
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

        // Apply planned changes
        for (idx, new_name) in planned {
            let user = inbound
                .users
                .get_mut(idx)
                .ok_or_else(|| anyhow!("Index out of bounds"))?;
            let old_name = user.name.clone();
            user.name = new_name.clone();
            eprintln!(
                "{} Updated user: {} -> {}",
                "[INFO]".green(),
                old_name,
                new_name
            );
        }
    }

    // Persist changes
    sync_short_ids(&mut config);
    save_config(&paths.staging, &config)?;

    eprintln!(
        "{} Update(s) staged. Run 'mimictl apply' to activate.",
        "[INFO]".green()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

use anyhow::Result;
use colored::*;
use serde_json::Value;
use std::fs;

use crate::paths::Paths;

pub fn upgrade(paths: &Paths, auto: bool, dry_run: bool) -> Result<()> {
    let input_path = paths.get_input_config_path();
    let current_str = fs::read_to_string(input_path)?;
    let current_config: Value = serde_json::from_str(&current_str)?;

    let default_str = fs::read_to_string(&paths.default_config)?;
    let default_config: Value = serde_json::from_str(&default_str)?;

    if auto || dry_run {
        eprintln!("{} Auto-upgrading config with new defaults...", "[INFO]".green());
        eprintln!("{} Keeping all current user data and keys...", "[INFO]".cyan());

        // Merge: keep current values, add new defaults
        let merged = deep_merge(&current_config, &default_config);

        if dry_run {
            eprintln!("{} [DRY RUN] Changes not written", "[WARN]".yellow());
            println!("{}", serde_json::to_string_pretty(&merged)?);
        } else {
            fs::write(&paths.staging, serde_json::to_string_pretty(&merged)?)?;
            eprintln!("{} Config upgraded and staged. Run 'mimictl apply' to activate.", "[INFO]".green());
        }
    } else {
        // Show what would change
        eprintln!("{} Config upgrade info:", "[INFO]".green());
        show_diff_info(&current_config, &default_config);

        eprintln!("\n{} Use --auto to auto-merge or --dry-run to preview.", "[INFO]".cyan());
    }

    Ok(())
}

fn show_diff_info(current: &Value, default: &Value) {
    // Check DNS servers
    if let (Some(curr_dns), Some(def_dns)) = (
        current.get("dns").and_then(|d| d.get("servers")),
        default.get("dns").and_then(|d| d.get("servers")),
    ) {
        let empty_vec = &Vec::<Value>::new();
        let curr_tags: std::collections::HashSet<_> = curr_dns
            .as_array()
            .unwrap_or(empty_vec)
            .iter()
            .filter_map(|s| s.get("tag").and_then(|t| t.as_str()))
            .collect();

        let def_tags: std::collections::HashSet<_> = def_dns
            .as_array()
            .unwrap_or(empty_vec)
            .iter()
            .filter_map(|s| s.get("tag").and_then(|t| t.as_str()))
            .collect();

        let new_tags: Vec<_> = def_tags.difference(&curr_tags).collect();
        if !new_tags.is_empty() {
            eprintln!("  {} New DNS servers: {:?}", "[+]".green(), new_tags);
        }
    }

    // Check inbounds
    if let (Some(curr_in), Some(def_in)) = (
        current.get("inbounds"),
        default.get("inbounds"),
    ) {
        let empty_vec = &Vec::<Value>::new();
        let curr_tags: std::collections::HashSet<_> = curr_in
            .as_array()
            .unwrap_or(empty_vec)
            .iter()
            .filter_map(|i| i.get("tag").and_then(|t| t.as_str()))
            .collect();

        let def_tags: std::collections::HashSet<_> = def_in
            .as_array()
            .unwrap_or(empty_vec)
            .iter()
            .filter_map(|i| i.get("tag").and_then(|t| t.as_str()))
            .collect();

        let new_tags: Vec<_> = def_tags.difference(&curr_tags).collect();
        if !new_tags.is_empty() {
            eprintln!("  {} New inbounds: {:?}", "[+]".green(), new_tags);
        }
    }

    // Check services
    if let (Some(curr_svc), Some(def_svc)) = (
        current.get("services"),
        default.get("services"),
    ) {
        let empty_vec = &Vec::<Value>::new();
        let curr_tags: std::collections::HashSet<_> = curr_svc
            .as_array()
            .unwrap_or(empty_vec)
            .iter()
            .filter_map(|s| s.get("tag").and_then(|t| t.as_str()))
            .collect();

        let def_tags: std::collections::HashSet<_> = def_svc
            .as_array()
            .unwrap_or(empty_vec)
            .iter()
            .filter_map(|s| s.get("tag").and_then(|t| t.as_str()))
            .collect();

        let new_tags: Vec<_> = def_tags.difference(&curr_tags).collect();
        if !new_tags.is_empty() {
            eprintln!("  {} New services: {:?}", "[+]".green(), new_tags);
        }
    }
}

fn deep_merge(base: &Value, override_: &Value) -> Value {
    match (base, override_) {
        (Value::Object(base_map), Value::Object(override_map)) => {
            let mut result = base_map.clone();
            for (key, override_val) in override_map {
                result.insert(
                    key.clone(),
                    if let Some(base_val) = base_map.get(key) {
                        deep_merge(base_val, override_val)
                    } else {
                        // Don't add new fields from override - they may be incompatible
                        // Only empty arrays/objects are safe to add
                        match override_val {
                            Value::Array(arr) if arr.is_empty() => override_val.clone(),
                            Value::Object(obj) if obj.is_empty() => override_val.clone(),
                            _ => override_val.clone(),
                        }
                    },
                );
            }
            Value::Object(result)
        }
        (Value::Array(base_arr), Value::Array(override_arr)) => {
            // Only merge existing array items by index - don't append new items
            // This prevents adding new inbounds/features that may be incompatible
            let mut result = base_arr.clone();
            for (i, override_item) in override_arr.iter().enumerate() {
                if i < result.len() {
                    result[i] = deep_merge(&result[i], override_item);
                }
                // Don't append new items - skip them
            }
            Value::Array(result)
        }
        _ => override_.clone(),
    }
}

use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::audit::days_to_date;
use crate::config::Config;

// ============================================================================
// Script Cache (whitelist + hash trust)
// ============================================================================

/// A single cached script entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CacheEntry {
    pub(crate) sha256: String,
    pub(crate) verdict: String,
    pub(crate) source_url: String,
    pub(crate) timestamp: String,
    pub(crate) runtime_passed: bool,
    pub(crate) blacklisted: bool,
}

/// Local hash-based script cache stored at ~/.scurl/cache.json.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ScriptCache {
    #[serde(default)]
    pub(crate) entries: std::collections::HashMap<String, CacheEntry>,
}

impl ScriptCache {
    fn cache_path() -> Result<PathBuf> {
        let dir = Config::config_dir()?;
        Ok(dir.join("cache.json"))
    }

    pub(crate) fn load() -> Result<Self> {
        let path = Self::cache_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(&path).context("Failed to read cache file")?;
        if data.trim().is_empty() {
            return Ok(Self::default());
        }
        match serde_json::from_str::<ScriptCache>(&data) {
            Ok(cache) => Ok(cache),
            Err(e) => {
                eprintln!(
                    "{} Cache file is corrupted ({}), starting fresh. Old file backed up.",
                    "⚠".yellow(),
                    e
                );
                // Back up the corrupted file
                let backup = path.with_extension("json.bak");
                let _ = fs::rename(&path, &backup);
                Ok(Self::default())
            }
        }
    }

    pub(crate) fn save(&self) -> Result<()> {
        let path = Self::cache_path()?;
        let dir = path.parent().unwrap();
        fs::create_dir_all(dir)?;

        let data = serde_json::to_string_pretty(self)?;

        // Atomic write: write to temp file then rename
        let tmp_path = path.with_extension("tmp");
        fs::write(&tmp_path, data.as_bytes())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }

        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn get(&self, sha256: &str) -> Option<&CacheEntry> {
        self.entries.get(sha256)
    }

    pub(crate) fn insert(&mut self, entry: CacheEntry) {
        self.entries.insert(entry.sha256.clone(), entry);
    }

    pub(crate) fn blacklist(&mut self, sha256: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(sha256) {
            entry.blacklisted = true;
            true
        } else {
            // Insert a minimal blacklisted entry
            self.entries.insert(
                sha256.to_string(),
                CacheEntry {
                    sha256: sha256.to_string(),
                    verdict: "BLACKLISTED".to_string(),
                    source_url: String::new(),
                    timestamp: current_timestamp(),
                    runtime_passed: false,
                    blacklisted: true,
                },
            );
            true
        }
    }

    pub(crate) fn is_blacklisted(&self, sha256: &str) -> bool {
        self.entries
            .get(sha256)
            .map(|e| e.blacklisted)
            .unwrap_or(false)
    }

    pub(crate) fn is_trusted(&self, sha256: &str, url: &str, whitelist: &[String]) -> bool {
        if let Some(entry) = self.entries.get(sha256) {
            if entry.blacklisted {
                return false;
            }
            let safe_verdict = matches!(
                entry.verdict.to_uppercase().as_str(),
                "SAFE" | "LOW"
            );
            if safe_verdict && entry.runtime_passed && url_matches_whitelist(url, whitelist) {
                return true;
            }
        }
        false
    }
}

/// Format current time as ISO-8601 (approximate, no chrono dependency).
pub(crate) fn current_timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let days = secs / 86400;
    let (y, m, d) = days_to_date(days);
    let hms_secs = secs % 86400;
    let h = hms_secs / 3600;
    let min = (hms_secs % 3600) / 60;
    let s = hms_secs % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, min, s)
}

/// Check whether a URL matches any prefix in the whitelist.
pub(crate) fn url_matches_whitelist(url: &str, whitelist: &[String]) -> bool {
    if whitelist.is_empty() {
        return false;
    }
    whitelist.iter().any(|prefix| url.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_matches_whitelist_basic() {
        let whitelist = vec![
            "https://raw.githubusercontent.com/".to_string(),
            "https://get.docker.com".to_string(),
        ];
        assert!(url_matches_whitelist(
            "https://raw.githubusercontent.com/user/repo/main/install.sh",
            &whitelist
        ));
        assert!(url_matches_whitelist(
            "https://get.docker.com/install.sh",
            &whitelist
        ));
        assert!(!url_matches_whitelist(
            "https://evil.com/install.sh",
            &whitelist
        ));
    }

    #[test]
    fn test_url_matches_whitelist_empty() {
        let whitelist: Vec<String> = Vec::new();
        assert!(!url_matches_whitelist(
            "https://raw.githubusercontent.com/user/repo/main/install.sh",
            &whitelist
        ));
    }

    #[test]
    fn test_script_cache_insert_and_get() {
        let mut cache = ScriptCache::default();
        let entry = CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "SAFE".to_string(),
            source_url: "https://example.com/install.sh".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        };
        cache.insert(entry);

        let got = cache.get("abc123").unwrap();
        assert_eq!(got.verdict, "SAFE");
        assert!(!got.blacklisted);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_script_cache_blacklist_existing() {
        let mut cache = ScriptCache::default();
        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "SAFE".to_string(),
            source_url: "https://example.com".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        });

        assert!(!cache.is_blacklisted("abc123"));
        cache.blacklist("abc123");
        assert!(cache.is_blacklisted("abc123"));
    }

    #[test]
    fn test_script_cache_blacklist_new_hash() {
        let mut cache = ScriptCache::default();
        assert!(!cache.is_blacklisted("def456"));
        cache.blacklist("def456");
        assert!(cache.is_blacklisted("def456"));
        let entry = cache.get("def456").unwrap();
        assert_eq!(entry.verdict, "BLACKLISTED");
    }

    #[test]
    fn test_script_cache_is_trusted() {
        let mut cache = ScriptCache::default();
        let whitelist = vec!["https://trusted.com/".to_string()];

        // Not trusted: not in cache
        assert!(!cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));

        // Insert safe entry
        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "SAFE".to_string(),
            source_url: "https://trusted.com/install.sh".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        });

        // Trusted: safe verdict, runtime passed, URL whitelisted
        assert!(cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));

        // Not trusted: URL not whitelisted
        assert!(!cache.is_trusted("abc123", "https://untrusted.com/install.sh", &whitelist));

        // Not trusted: empty whitelist
        assert!(!cache.is_trusted("abc123", "https://trusted.com/install.sh", &[]));
    }

    #[test]
    fn test_script_cache_blacklisted_not_trusted() {
        let mut cache = ScriptCache::default();
        let whitelist = vec!["https://trusted.com/".to_string()];

        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "SAFE".to_string(),
            source_url: "https://trusted.com/install.sh".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        });

        // Trusted initially
        assert!(cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));

        // Blacklist it
        cache.blacklist("abc123");

        // No longer trusted
        assert!(!cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));
    }

    #[test]
    fn test_script_cache_medium_verdict_not_trusted() {
        let mut cache = ScriptCache::default();
        let whitelist = vec!["https://trusted.com/".to_string()];

        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "MEDIUM".to_string(),
            source_url: "https://trusted.com/install.sh".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        });

        // MEDIUM verdict does not qualify as trusted
        assert!(!cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));
    }

    #[test]
    fn test_script_cache_runtime_not_passed() {
        let mut cache = ScriptCache::default();
        let whitelist = vec!["https://trusted.com/".to_string()];

        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "SAFE".to_string(),
            source_url: "https://trusted.com/install.sh".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: false,
            blacklisted: false,
        });

        // Not trusted because runtime didn't pass
        assert!(!cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));
    }

    #[test]
    fn test_script_cache_low_verdict_trusted() {
        let mut cache = ScriptCache::default();
        let whitelist = vec!["https://trusted.com/".to_string()];

        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "LOW".to_string(),
            source_url: "https://trusted.com/install.sh".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        });

        // LOW verdict qualifies as trusted
        assert!(cache.is_trusted("abc123", "https://trusted.com/install.sh", &whitelist));
    }

    #[test]
    fn test_script_cache_serialize_roundtrip() {
        let mut cache = ScriptCache::default();
        cache.insert(CacheEntry {
            sha256: "abc123".to_string(),
            verdict: "SAFE".to_string(),
            source_url: "https://example.com".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            runtime_passed: true,
            blacklisted: false,
        });
        cache.blacklist("def456");

        let json = serde_json::to_string(&cache).unwrap();
        let loaded: ScriptCache = serde_json::from_str(&json).unwrap();

        assert!(loaded.get("abc123").is_some());
        assert!(!loaded.is_blacklisted("abc123"));
        assert!(loaded.is_blacklisted("def456"));
    }

    #[test]
    fn test_current_timestamp_format() {
        let ts = current_timestamp();
        // Should be ISO-8601 like: 2026-01-30T12:34:56Z
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
        assert_eq!(&ts[4..5], "-");
        assert_eq!(&ts[7..8], "-");
        assert_eq!(&ts[10..11], "T");
        assert_eq!(&ts[13..14], ":");
        assert_eq!(&ts[16..17], ":");
    }

    // --- ScriptCache hardening ---

    #[test]
    fn test_script_cache_load_empty_file() {
        // Simulate loading from empty string via serde
        let cache: ScriptCache = serde_json::from_str("{}").unwrap();
        assert!(cache.entries.is_empty());
    }

    #[test]
    fn test_script_cache_load_entries_with_defaults() {
        // Simulate a cache entry missing optional fields
        let json = r#"{"entries":{"abc":{"sha256":"abc","verdict":"SAFE","source_url":"https://example.com","timestamp":"2026-01-01T00:00:00Z","runtime_passed":true,"blacklisted":false}}}"#;
        let cache: ScriptCache = serde_json::from_str(json).unwrap();
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn test_script_cache_blacklist_idempotent() {
        let mut cache = ScriptCache::default();
        cache.blacklist("abc123");
        assert!(cache.is_blacklisted("abc123"));
        cache.blacklist("abc123"); // second call
        assert!(cache.is_blacklisted("abc123"));
        assert_eq!(cache.entries.len(), 1); // still just one entry
    }
}

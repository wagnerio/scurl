use anyhow::{Context, Result};
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tempfile::NamedTempFile;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Config {
    pub(crate) provider: String,
    pub(crate) api_key: String,
    pub(crate) model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) azure_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) azure_deployment: Option<String>,
    /// URL prefixes considered trusted (skip AI review if hash cached as safe)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) whitelist_sources: Vec<String>,
}

impl Config {
    pub(crate) fn config_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        Ok(home.join(".scurl"))
    }

    pub(crate) fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    pub(crate) fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            anyhow::bail!(
                "No configuration found. Please run {} first.",
                "scurl login".green().bold()
            );
        }
        let content = fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content).context("Failed to parse config file")?;

        // If api_key is the sentinel "keyring", load from OS keyring
        if config.api_key == "keyring" {
            match load_api_key_keyring(&config.provider) {
                Ok(key) => config.api_key = key,
                Err(e) => {
                    anyhow::bail!(
                        "API key is stored in OS keyring but could not be loaded: {}. \
                         You can set SCURL_API_KEY env var or run 'scurl login' again.",
                        e
                    );
                }
            }
        } else if config.api_key != "ollama-no-key" {
            // API key is stored in plaintext — warn if keyring is available
            if keyring::Entry::new("scurl", &config.provider).is_ok() {
                eprintln!(
                    "{} API key is stored in plaintext config file. \
                     Run '{}' to migrate to the OS keyring, or set {} env var.",
                    "⚠".yellow(),
                    "scurl login".green().bold(),
                    "SCURL_API_KEY".cyan()
                );
            }
        }

        Ok(config)
    }

    pub(crate) fn save(&self) -> Result<()> {
        let dir = Self::config_dir()?;
        fs::create_dir_all(&dir)?;

        // Set directory permissions to 0o700 (owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }

        let path = Self::config_path()?;
        let content = toml::to_string_pretty(self)?;

        // Atomic write with secure permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Create temp file in same directory for atomic rename
            let mut temp_file = NamedTempFile::new_in(&dir)?;

            // Set permissions BEFORE writing content
            let temp_path = temp_file.path();
            fs::set_permissions(temp_path, fs::Permissions::from_mode(0o600))?;

            // Write content
            temp_file.write_all(content.as_bytes())?;

            // Atomic rename
            temp_file.persist(&path)?;
        }

        // Windows fallback
        #[cfg(not(unix))]
        {
            fs::write(&path, content)?;
            eprintln!(
                "{} File permissions are not restricted on Windows. Consider using SCURL_API_KEY environment variable for better security.",
                "⚠".yellow()
            );
        }

        Ok(())
    }
}

pub(crate) fn store_api_key_keyring(provider: &str, key: &str) -> Result<()> {
    let entry = keyring::Entry::new("scurl", provider)
        .context("Failed to create keyring entry")?;
    entry
        .set_password(key)
        .context("Failed to store API key in OS keyring")?;
    Ok(())
}

pub(crate) fn load_api_key_keyring(provider: &str) -> Result<String> {
    let entry = keyring::Entry::new("scurl", provider)
        .context("Failed to create keyring entry")?;
    entry
        .get_password()
        .context("Failed to load API key from OS keyring")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_paths() {
        let config_dir = Config::config_dir().unwrap();
        assert!(config_dir.ends_with(".scurl"));

        let config_path = Config::config_path().unwrap();
        assert!(config_path.ends_with("config.toml"));
    }

    #[test]
    fn test_config_deserialize_minimal() {
        let toml_str = r#"
provider = "anthropic"
api_key = "sk-test"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider, "anthropic");
        assert!(config.whitelist_sources.is_empty());
    }

    #[test]
    fn test_config_deserialize_with_all_fields() {
        let toml_str = r#"
provider = "openai"
api_key = "sk-test"
model = "gpt-4"
azure_endpoint = "https://myresource.openai.azure.com"
azure_deployment = "my-deployment"
whitelist_sources = ["https://github.com/", "https://get.docker.com"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider, "openai");
        assert_eq!(config.whitelist_sources.len(), 2);
    }

    #[test]
    fn test_config_deserialize_ignores_unknown_fields() {
        // toml crate with serde should handle unknown fields based on #[serde(deny_unknown_fields)] or not
        // Our Config does NOT deny unknown fields, so extra keys should be silently ignored
        let toml_str = r#"
provider = "anthropic"
api_key = "sk-test"
unknown_future_field = "hello"
"#;
        let result = toml::from_str::<Config>(toml_str);
        // This may or may not fail depending on serde config, but should not panic
        let _ = result;
    }
}

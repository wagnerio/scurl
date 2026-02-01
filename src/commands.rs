use anyhow::Result;
use colored::*;

use crate::config::{store_api_key_keyring, Config};
use crate::helpers::{new_spinner, prompt};
use crate::network::NetworkConfig;
use crate::provider::Provider;

// ============================================================================
// Commands
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub(crate) async fn login_command(
    timeout: u64,
    max_redirects: usize,
    insecure: bool,
    no_proxy: bool,
    proxy: Option<String>,
    system_proxy: bool,
    user_agent: Option<String>,
    headers: Vec<String>,
    retries: usize,
) -> Result<()> {
    println!(
        "\n{} {}\n",
        "🔒 scurl".bright_cyan().bold(),
        "- Initial Setup".bright_white()
    );

    println!("Welcome to scurl! Let's configure your AI provider.\n");

    // Select provider
    println!("{}", "Available providers:".bold());
    println!(
        "  1. {} (Claude Haiku 4.5, Sonnet, Opus)",
        "Anthropic".cyan()
    );
    println!("  2. {} (Grok 4)", "xAI".cyan());
    println!("  3. {} (GPT-5)", "OpenAI".cyan());
    println!("  4. {} (GPT-5)", "Azure OpenAI".cyan());
    println!("  5. {} (Gemini 2.5)", "Google Gemini".cyan());
    println!("  6. {} (Local models via Ollama)", "Ollama".cyan());

    let choice = prompt("\nSelect provider [1-6]: ")?;

    let provider_name = match choice.as_str() {
        "1" => "anthropic",
        "2" => "xai",
        "3" => "openai",
        "4" => "azure-openai",
        "5" => "gemini",
        "6" => "ollama",
        _ => {
            anyhow::bail!("Invalid choice. Please run 'scurl login' again.");
        }
    };

    let provider: Provider = provider_name.parse()?;

    println!(
        "\n{} {}",
        "Selected:".green(),
        provider.name().bright_white().bold()
    );

    // Get API key and Azure-specific configuration
    let (api_key, azure_endpoint, azure_deployment) = if matches!(provider, Provider::Ollama) {
        println!("\n{}", "Ollama Setup:".bold());
        println!("  → Install Ollama from https://ollama.ai");
        println!("  → Run: ollama pull llama3.2 (or your preferred model)");
        println!("  → Ensure Ollama is running: ollama serve");
        println!(
            "\n{}",
            "Note: Ollama doesn't require an API key".bright_black()
        );

        let api_key_input = prompt("\nEnter API key (press Enter to skip for Ollama): ")?;
        let key = if api_key_input.is_empty() {
            "ollama-no-key".to_string()
        } else {
            api_key_input
        };
        (key, None, None)
    } else if matches!(provider, Provider::AzureOpenAI) {
        println!("\n{}", "Azure OpenAI Setup:".bold());
        println!("  → Go to Azure Portal: https://portal.azure.com");
        println!("  → Navigate to your Azure OpenAI resource");
        println!("  → Get your endpoint (e.g., https://your-resource.openai.azure.com)");
        println!("  → Get your API key from Keys and Endpoint");
        println!("  → Note your deployment name");

        let endpoint_input = prompt("\nEnter your Azure endpoint URL: ")?;
        if endpoint_input.is_empty() {
            anyhow::bail!("Azure endpoint cannot be empty");
        }

        let api_key_input = prompt("\nEnter your API key: ")?;
        if api_key_input.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }

        let deployment_input = prompt("\nEnter your deployment name: ")?;
        if deployment_input.is_empty() {
            anyhow::bail!("Deployment name cannot be empty");
        }

        (api_key_input, Some(endpoint_input), Some(deployment_input))
    } else {
        println!("\n{}", "Get your API key:".bold());
        match provider {
            Provider::Anthropic => println!("  → https://console.anthropic.com"),
            Provider::XAI => println!("  → https://console.x.ai"),
            Provider::OpenAI => println!("  → https://platform.openai.com/api-keys"),
            Provider::Gemini => println!("  → https://aistudio.google.com/app/apikey"),
            Provider::AzureOpenAI | Provider::Ollama => unreachable!(),
        }

        let api_key_input = prompt("\nEnter your API key: ")?;

        if api_key_input.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }

        (api_key_input, None, None)
    };

    // Optional: custom model
    println!(
        "\n{} {}",
        "Default model:".bright_black(),
        provider.default_model().bright_black()
    );
    let custom_model = prompt("Custom model (press Enter to use default): ")?;

    let model = if custom_model.is_empty() {
        None
    } else {
        Some(custom_model)
    };

    // Test the configuration (respects --proxy and other network flags)
    let spinner = new_spinner("Testing API connection...");
    let net_config = NetworkConfig::new(
        timeout,
        max_redirects,
        insecure,
        no_proxy,
        proxy,
        system_proxy,
        user_agent,
        headers,
        retries,
    )?;

    // Create temporary config for testing
    let test_config = Config {
        provider: provider_name.to_string(),
        api_key: api_key.clone(),
        model: model.clone(),
        azure_endpoint: azure_endpoint.clone(),
        azure_deployment: azure_deployment.clone(),
        whitelist_sources: Vec::new(),
    };

    let test_script = "#!/bin/bash\necho 'Hello, World!'";
    match provider
        .analyze(
            test_script,
            &test_config.api_key,
            test_config.model.as_deref(),
            &net_config,
            None,
            &test_config,
        )
        .await
    {
        Ok(_) => {
            spinner
                .finish_with_message(format!("{} API connection successful!", "✓".green().bold()));
        }
        Err(e) => {
            spinner.finish_with_message(format!("{} API connection failed!", "✗".red().bold()));
            anyhow::bail!("Error: {}", e);
        }
    }

    // Attempt to store API key in OS keyring first
    let (config_api_key, key_storage_msg) = match store_api_key_keyring(provider_name, &api_key) {
        Ok(()) => {
            // Store sentinel value in config file so we know to load from keyring
            ("keyring".to_string(), "API key stored securely in OS keyring.")
        }
        Err(e) => {
            eprintln!(
                "\n{} Could not store API key in OS keyring: {}. Falling back to config file.",
                "⚠".yellow(),
                e
            );
            (api_key, "API key stored in plaintext config file. For maximum security, use SCURL_API_KEY env var instead.")
        }
    };

    // Save configuration
    // Preserve existing whitelist when re-saving config
    let existing_config = Config::load().ok();
    let existing_whitelist = existing_config
        .as_ref()
        .map(|c| c.whitelist_sources.clone())
        .unwrap_or_default();
    let config = Config {
        provider: provider_name.to_string(),
        api_key: config_api_key,
        model,
        azure_endpoint,
        azure_deployment,
        whitelist_sources: existing_whitelist,
    };

    config.save()?;

    println!(
        "\n{} Configuration saved to {}",
        "✓".green().bold(),
        Config::config_path()?.display().to_string().bright_black()
    );

    println!("\n{} {}", "ℹ".blue(), key_storage_msg);

    println!("\n{}", "You're all set! Try:".green().bold());
    println!("  {}", "scurl https://example.com/install.sh".cyan());

    Ok(())
}

pub(crate) fn config_command() -> Result<()> {
    let config = Config::load()?;

    println!("\n{}", "Current Configuration".bold());
    println!("{}", "═".repeat(50).bright_black());

    let provider: Provider = config.provider.parse()?;
    println!("{:15} {}", "Provider:".bright_white(), provider.name());

    let masked_key = {
        let chars: Vec<char> = config.api_key.chars().collect();
        if chars.len() > 10 {
            let prefix: String = chars[..6].iter().collect();
            let suffix: String = chars[chars.len() - 4..].iter().collect();
            format!("{}...{}", prefix, suffix)
        } else {
            "***".to_string()
        }
    };
    println!("{:15} {}", "API Key:".bright_white(), masked_key);

    if let Some(model) = &config.model {
        println!("{:15} {}", "Model:".bright_white(), model);
    } else {
        println!(
            "{:15} {} (default)",
            "Model:".bright_white(),
            provider.default_model().bright_black()
        );
    }

    println!(
        "{:15} {}",
        "Config File:".bright_white(),
        Config::config_path()?.display().to_string().bright_black()
    );

    println!("{}", "═".repeat(50).bright_black());
    println!("\nTo reconfigure, run: {}", "scurl login".green().bold());

    Ok(())
}

pub(crate) fn skill_command() -> Result<()> {
    print!(
        r#"---
name: openclaw
description: Security review for installation scripts using scurl. Analyzes URLs for dangerous patterns, prompt injection, and security risks before execution. Use when reviewing shell scripts, install scripts, or any piped-to-bash content.
user-invocable: true
allowed-tools: Bash
argument-hint: <url>
---

# openclaw — Security Review via scurl

Run `scurl` to analyze a script URL for security risks and present the findings.

## Input

`$ARGUMENTS` is a URL to analyze. If no argument is provided, ask the user for the URL.

## Execution

Run scurl against the target URL. Choose flags based on context:

```bash
scurl $ARGUMENTS
```

If the user wants auto-execution of safe scripts:
```bash
scurl -a $ARGUMENTS
```

If the user specifies a provider:
```bash
scurl -p <provider> $ARGUMENTS
```

## Requirements

- `scurl` must be installed (`cargo install scurl`)
- An AI provider must be configured (`scurl login`) or `SCURL_API_KEY` must be set

If `scurl` is not found, tell the user to install it:
```
cargo install scurl
```

## Available Flags

Pass through any flags the user requests:

| Flag | Description |
|------|-------------|
| `-a` | Auto-execute if risk is SAFE or LOW |
| `-p <provider>` | Override AI provider (anthropic, openai, xai, azure, gemini, ollama) |
| `-s <shell>` | Shell for execution (default: bash) |
| `-x <url>` | HTTP/HTTPS proxy |
| `-t <secs>` | Request timeout |
| `-k` | Skip TLS verification for script download |
| `-H <header>` | Custom request header |
| `--retries <n>` | Retry attempts |
| `--runtime-container` | Execute in rootless Podman container |
| `--container-timeout <secs>` | Container execution timeout (default: 300) |
| `--monitor-level <level>` | Falco monitor sensitivity (strict, normal, permissive) |
| `--no-monitor` | Disable Falco runtime monitoring |
| `--auto-trust` | Cache and auto-trust safe scripts |
| `--blacklist-hash <hex>` | Blacklist a script hash |
| `--second-opinion` | Cross-validate with a second AI provider |
| `--second-provider <name>` | Provider for second opinion |
| `--no-sandbox` | Disable OS-level sandbox |

## Rules

- Always show the full scurl output to the user
- Do not attempt to parse or reformat scurl's output — it has its own report format
- If scurl prompts "Execute this script? [y/N]:", tell the user and let them decide
- Do not pass `-a` unless the user explicitly asks for auto-execution
"#
    );
    Ok(())
}

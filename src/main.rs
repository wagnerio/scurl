use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    provider: String,
    api_key: String,
    model: Option<String>,
}

impl Config {
    fn config_dir() -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not find home directory")?;
        Ok(home.join(".scurl"))
    }

    fn config_path() -> Result<PathBuf> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            anyhow::bail!(
                "No configuration found. Please run {} first.",
                "scurl login".green().bold()
            );
        }
        let content = fs::read_to_string(path)?;
        toml::from_str(&content).context("Failed to parse config file")
    }

    fn save(&self) -> Result<()> {
        let dir = Self::config_dir()?;
        fs::create_dir_all(&dir)?;

        let path = Self::config_path()?;
        let content = toml::to_string_pretty(self)?;
        fs::write(&path, content)?;

        // Restrict file permissions to owner-only (contains API keys)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "scurl")]
#[command(version)]
#[command(about = "Secure curl - AI-powered security review for install scripts", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// URL of the install script (shorthand for 'scurl analyze <URL>')
    #[arg(value_name = "URL")]
    url: Option<String>,

    /// Shell to use for execution
    #[arg(short, long, default_value = "bash", global = true)]
    shell: String,

    /// Auto-execute if classified as probably safe
    #[arg(short, long, global = true)]
    auto_execute: bool,

    /// Skip AI review and just download + execute (dangerous!)
    #[arg(long, global = true)]
    yolo: bool,

    /// Override API key from config
    #[arg(long, global = true)]
    api_key: Option<String>,

    /// Override provider from config
    #[arg(short = 'p', long, global = true)]
    provider: Option<String>,

    // Network & Proxy Options
    /// HTTP/HTTPS proxy URL (e.g., http://proxy.example.com:8080)
    #[arg(short = 'x', long, global = true, env = "HTTPS_PROXY")]
    proxy: Option<String>,

    /// Timeout in seconds for network requests
    #[arg(short = 't', long, default_value = "30", global = true)]
    timeout: u64,

    /// Maximum number of redirects to follow
    #[arg(long, default_value = "10", global = true)]
    max_redirects: usize,

    /// Disable SSL certificate verification (insecure!)
    #[arg(short = 'k', long = "insecure", global = true)]
    insecure: bool,

    /// Custom User-Agent header
    #[arg(short = 'A', long, global = true)]
    user_agent: Option<String>,

    /// Additional headers (format: 'Key: Value')
    #[arg(short = 'H', long = "header", global = true)]
    headers: Vec<String>,

    /// Number of retries on network failure
    #[arg(long, default_value = "3", global = true)]
    retries: usize,

    /// Use system proxy settings
    #[arg(long, global = true)]
    system_proxy: bool,

    /// Disable proxy even if environment variables are set
    #[arg(long, global = true)]
    no_proxy: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Configure scurl with your AI provider credentials
    Login,
    /// Analyze and potentially execute a script (default command)
    Analyze {
        /// URL of the install script to download and review
        url: String,
    },
    /// Show current configuration
    Config,
}

// ============================================================================
// Network Configuration
// ============================================================================

#[derive(Debug, Clone)]
struct NetworkConfig {
    headers: Vec<String>,
    retries: usize,
    client: reqwest::Client,
}

impl NetworkConfig {
    fn from_cli(cli: &Cli) -> Result<Self> {
        let timeout = cli.timeout;
        let max_redirects = cli.max_redirects;
        let insecure = cli.insecure;
        let no_proxy = cli.no_proxy;
        let proxy = cli.proxy.clone();
        let system_proxy = cli.system_proxy;
        let user_agent = cli.user_agent.clone();

        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout))
            .redirect(if max_redirects > 0 {
                reqwest::redirect::Policy::limited(max_redirects)
            } else {
                reqwest::redirect::Policy::none()
            });

        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }

        if no_proxy {
            builder = builder.no_proxy();
        } else if let Some(ref proxy_url) = proxy {
            let p = reqwest::Proxy::all(proxy_url).context("Invalid proxy URL")?;
            builder = builder.proxy(p);
        } else if system_proxy {
            // System proxy is enabled by default in reqwest
        }

        if let Some(ref ua) = user_agent {
            builder = builder.user_agent(ua.clone());
        } else {
            builder = builder.user_agent(format!("scurl/{}", env!("CARGO_PKG_VERSION")));
        }

        let client = builder.build().context("Failed to build HTTP client")?;

        Ok(Self {
            headers: cli.headers.clone(),
            retries: cli.retries,
            client,
        })
    }

    fn parse_headers(&self) -> Result<Vec<(String, String)>> {
        let mut parsed = Vec::new();
        for header in &self.headers {
            if let Some((key, value)) = header.split_once(':') {
                parsed.push((key.trim().to_string(), value.trim().to_string()));
            } else {
                anyhow::bail!("Invalid header format: '{}'. Use 'Key: Value'", header);
            }
        }
        Ok(parsed)
    }
}

// ============================================================================
// AI Provider Abstraction
// ============================================================================

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
enum Provider {
    Anthropic,
    XAI,
    OpenAI,
    Ollama,
}

impl std::str::FromStr for Provider {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "anthropic" | "claude" => Ok(Provider::Anthropic),
            "xai" | "x.ai" | "grok" => Ok(Provider::XAI),
            "openai" | "chatgpt" => Ok(Provider::OpenAI),
            "ollama" | "local" => Ok(Provider::Ollama),
            _ => anyhow::bail!("Unknown provider: {}", s),
        }
    }
}

impl Provider {
    fn name(&self) -> &str {
        match self {
            Provider::Anthropic => "Anthropic (Claude)",
            Provider::XAI => "xAI (Grok)",
            Provider::OpenAI => "OpenAI (GPT)",
            Provider::Ollama => "Ollama (Local)",
        }
    }

    fn default_model(&self) -> &str {
        match self {
            Provider::Anthropic => "claude-haiku-4-5",
            Provider::XAI => "grok-4-1-fast-reasoning",
            Provider::OpenAI => "gpt-5-nano",
            Provider::Ollama => "llama3.2",
        }
    }

    async fn analyze(
        &self,
        script: &str,
        api_key: &str,
        model: Option<&str>,
        net_config: &NetworkConfig,
    ) -> Result<String> {
        let model = model.unwrap_or_else(|| self.default_model());

        let prompt = format!(
            r#"You are a security expert analyzing a shell installation script. Review this script for security issues.

Script to analyze:
```bash
{}
```

Provide your analysis in the following format:
RISK_LEVEL: [SAFE/LOW/MEDIUM/HIGH/CRITICAL]
FINDINGS:
- [Finding 1]
- [Finding 2]
...
RECOMMENDATION: [Your recommendation on whether to execute this script]

Focus on:
- Suspicious commands (curl | bash chains, eval, base64 decoding)
- Downloads from untrusted sources
- Privilege escalation (sudo, chmod 777, etc.)
- Code obfuscation
- Credential harvesting
- Backdoor installation
- Malicious payloads
- Destructive operations (rm -rf, dd, etc.)

Be practical: common patterns like sudo for installation, downloading from official sources, and standard package management are acceptable."#,
            script
        );

        let max_attempts = net_config.retries.max(1);
        let mut last_error = None;

        for attempt in 1..=max_attempts {
            if attempt > 1 {
                tokio::time::sleep(std::time::Duration::from_millis(1000 * attempt as u64)).await;
            }

            let result = match self {
                Provider::Anthropic => {
                    self.call_anthropic(&prompt, api_key, model, net_config)
                        .await
                }
                Provider::XAI => {
                    self.call_openai_compatible(
                        &prompt,
                        api_key,
                        model,
                        "https://api.x.ai/v1/chat/completions",
                        net_config,
                    )
                    .await
                }
                Provider::OpenAI => {
                    self.call_openai_compatible(
                        &prompt,
                        api_key,
                        model,
                        "https://api.openai.com/v1/chat/completions",
                        net_config,
                    )
                    .await
                }
                Provider::Ollama => {
                    self.call_openai_compatible(
                        &prompt,
                        api_key,
                        model,
                        "http://localhost:11434/v1/chat/completions",
                        net_config,
                    )
                    .await
                }
            };

            match result {
                Ok(text) => return Ok(text),
                Err(e) => {
                    let err_str = e.to_string();
                    // Don't retry client errors (4xx) — they won't succeed on retry
                    if err_str.contains("API error 4") {
                        return Err(e);
                    }
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow::anyhow!("AI analysis failed after {} attempts", max_attempts)
        }))
    }

    async fn call_anthropic(
        &self,
        prompt: &str,
        api_key: &str,
        model: &str,
        net_config: &NetworkConfig,
    ) -> Result<String> {
        #[derive(Serialize)]
        struct Message {
            role: String,
            content: String,
        }

        #[derive(Serialize)]
        struct Request {
            model: String,
            max_tokens: u32,
            messages: Vec<Message>,
        }

        #[derive(Deserialize)]
        struct ContentBlock {
            text: String,
        }

        #[derive(Deserialize)]
        struct Response {
            content: Vec<ContentBlock>,
        }

        let request = Request {
            model: model.to_string(),
            max_tokens: 2048,
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };

        let response = net_config
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to call Anthropic API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error {}: {}", status, error_text);
        }

        let api_response: Response = response
            .json()
            .await
            .context("Failed to parse API response")?;

        Ok(api_response
            .content
            .first()
            .context("No content in API response")?
            .text
            .clone())
    }

    async fn call_openai_compatible(
        &self,
        prompt: &str,
        api_key: &str,
        model: &str,
        endpoint: &str,
        net_config: &NetworkConfig,
    ) -> Result<String> {
        #[derive(Serialize)]
        struct Message {
            role: String,
            content: String,
        }

        #[derive(Serialize)]
        struct Request {
            model: String,
            messages: Vec<Message>,
            max_tokens: Option<u32>,
        }

        #[derive(Deserialize)]
        struct Choice {
            message: ResponseMessage,
        }

        #[derive(Deserialize)]
        struct ResponseMessage {
            content: String,
        }

        #[derive(Deserialize)]
        struct Response {
            choices: Vec<Choice>,
        }

        let request = Request {
            model: model.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
            max_tokens: Some(2048),
        };

        let mut req = net_config
            .client
            .post(endpoint)
            .header("content-type", "application/json");

        // Skip Authorization header for Ollama (local, no API key needed)
        if !matches!(self, Provider::Ollama) {
            req = req.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = req
            .json(&request)
            .send()
            .await
            .context("Failed to call API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("API error {}: {}", status, error_text);
        }

        let api_response: Response = response
            .json()
            .await
            .context("Failed to parse API response")?;

        Ok(api_response
            .choices
            .first()
            .context("No choices in API response")?
            .message
            .content
            .clone())
    }
}

// ============================================================================
// Security Analysis
// ============================================================================

#[derive(Debug)]
struct SecurityAnalysis {
    risk_level: RiskLevel,
    findings: Vec<String>,
    recommendation: String,
}

#[derive(Debug, PartialEq)]
enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "safe" => RiskLevel::Safe,
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => RiskLevel::High,
        }
    }

    fn color(&self) -> Color {
        match self {
            RiskLevel::Safe => Color::Green,
            RiskLevel::Low => Color::Cyan,
            RiskLevel::Medium => Color::Yellow,
            RiskLevel::High => Color::Red,
            RiskLevel::Critical => Color::Magenta,
        }
    }

    fn is_probably_safe(&self) -> bool {
        matches!(self, RiskLevel::Safe | RiskLevel::Low)
    }
}

fn parse_analysis(text: &str) -> Result<SecurityAnalysis> {
    let mut risk_level = None;
    let mut findings = Vec::new();
    let mut recommendation = String::new();

    let mut current_section = "";

    // Strip common markdown formatting the LLM might add
    let clean = text.replace("**", "").replace("__", "");

    for line in clean.lines() {
        let line = line.trim();

        if line.starts_with("RISK_LEVEL:") {
            let level = line.replace("RISK_LEVEL:", "").trim().to_string();
            risk_level = Some(RiskLevel::from_str(&level));
        } else if line == "FINDINGS:" {
            current_section = "findings";
        } else if line.starts_with("RECOMMENDATION:") {
            current_section = "recommendation";
            recommendation = line.replace("RECOMMENDATION:", "").trim().to_string();
        } else if current_section == "findings" && line.starts_with('-') {
            findings.push(line.trim_start_matches('-').trim().to_string());
        } else if current_section == "recommendation" && !line.is_empty() {
            if !recommendation.is_empty() {
                recommendation.push(' ');
            }
            recommendation.push_str(line);
        }
    }

    // If we couldn't parse the risk level, treat as HIGH out of caution
    // and include the raw response so the user can judge for themselves
    let risk_level = match risk_level {
        Some(level) => level,
        None => {
            eprintln!(
                "{} Could not parse AI risk level — defaulting to HIGH for safety.",
                "⚠".yellow()
            );
            if findings.is_empty() {
                findings
                    .push("AI response could not be parsed into structured format.".to_string());
            }
            if recommendation.is_empty() {
                recommendation =
                    "Review the raw analysis below and use your own judgement.".to_string();
                // Include raw response as a finding so the user can still see it
                findings.push(format!("Raw AI response:\n{}", text));
            }
            RiskLevel::High
        }
    };

    Ok(SecurityAnalysis {
        risk_level,
        findings,
        recommendation,
    })
}

fn display_analysis(analysis: &SecurityAnalysis) {
    println!(
        "\n{}",
        "═══════════════════════════════════════════════════".bright_white()
    );
    println!(
        "{}",
        "           SECURITY ANALYSIS REPORT".bright_white().bold()
    );
    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_white()
    );

    println!(
        "\n{} {}",
        "Risk Level:".bold(),
        format!("{:?}", analysis.risk_level)
            .to_uppercase()
            .color(analysis.risk_level.color())
            .bold()
    );

    if !analysis.findings.is_empty() {
        println!("\n{}", "Findings:".bold());
        for (i, finding) in analysis.findings.iter().enumerate() {
            println!("  {}. {}", i + 1, finding);
        }
    }

    println!("\n{}", "Recommendation:".bold());
    println!("  {}", analysis.recommendation);

    println!(
        "{}",
        "═══════════════════════════════════════════════════".bright_white()
    );
}

// ============================================================================
// Core Functions
// ============================================================================

async fn download_script(url: &str, net_config: &NetworkConfig) -> Result<String> {
    let spinner = new_spinner("Downloading script...");

    let client = &net_config.client;
    let headers = net_config.parse_headers()?;

    let mut last_error = None;
    let max_attempts = net_config.retries.max(1);

    for attempt in 1..=max_attempts {
        if attempt > 1 {
            spinner.set_message(format!(
                "Downloading script... (retry {}/{})",
                attempt - 1,
                max_attempts - 1
            ));
            tokio::time::sleep(std::time::Duration::from_millis(1000 * attempt as u64)).await;
        }

        let mut request = client.get(url);

        // Add custom headers
        for (key, value) in &headers {
            request = request.header(key, value);
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();

                if !status.is_success() {
                    let err = anyhow::anyhow!("HTTP error: {}", status);
                    // Don't retry client errors (4xx) — they won't succeed on retry
                    if status.is_client_error() {
                        spinner.finish_and_clear();
                        return Err(err);
                    }
                    last_error = Some(err);
                    continue;
                }

                // Validate content type looks like a script
                if let Some(content_type) = response.headers().get("content-type") {
                    let ct = content_type.to_str().unwrap_or("");
                    let is_script_like = ct.contains("text/")
                        || ct.contains("application/x-sh")
                        || ct.contains("application/x-shellscript")
                        || ct.contains("application/octet-stream")
                        || ct.is_empty();

                    if !is_script_like {
                        eprintln!(
                            "{} Content-Type is '{}' (expected script-like content)",
                            "⚠".yellow(),
                            ct
                        );
                    }
                }

                // Guard against excessively large responses (10 MB limit)
                const MAX_SCRIPT_SIZE: u64 = 10 * 1024 * 1024;
                if let Some(len) = response.content_length() {
                    if len > MAX_SCRIPT_SIZE {
                        spinner.finish_and_clear();
                        anyhow::bail!(
                            "Script too large ({:.1} MB). Max allowed: {:.0} MB",
                            len as f64 / 1_048_576.0,
                            MAX_SCRIPT_SIZE as f64 / 1_048_576.0
                        );
                    }
                }

                match response.text().await {
                    Ok(script) => {
                        if script.is_empty() {
                            spinner.finish_and_clear();
                            anyhow::bail!("Downloaded script is empty");
                        }

                        if script.len() as u64 > MAX_SCRIPT_SIZE {
                            spinner.finish_and_clear();
                            anyhow::bail!(
                                "Script too large ({:.1} MB)",
                                script.len() as f64 / 1_048_576.0
                            );
                        }

                        spinner.finish_with_message(format!(
                            "{} Downloaded {} bytes",
                            "✓".green(),
                            script.len()
                        ));
                        return Ok(script);
                    }
                    Err(e) => {
                        last_error = Some(anyhow::Error::from(e));
                        continue;
                    }
                }
            }
            Err(e) => {
                last_error = Some(anyhow::Error::from(e));
                continue;
            }
        }
    }

    spinner.finish_and_clear();
    Err(last_error.unwrap_or_else(|| {
        anyhow::anyhow!("Failed to download script after {} attempts", max_attempts)
    }))
}

async fn analyze_script(
    script: &str,
    config: &Config,
    net_config: &NetworkConfig,
) -> Result<SecurityAnalysis> {
    let provider: Provider = config.provider.parse()?;
    let spinner = new_spinner(&format!("Analyzing script with {} AI...", provider.name()));

    // Perform analysis
    let response_text = provider
        .analyze(script, &config.api_key, config.model.as_deref(), net_config)
        .await?;

    spinner.finish_with_message(format!("{} Analysis complete!", "✓".green()));

    parse_analysis(&response_text)
}

fn prompt_user_confirmation() -> Result<bool> {
    print!("\n{} ", "Execute this script? [y/N]:".yellow().bold());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn execute_script(script: &str, shell: &str) -> Result<()> {
    println!("\n{}", format!("Executing script with {}...", shell).cyan());

    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(script.as_bytes())?;
    let temp_path = temp_file.path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(temp_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(temp_path, perms)?;
    }

    let status = Command::new(shell)
        .arg(temp_path)
        .status()
        .context(format!("Failed to execute script with {}", shell))?;

    if !status.success() {
        anyhow::bail!(
            "Script execution failed with exit code: {:?}",
            status.code()
        );
    }

    println!("\n{}", "Script executed successfully".green().bold());
    Ok(())
}

// ============================================================================
// Commands
// ============================================================================

fn prompt(message: &str) -> Result<String> {
    print!("{}", message.bright_white().bold());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

fn new_spinner(msg: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    spinner.set_message(msg.to_string());
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));
    spinner
}

async fn login_command(cli: &Cli) -> Result<()> {
    println!(
        "\n{} {}\n",
        "🔒 scurl".bright_cyan().bold(),
        "- Initial Setup".bright_white()
    );

    println!("Welcome to scurl! Let's configure your AI provider.\n");

    // Select provider
    println!("{}", "Available providers:".bold());
    println!(
        "  1. {} (Claude Sonnet 4.5, Haiku, Opus)",
        "Anthropic".cyan()
    );
    println!("  2. {} (Grok 4)", "xAI".cyan());
    println!("  3. {} (GPT-4, gpt-5-nano)", "OpenAI".cyan());
    println!("  4. {} (Local models via Ollama)", "Ollama".cyan());

    let choice = prompt("\nSelect provider [1-4]: ")?;

    let provider_name = match choice.as_str() {
        "1" => "anthropic",
        "2" => "xai",
        "3" => "openai",
        "4" => "ollama",
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

    // Get API key
    let api_key = if matches!(provider, Provider::Ollama) {
        println!("\n{}", "Ollama Setup:".bold());
        println!("  → Install Ollama from https://ollama.ai");
        println!("  → Run: ollama pull llama3.2 (or your preferred model)");
        println!("  → Ensure Ollama is running: ollama serve");
        println!(
            "\n{}",
            "Note: Ollama doesn't require an API key".bright_black()
        );

        let api_key_input = prompt("\nEnter API key (press Enter to skip for Ollama): ")?;
        if api_key_input.is_empty() {
            "ollama-no-key".to_string()
        } else {
            api_key_input
        }
    } else {
        println!("\n{}", "Get your API key:".bold());
        match provider {
            Provider::Anthropic => println!("  → https://console.anthropic.com"),
            Provider::XAI => println!("  → https://console.x.ai"),
            Provider::OpenAI => println!("  → https://platform.openai.com/api-keys"),
            Provider::Ollama => unreachable!(),
        }

        let api_key_input = prompt("\nEnter your API key: ")?;

        if api_key_input.is_empty() {
            anyhow::bail!("API key cannot be empty");
        }

        api_key_input
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
    let net_config = NetworkConfig::from_cli(cli)?;

    let test_script = "#!/bin/bash\necho 'Hello, World!'";
    match provider
        .analyze(test_script, &api_key, model.as_deref(), &net_config)
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

    // Save configuration
    let config = Config {
        provider: provider_name.to_string(),
        api_key,
        model,
    };

    config.save()?;

    println!(
        "\n{} Configuration saved to {}",
        "✓".green().bold(),
        Config::config_path()?.display().to_string().bright_black()
    );

    println!("\n{}", "You're all set! Try:".green().bold());
    println!("  {}", "scurl https://example.com/install.sh".cyan());

    Ok(())
}

fn config_command() -> Result<()> {
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

async fn analyze_command(url: &str, cli: &Cli) -> Result<()> {
    println!(
        "\n{} {}\n",
        "🔒 scurl".bright_cyan().bold(),
        "- Secure Script Execution".bright_white()
    );

    // Load config or build from CLI overrides
    let config = match (&cli.provider, &cli.api_key) {
        (Some(provider), Some(api_key)) => Config {
            provider: provider.clone(),
            api_key: api_key.clone(),
            model: None,
        },
        _ => {
            let mut cfg = Config::load()?;
            if let Some(ref api_key) = cli.api_key {
                cfg.api_key = api_key.clone();
            }
            if let Some(ref provider) = cli.provider {
                cfg.provider = provider.clone();
            }
            cfg
        }
    };

    // Build network configuration and HTTP client from CLI
    let net_config = NetworkConfig::from_cli(cli)?;

    if cli.insecure {
        eprintln!(
            "{}",
            "⚠️  SSL verification disabled — connection is not secure!".bright_yellow()
        );
    }

    // Download the script
    let script = download_script(url, &net_config).await?;

    // YOLO mode - skip review
    if cli.yolo {
        println!(
            "\n{}",
            "⚠️  YOLO mode enabled - skipping security review!"
                .bright_red()
                .bold()
        );
        execute_script(&script, &cli.shell)?;
        return Ok(());
    }

    // Perform security analysis
    let analysis = analyze_script(&script, &config, &net_config).await?;

    // Display results
    display_analysis(&analysis);

    // Decide whether to execute
    let should_execute = if cli.auto_execute && analysis.risk_level.is_probably_safe() {
        println!(
            "\n{}",
            "✓ Auto-executing (classified as safe)".green().bold()
        );
        true
    } else if cli.auto_execute {
        println!(
            "\n{}",
            "✗ Auto-execute disabled due to risk level".red().bold()
        );
        prompt_user_confirmation()?
    } else {
        prompt_user_confirmation()?
    };

    if should_execute {
        execute_script(&script, &cli.shell)?;
    } else {
        println!("\n{}", "Execution cancelled by user".yellow());
    }

    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Login) => login_command(&cli).await,
        Some(Commands::Config) => config_command(),
        Some(Commands::Analyze { ref url }) => analyze_command(url, &cli).await,
        None => {
            if let Some(ref url) = cli.url {
                // Shorthand: scurl <URL>
                analyze_command(url, &cli).await
            } else {
                // No command or URL provided
                println!("{}", "scurl - Secure curl".bold());
                println!("\nUsage:");
                println!("  {}  Configure your AI provider", "scurl login".green());
                println!("  {}     Analyze a script", "scurl <URL>".green());
                println!("  {}      Show configuration", "scurl config".green());
                println!("\nFor more help: {}", "scurl --help".cyan());
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_str() {
        assert_eq!(RiskLevel::from_str("safe"), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_str("SAFE"), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_str("low"), RiskLevel::Low);
        assert_eq!(RiskLevel::from_str("critical"), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_str("unknown"), RiskLevel::High);
    }

    #[test]
    fn test_risk_level_is_probably_safe() {
        assert!(RiskLevel::Safe.is_probably_safe());
        assert!(RiskLevel::Low.is_probably_safe());
        assert!(!RiskLevel::Medium.is_probably_safe());
        assert!(!RiskLevel::High.is_probably_safe());
        assert!(!RiskLevel::Critical.is_probably_safe());
    }

    #[test]
    fn test_parse_analysis_valid() {
        let text = r#"
RISK_LEVEL: LOW
FINDINGS:
- Uses sudo for installation
- Downloads from GitHub
RECOMMENDATION: This script appears safe to execute.
"#;

        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Low);
        assert_eq!(result.findings.len(), 2);
        assert!(result.recommendation.contains("safe"));
    }

    #[test]
    fn test_parse_analysis_with_markdown() {
        let text = r#"
**RISK_LEVEL:** SAFE
**FINDINGS:**
- No issues found
**RECOMMENDATION:** Safe to run.
"#;

        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Safe);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_parse_analysis_missing_risk_defaults_to_high() {
        let text = r#"
FINDINGS:
- Some finding
RECOMMENDATION: Some recommendation
"#;

        let result = parse_analysis(text).unwrap();
        // Should default to HIGH when risk level can't be parsed
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_provider_from_str() {
        assert!(matches!(
            "anthropic".parse::<Provider>().unwrap(),
            Provider::Anthropic
        ));
        assert!(matches!(
            "claude".parse::<Provider>().unwrap(),
            Provider::Anthropic
        ));
        assert!(matches!("xai".parse::<Provider>().unwrap(), Provider::XAI));
        assert!(matches!("grok".parse::<Provider>().unwrap(), Provider::XAI));
        assert!(matches!(
            "openai".parse::<Provider>().unwrap(),
            Provider::OpenAI
        ));
        assert!(matches!(
            "ollama".parse::<Provider>().unwrap(),
            Provider::Ollama
        ));
        assert!(matches!(
            "local".parse::<Provider>().unwrap(),
            Provider::Ollama
        ));
        assert!("invalid".parse::<Provider>().is_err());
    }

    #[test]
    fn test_provider_default_models() {
        let anthropic = Provider::Anthropic;
        assert!(anthropic.default_model().contains("claude"));

        let xai = Provider::XAI;
        assert_eq!(xai.default_model(), "grok-4-1-fast-reasoning");

        let openai = Provider::OpenAI;
        assert_eq!(openai.default_model(), "gpt-5-nano");

        let ollama = Provider::Ollama;
        assert_eq!(ollama.default_model(), "llama3.2");
    }

    #[test]
    fn test_network_config_parse_headers() {
        let config = NetworkConfig {
            headers: vec![
                "Authorization: Bearer token".to_string(),
                "X-Custom: value".to_string(),
            ],
            retries: 3,
            client: reqwest::Client::new(),
        };

        let parsed = config.parse_headers().unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parsed[0],
            ("Authorization".to_string(), "Bearer token".to_string())
        );
        assert_eq!(parsed[1], ("X-Custom".to_string(), "value".to_string()));
    }

    #[test]
    fn test_network_config_parse_headers_invalid() {
        let config = NetworkConfig {
            headers: vec!["InvalidHeader".to_string()],
            retries: 3,
            client: reqwest::Client::new(),
        };

        assert!(config.parse_headers().is_err());
    }

    #[test]
    fn test_config_paths() {
        let config_dir = Config::config_dir().unwrap();
        assert!(config_dir.ends_with(".scurl"));

        let config_path = Config::config_path().unwrap();
        assert!(config_path.ends_with("config.toml"));
    }
}

mod analysis;
mod audit;
mod cache;
mod commands;
mod config;
mod container;
mod helpers;
mod network;
mod provider;
mod sandbox;
mod static_analysis;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

use analysis::{display_analysis, RiskLevel};
use audit::write_audit_log;
use cache::{current_timestamp, CacheEntry, ScriptCache};
use config::Config;
use container::{
    classify_alert, display_container_result, execute_in_container, AlertSeverity,
    ContainerResult, FalcoAlert,
};
use helpers::{
    analyze_script, display_second_opinion, download_script, prompt_user_confirmation,
    runtime_ai_review, second_opinion_analysis, validate_shell, validate_url,
};
use network::NetworkConfig;
use sandbox::execute_script;
use static_analysis::{display_static_report, static_analyze};

// ============================================================================
// Monitor Level
// ============================================================================

/// Monitoring sensitivity level for Falco runtime observation.
#[derive(Debug, Clone, Copy, PartialEq, clap::ValueEnum)]
pub(crate) enum MonitorLevel {
    /// Warn only — log alerts but never kill the container
    Low,
    /// Kill on suspicious or critical alerts (default)
    Medium,
    /// Kill on any anomaly
    High,
}

impl std::fmt::Display for MonitorLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitorLevel::Low => write!(f, "low"),
            MonitorLevel::Medium => write!(f, "medium"),
            MonitorLevel::High => write!(f, "high"),
        }
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(name = "scurl")]
#[command(version)]
#[command(about = "Secure curl - AI-powered security review for install scripts", long_about = None)]
pub(crate) struct Cli {
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

    /// Disable sandboxed script execution
    #[arg(long, global = true)]
    no_sandbox: bool,

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

    /// Run script in a Podman container for runtime observation
    #[arg(long, global = true)]
    runtime_container: bool,

    /// Timeout in seconds for container execution
    #[arg(long, default_value = "120", global = true)]
    container_timeout: u64,

    /// Monitoring sensitivity during container execution (requires Falco)
    #[arg(long, value_enum, default_value = "medium", global = true)]
    monitor_level: MonitorLevel,

    /// Disable runtime monitoring (Falco) even if available
    #[arg(long, global = true)]
    no_monitor: bool,

    /// Automatically trust scripts that pass AI + runtime review (cache as safe)
    #[arg(long, global = true)]
    auto_trust: bool,

    /// Blacklist a script hash — revokes trust and blocks future execution
    #[arg(long, global = true, value_name = "HASH")]
    blacklist_hash: Option<String>,

    /// Run a second AI provider for cross-validation
    #[arg(long, global = true)]
    second_opinion: bool,

    /// Provider for second-opinion analysis (default: openai if primary is not openai, else anthropic)
    #[arg(long, global = true)]
    second_provider: Option<String>,
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
    /// Output the openclaw Claude Code skill (SKILL.md)
    Skill,
}

// ============================================================================
// Analyze Command
// ============================================================================

async fn analyze_command(url: &str, cli: &Cli) -> Result<()> {
    println!(
        "\n{} {}\n",
        "🔒 scurl".bright_cyan().bold(),
        "- Secure Script Execution".bright_white()
    );

    // Load config or build from CLI overrides
    let mut config = if let Some(ref provider) = cli.provider {
        // Provider override - try to load config or require env var
        match Config::load() {
            Ok(cfg) => cfg,
            Err(_) => {
                // No config file, require SCURL_API_KEY
                let api_key = std::env::var("SCURL_API_KEY")
                    .context("SCURL_API_KEY environment variable required when using --provider without configured credentials. Run 'scurl login' first.")?;
                Config {
                    provider: provider.clone(),
                    api_key,
                    model: None,
                    azure_endpoint: std::env::var("AZURE_OPENAI_ENDPOINT").ok(),
                    azure_deployment: std::env::var("AZURE_OPENAI_DEPLOYMENT").ok(),
                    whitelist_sources: Vec::new(),
                }
            }
        }
    } else {
        Config::load()?
    };

    // Override from environment variable if set
    if let Ok(api_key) = std::env::var("SCURL_API_KEY") {
        config.api_key = api_key;
    }

    // Override provider if specified
    if let Some(ref provider) = cli.provider {
        config.provider = provider.clone();
    }

    // Build network configuration and HTTP client from CLI
    let net_config = NetworkConfig::new(
        cli.timeout,
        cli.max_redirects,
        cli.insecure,
        cli.no_proxy,
        cli.proxy.clone(),
        cli.system_proxy,
        cli.user_agent.clone(),
        cli.headers.clone(),
        cli.retries,
    )?;

    if cli.insecure {
        eprintln!(
            "{}",
            "⚠️  SSL verification disabled for script downloads only!".bright_yellow()
        );
    }

    if cli.auto_execute {
        eprintln!(
            "\n{}\n{}\n{}\n{}\n",
            "WARNING: Auto-execute mode is enabled."
                .yellow()
                .bold(),
            "Scripts classified as SAFE or LOW will run without confirmation."
                .yellow(),
            "Even with sandboxing, a theoretical sandbox escape could compromise the host."
                .yellow(),
            "Consider restricting auto-execute to local models (e.g. --provider ollama).\n\
             Sandbox runs with all capabilities dropped (--cap-drop ALL on Linux)."
                .yellow()
        );
    }

    // Validate URL
    validate_url(url)?;

    // Download the script
    let script = download_script(url, &net_config).await?;

    // Compute SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(script.as_bytes());
    let script_hash = format!("{:x}", hasher.finalize());
    println!("{} {}", "SHA-256:".bold(), script_hash);

    // Load script cache
    let mut script_cache = ScriptCache::load().unwrap_or_default();

    // Check blacklist — hard block
    if script_cache.is_blacklisted(&script_hash) {
        println!(
            "\n{} Script {} is blacklisted. Execution blocked.",
            "⛔".red(),
            &script_hash[..12]
        );
        write_audit_log(
            url,
            &script_hash,
            script.len(),
            0,
            false,
            false,
            "BLACKLISTED",
            "",
            "blocked-blacklist",
            false,
            None,
            &[],
            None,
        );
        return Ok(());
    }

    // Check trusted cache — skip AI review if hash known-safe and URL whitelisted
    if script_cache.is_trusted(&script_hash, url, &config.whitelist_sources) {
        println!(
            "\n{} Cached as trusted (hash {} from whitelisted source). Skipping AI review.",
            "✓".green().bold(),
            &script_hash[..12]
        );
        // Fast-path: execute directly with sandbox
        execute_script(&script, &cli.shell, !cli.no_sandbox)?;
        write_audit_log(
            url,
            &script_hash,
            script.len(),
            0,
            false,
            false,
            "CACHED-SAFE",
            "",
            "auto-trusted",
            !cli.no_sandbox,
            None,
            &[],
            None,
        );
        return Ok(());
    }

    // Run static analysis
    let static_report = static_analyze(&script);
    display_static_report(&static_report);

    // Disable auto-execute if critical findings
    let mut force_no_auto = static_report.has_critical;

    // Format static findings for AI
    let static_findings_text = if !static_report.findings.is_empty() {
        let mut text = String::new();
        for finding in &static_report.findings {
            text.push_str(&format!(
                "\n- {} [{}] {}: {} (line {})",
                finding.category.label(),
                finding.severity.as_str(),
                finding.pattern_id,
                finding.description,
                finding.line_number
            ));
        }
        Some(text)
    } else {
        None
    };

    // Perform AI security analysis
    let (analysis, ai_raw_response) = analyze_script(
        &script,
        &config,
        &net_config,
        static_findings_text.as_deref(),
    )
    .await?;

    // Display results
    display_analysis(&analysis);

    // ── Second opinion ──
    let mut _second_analysis: Option<analysis::SecurityAnalysis> = None;
    if cli.second_opinion {
        let default_second = if config.provider.to_lowercase().contains("openai") {
            "anthropic"
        } else {
            "openai"
        };
        let second_provider_name = cli
            .second_provider
            .as_deref()
            .unwrap_or(default_second);

        match second_opinion_analysis(
            &script,
            &config,
            &net_config,
            static_findings_text.as_deref(),
            second_provider_name,
        )
        .await
        {
            Ok((second, _raw)) => {
                display_second_opinion(&analysis, &second, second_provider_name);

                // On disagreement: inhibit auto-execute if second opinion is higher risk
                if !second.risk_level.is_probably_safe()
                    && analysis.risk_level.is_probably_safe()
                {
                    force_no_auto = true;
                    println!(
                        "{} Auto-execute inhibited: second opinion disagrees.",
                        "⚠".yellow()
                    );
                }

                _second_analysis = Some(second);
            }
            Err(e) => {
                eprintln!(
                    "{} Second opinion failed: {}",
                    "⚠".yellow(),
                    e
                );
            }
        }
    }

    // Validate shell before offering execution
    validate_shell(&cli.shell)?;

    let ai_risk_str = format!("{:?}", analysis.risk_level).to_uppercase();

    // Decide whether to execute
    let should_execute =
        if cli.auto_execute && analysis.risk_level.is_probably_safe() && !force_no_auto {
            println!(
                "\n{}",
                "✓ Auto-executing (classified as safe)".green().bold()
            );
            true
        } else if cli.auto_execute && force_no_auto {
            println!(
                "\n{}",
                "✗ Auto-execute disabled due to critical static findings"
                    .red()
                    .bold()
            );
            // Show hash again before prompting
            println!("{} {}", "SHA-256:".bold(), script_hash);
            prompt_user_confirmation()?
        } else if cli.auto_execute {
            println!(
                "\n{}",
                "✗ Auto-execute disabled due to risk level".red().bold()
            );
            // Show hash again before prompting
            println!("{} {}", "SHA-256:".bold(), script_hash);
            prompt_user_confirmation()?
        } else {
            // Show hash again before prompting
            println!("{} {}", "SHA-256:".bold(), script_hash);
            prompt_user_confirmation()?
        };

    let decision = if should_execute {
        if cli.auto_execute && analysis.risk_level.is_probably_safe() && !force_no_auto {
            "auto-executed"
        } else {
            "user-approved"
        }
    } else {
        "cancelled"
    };

    let sandboxed = !cli.no_sandbox;
    let mut container_result: Option<ContainerResult> = None;
    let mut falco_alerts: Vec<FalcoAlert> = Vec::new();
    let mut runtime_verdict: Option<String> = None;

    if should_execute {
        // Determine whether to use container mode
        let use_container = cli.runtime_container
            && matches!(
                analysis.risk_level,
                RiskLevel::Safe | RiskLevel::Low | RiskLevel::Medium
            );

        if use_container {
            println!(
                "\n{}",
                "Running in Podman container for observation...".cyan()
            );
            let enable_monitor = !cli.no_monitor;
            match execute_in_container(
                &script,
                cli.container_timeout,
                &cli.monitor_level,
                enable_monitor,
            )
            .await
            {
                Ok((result, alerts)) => {
                    display_container_result(&result, &alerts);

                    let was_killed = result.killed_by_monitor;
                    falco_alerts = alerts;
                    container_result = Some(result);

                    // ── Snipe: quarantine + AI re-review on critical alerts ──
                    if was_killed || !falco_alerts.is_empty() {
                        let has_critical_alert = falco_alerts
                            .iter()
                            .any(|a| classify_alert(a) == AlertSeverity::Critical);

                        if has_critical_alert || was_killed {
                            println!(
                                "\n{}",
                                "CRITICAL runtime alert — requesting AI re-review..."
                                    .red()
                                    .bold()
                            );

                            match runtime_ai_review(
                                &script,
                                &ai_risk_str,
                                static_findings_text.as_deref(),
                                container_result.as_ref().unwrap(),
                                &falco_alerts,
                                &config,
                                &net_config,
                            )
                            .await
                            {
                                Ok((re_analysis, raw)) => {
                                    let re_risk = format!(
                                        "{:?}",
                                        re_analysis.risk_level
                                    )
                                    .to_uppercase();

                                    println!(
                                        "\n{} {}",
                                        "Runtime AI verdict:".bold(),
                                        re_risk
                                            .color(re_analysis.risk_level.color())
                                            .bold()
                                    );
                                    for finding in &re_analysis.findings {
                                        println!("  - {}", finding);
                                    }
                                    println!(
                                        "{} {}",
                                        "Recommendation:".bold(),
                                        re_analysis.recommendation
                                    );

                                    runtime_verdict = Some(re_risk.clone());

                                    // Override the audit risk if re-review escalates
                                    let _ = raw; // captured for audit
                                }
                                Err(e) => {
                                    eprintln!(
                                        "{} Runtime AI re-review failed: {}",
                                        "⚠".yellow(),
                                        e
                                    );
                                }
                            }

                            // Quarantine: log as CRITICAL verdict regardless
                            println!(
                                "\n{} Script hash {} quarantined.",
                                "⛔".red(),
                                &script_hash[..12]
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{} Container execution failed: {}. Falling back to sandbox.",
                        "⚠".yellow(),
                        e
                    );
                    execute_script(&script, &cli.shell, !cli.no_sandbox)?;
                }
            }
        } else {
            if cli.runtime_container {
                eprintln!(
                    "{} Risk level {} too high for container mode; using standard sandbox.",
                    "⚠".yellow(),
                    ai_risk_str
                );
            }
            execute_script(&script, &cli.shell, !cli.no_sandbox)?;
        }
    } else {
        println!("\n{}", "Execution cancelled by user".yellow());
    }

    // ── Cache update ──
    if should_execute {
        let has_critical_runtime = runtime_verdict
            .as_deref()
            .map(|v| v == "CRITICAL" || v == "HIGH")
            .unwrap_or(false);
        let was_killed = container_result
            .as_ref()
            .map(|r| r.killed_by_monitor)
            .unwrap_or(false);

        if has_critical_runtime || was_killed {
            // Quarantine: auto-blacklist on critical runtime findings
            script_cache.blacklist(&script_hash);
            if let Err(e) = script_cache.save() {
                eprintln!("{} Failed to save blacklist: {}", "⚠".yellow(), e);
            } else {
                println!(
                    "{} Hash {} added to blacklist.",
                    "⛔".red(),
                    &script_hash[..12]
                );
            }
        } else if cli.auto_trust && analysis.risk_level.is_probably_safe() {
            // Auto-trust: cache as safe
            let runtime_passed = container_result.as_ref().map(|r| !r.timed_out).unwrap_or(true);
            script_cache.insert(CacheEntry {
                sha256: script_hash.clone(),
                verdict: ai_risk_str.clone(),
                source_url: url.to_string(),
                timestamp: current_timestamp(),
                runtime_passed,
                blacklisted: false,
            });
            if let Err(e) = script_cache.save() {
                eprintln!("{} Failed to save cache: {}", "⚠".yellow(), e);
            } else {
                println!(
                    "{} Hash {} cached as trusted.",
                    "✓".green(),
                    &script_hash[..12]
                );
            }
        } else if !cli.auto_trust && analysis.risk_level.is_probably_safe() {
            // Prompt user to cache
            print!(
                "\n{} Cache this script hash as trusted? [y/N] ",
                "?".cyan().bold()
            );
            io::stdout().flush().ok();
            let mut answer = String::new();
            if io::stdin().read_line(&mut answer).is_ok()
                && answer.trim().eq_ignore_ascii_case("y")
            {
                let runtime_passed =
                    container_result.as_ref().map(|r| !r.timed_out).unwrap_or(true);
                script_cache.insert(CacheEntry {
                    sha256: script_hash.clone(),
                    verdict: ai_risk_str.clone(),
                    source_url: url.to_string(),
                    timestamp: current_timestamp(),
                    runtime_passed,
                    blacklisted: false,
                });
                if let Err(e) = script_cache.save() {
                    eprintln!("{} Failed to save cache: {}", "⚠".yellow(), e);
                } else {
                    println!(
                        "{} Hash {} cached as trusted.",
                        "✓".green(),
                        &script_hash[..12]
                    );
                }
            }
        }
    }

    // Write audit log (after execution so container + Falco results are available)
    write_audit_log(
        url,
        &script_hash,
        script.len(),
        static_report.findings.len(),
        static_report.has_critical,
        static_report.has_prompt_injection,
        &ai_risk_str,
        &ai_raw_response,
        decision,
        sandboxed,
        container_result.as_ref(),
        &falco_alerts,
        runtime_verdict.as_deref(),
    );

    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle --blacklist-hash before any command dispatch
    if let Some(ref hash) = cli.blacklist_hash {
        // Validate: must be non-empty hex string (SHA-256 = 64 chars, but allow shorter prefixes)
        let hash_trimmed = hash.trim().to_lowercase();
        if hash_trimmed.is_empty() || !hash_trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "Invalid hash: '{}'. Expected a hexadecimal SHA-256 hash (e.g. a1b2c3d4...).",
                hash
            );
        }
        let mut cache = ScriptCache::load().unwrap_or_default();
        cache.blacklist(&hash_trimmed);
        cache.save().context("Failed to save blacklist")?;
        println!(
            "{} Hash {} added to blacklist.",
            "⛔".red(),
            if hash_trimmed.len() >= 12 {
                &hash_trimmed[..12]
            } else {
                &hash_trimmed
            }
        );
        return Ok(());
    }

    match cli.command {
        Some(Commands::Login) => {
            commands::login_command(
                cli.timeout,
                cli.max_redirects,
                cli.insecure,
                cli.no_proxy,
                cli.proxy.clone(),
                cli.system_proxy,
                cli.user_agent.clone(),
                cli.headers.clone(),
                cli.retries,
            )
            .await
        }
        Some(Commands::Config) => commands::config_command(),
        Some(Commands::Skill) => commands::skill_command(),
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
                println!("  {}      Output openclaw Claude Code skill", "scurl skill".green());
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
    fn test_help_includes_no_sandbox() {
        use clap::CommandFactory;
        let mut buf = Vec::new();
        Cli::command().write_help(&mut buf).unwrap();
        let help_text = String::from_utf8(buf).unwrap();
        assert!(help_text.contains("--no-sandbox"));
    }

    #[test]
    fn test_monitor_level_display() {
        assert_eq!(format!("{}", MonitorLevel::Low), "low");
        assert_eq!(format!("{}", MonitorLevel::Medium), "medium");
        assert_eq!(format!("{}", MonitorLevel::High), "high");
    }
}

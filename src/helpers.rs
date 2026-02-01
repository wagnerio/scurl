use anyhow::{Context, Result};
use colored::*;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use crate::analysis::{parse_analysis, SecurityAnalysis};
use crate::config::Config;
use crate::container::{ContainerResult, FalcoAlert};
use crate::network::NetworkConfig;
use crate::provider::{build_runtime_prompt, Provider};

// ============================================================================
// Core Functions
// ============================================================================

pub(crate) fn retry_delay(attempt: usize) -> Duration {
    // Exponential backoff: 1s, 2s, 4s, 8s... capped at 30s
    let base_delay = 2u64.pow((attempt - 1) as u32);
    let delay_secs = base_delay.min(30);

    // Add jitter using SystemTime to avoid adding rand dependency
    let jitter_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .subsec_nanos()
        % 1000;

    Duration::from_secs(delay_secs) + Duration::from_millis(jitter_ms as u64)
}

pub(crate) fn validate_url(url: &str) -> Result<()> {
    // Reject overly long URLs (8 KB limit)
    if url.len() > 8192 {
        anyhow::bail!("URL too long ({} bytes, max 8192)", url.len());
    }

    let parsed = reqwest::Url::parse(url).context("Invalid URL format")?;

    let scheme = parsed.scheme();
    if !matches!(scheme, "http" | "https") {
        anyhow::bail!(
            "Invalid URL scheme: {}. Only http and https are supported.",
            scheme
        );
    }

    // Reject URLs with no host
    if parsed.host_str().is_none() {
        anyhow::bail!("URL has no host component");
    }

    // Reject URLs with credentials
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!(
            "URLs with embedded credentials are not supported for security reasons"
        );
    }

    // Warn about private/local addresses (SSRF protection)
    if let Some(host) = parsed.host_str() {
        let is_private = host == "localhost"
            || host == "127.0.0.1"
            || host == "::1"
            || host == "[::1]"
            || host == "0.0.0.0"
            || host.starts_with("10.")
            || host.starts_with("192.168.")
            || host.starts_with("172.16.")
            || host.starts_with("172.17.")
            || host.starts_with("172.18.")
            || host.starts_with("172.19.")
            || host.starts_with("172.2")
            || host.starts_with("172.30.")
            || host.starts_with("172.31.")
            || host.starts_with("169.254.")
            || host.starts_with("fd")
            || host.starts_with("fe80:");

        if is_private {
            eprintln!(
                "{} Downloading from private/local address: {}",
                "⚠".yellow(),
                host
            );
        }
    }

    Ok(())
}

pub(crate) fn validate_shell(shell: &str) -> Result<()> {
    const ALLOWED_SHELLS: &[&str] = &["bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh"];

    let shell_name = Path::new(shell)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(shell);

    if !ALLOWED_SHELLS.contains(&shell_name) {
        anyhow::bail!(
            "Unknown shell: '{}'. Allowed shells: {}",
            shell,
            ALLOWED_SHELLS.join(", ")
        );
    }

    // If it's an absolute path, verify it exists
    if shell.contains('/') || shell.contains('\\') {
        let path = Path::new(shell);
        if !path.exists() {
            anyhow::bail!("Shell binary not found: {}", shell);
        }
    } else {
        // For bare names, verify via `which`
        let result = Command::new("which")
            .arg(shell)
            .output()
            .context("Failed to locate shell binary")?;
        if !result.status.success() {
            anyhow::bail!(
                "Shell '{}' not found on this system. Is it installed?",
                shell
            );
        }
    }

    Ok(())
}

pub(crate) fn command_exists(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub(crate) fn new_spinner(msg: &str) -> ProgressBar {
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

pub(crate) fn prompt(message: &str) -> Result<String> {
    print!("{}", message.bright_white().bold());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

pub(crate) fn prompt_user_confirmation() -> Result<bool> {
    print!("\n{} ", "Execute this script? [y/N]:".yellow().bold());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

pub(crate) async fn download_script(url: &str, net_config: &NetworkConfig) -> Result<String> {
    let spinner = new_spinner("Downloading script...");

    let client = &net_config.script_client;
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
            tokio::time::sleep(retry_delay(attempt)).await;
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

                // Check content type - block dangerous types
                if let Some(content_type) = response.headers().get("content-type") {
                    let ct = content_type.to_str().unwrap_or("");

                    // Blocklist: definitely not scripts
                    let blocked_types = [
                        "image/",
                        "video/",
                        "audio/",
                        "application/pdf",
                        "application/zip",
                        "application/gzip",
                        "application/x-executable",
                        "application/x-mach-binary",
                    ];

                    for blocked in &blocked_types {
                        if ct.contains(blocked) {
                            spinner.finish_and_clear();
                            anyhow::bail!(
                                "Blocked content type: {}. This doesn't appear to be a script.",
                                ct
                            );
                        }
                    }

                    // Allowlist check
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
                const MAX_SCRIPT_SIZE: usize = 10 * 1024 * 1024;

                // Check Content-Length header first for early rejection
                if let Some(len) = response.content_length() {
                    if len > MAX_SCRIPT_SIZE as u64 {
                        spinner.finish_and_clear();
                        anyhow::bail!(
                            "Script too large ({:.1} MB). Max allowed: {:.0} MB",
                            len as f64 / 1_048_576.0,
                            MAX_SCRIPT_SIZE as f64 / 1_048_576.0
                        );
                    }
                }

                // Stream download with size limit
                let mut body = Vec::new();
                let mut stream = response.bytes_stream();
                let mut stream_error = None;

                while let Some(chunk) = stream.next().await {
                    match chunk {
                        Ok(bytes) => {
                            if body.len() + bytes.len() > MAX_SCRIPT_SIZE {
                                spinner.finish_and_clear();
                                anyhow::bail!(
                                    "Script too large (exceeded {:.0} MB during download)",
                                    MAX_SCRIPT_SIZE as f64 / 1_048_576.0
                                );
                            }
                            body.extend_from_slice(&bytes);
                        }
                        Err(e) => {
                            stream_error = Some(anyhow::Error::from(e));
                            break;
                        }
                    }
                }

                // Check if stream had an error
                if let Some(e) = stream_error {
                    last_error = Some(e);
                    continue;
                }

                // Convert to UTF-8 string
                match String::from_utf8(body) {
                    Ok(script) => {
                        if script.is_empty() {
                            spinner.finish_and_clear();
                            anyhow::bail!("Downloaded script is empty");
                        }

                        // Reject scripts containing null bytes
                        if script.contains('\0') {
                            spinner.finish_and_clear();
                            anyhow::bail!(
                                "Downloaded script contains null bytes. Valid shell scripts should not contain null bytes — this may indicate a binary or corrupted file."
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
                        spinner.finish_and_clear();
                        anyhow::bail!("Downloaded content is not valid UTF-8: {}", e);
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

pub(crate) async fn analyze_script(
    script: &str,
    config: &Config,
    net_config: &NetworkConfig,
    static_findings: Option<&str>,
) -> Result<(SecurityAnalysis, String)> {
    let provider: Provider = config.provider.parse()?;
    let spinner = new_spinner(&format!("Analyzing script with {} AI...", provider.name()));

    // Perform analysis
    let response_text = provider
        .analyze(
            script,
            &config.api_key,
            config.model.as_deref(),
            net_config,
            static_findings,
            config,
        )
        .await?;

    spinner.finish_with_message(format!("{} Analysis complete!", "✓".green()));

    let analysis = parse_analysis(&response_text)?;
    Ok((analysis, response_text))
}

/// Run second-opinion analysis with a different provider.
pub(crate) async fn second_opinion_analysis(
    script: &str,
    config: &Config,
    net_config: &NetworkConfig,
    static_findings: Option<&str>,
    second_provider_name: &str,
) -> Result<(SecurityAnalysis, String)> {
    let provider: Provider = second_provider_name.parse()?;
    let spinner = new_spinner(&format!(
        "Second opinion from {} AI...",
        provider.name()
    ));

    // Second opinion needs its own API key — try env var SCURL_SECOND_API_KEY
    let api_key = std::env::var("SCURL_SECOND_API_KEY").unwrap_or_else(|_| config.api_key.clone());

    let response_text = provider
        .analyze(
            script,
            &api_key,
            None, // use default model for second provider
            net_config,
            static_findings,
            config,
        )
        .await?;

    spinner.finish_with_message(format!("{} Second opinion complete!", "✓".green()));

    let analysis = parse_analysis(&response_text)?;
    Ok((analysis, response_text))
}

/// Display second opinion alongside primary analysis.
pub(crate) fn display_second_opinion(primary: &SecurityAnalysis, second: &SecurityAnalysis, second_provider: &str) {
    println!(
        "\n{} {}",
        "Second Opinion".bold().underline(),
        format!("({})", second_provider).bright_black()
    );

    let agree = primary.risk_level == second.risk_level;
    let second_risk = format!("{:?}", second.risk_level).to_uppercase();

    println!(
        "  {} {}  {} {}",
        "Risk Level:".bold(),
        second_risk.color(second.risk_level.color()).bold(),
        "Confidence:".bold(),
        format!("{}%", second.confidence)
            .color(if second.confidence >= 80 {
                Color::Green
            } else if second.confidence >= 60 {
                Color::Yellow
            } else {
                Color::Red
            })
            .bold()
    );

    if !second.findings.is_empty() {
        println!("  {}", "Findings:".bold());
        for finding in &second.findings {
            println!("    - {}", finding);
        }
    }

    if agree {
        println!(
            "\n  {} Both providers agree: {}",
            "✓".green(),
            second_risk.color(second.risk_level.color()).bold()
        );
    } else {
        let primary_risk = format!("{:?}", primary.risk_level).to_uppercase();
        println!(
            "\n  {} Disagreement: primary says {}, second says {}",
            "⚠".yellow(),
            primary_risk.color(primary.risk_level.color()),
            second_risk.color(second.risk_level.color())
        );
        // On disagreement, recommend manual review
        println!(
            "  {} Consider manual review before executing.",
            "ℹ".bright_black()
        );
    }
}

/// Build a runtime analysis prompt combining static + runtime evidence and
/// send it to the AI provider for a re-verdict.
pub(crate) async fn runtime_ai_review(
    script: &str,
    static_risk: &str,
    static_findings: Option<&str>,
    container: &ContainerResult,
    alerts: &[FalcoAlert],
    config: &Config,
    net_config: &NetworkConfig,
) -> Result<(SecurityAnalysis, String)> {
    let provider: Provider = config.provider.parse()?;
    let spinner = new_spinner(&format!(
        "Runtime re-review with {} AI...",
        provider.name()
    ));

    // Truncate script to first 200 lines for prompt size
    let script_truncated: String = script
        .lines()
        .take(200)
        .collect::<Vec<_>>()
        .join("\n")
        .replace("```", "\\`\\`\\`");

    let prompt = build_runtime_prompt(
        &script_truncated,
        static_risk,
        static_findings,
        container,
        alerts,
    );

    let response_text = provider
        .send_prompt(
            &prompt,
            &config.api_key,
            config.model.as_deref(),
            net_config,
            config,
        )
        .await?;

    spinner.finish_with_message(format!("{} Runtime re-review complete!", "✓".green()));

    let analysis = parse_analysis(&response_text)?;
    Ok((analysis, response_text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::RiskLevel;

    #[test]
    fn test_url_validation_valid() {
        assert!(validate_url("https://example.com/script.sh").is_ok());
        assert!(validate_url("http://example.com/script.sh").is_ok());
    }

    #[test]
    fn test_url_validation_invalid_scheme() {
        assert!(validate_url("file:///etc/passwd").is_err());
        assert!(validate_url("ftp://example.com/script.sh").is_err());
        assert!(validate_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_url_validation_malformed() {
        assert!(validate_url("not a url").is_err());
        assert!(validate_url("://missing-scheme").is_err());
    }

    #[test]
    fn test_validate_shell_known() {
        // "sh" is universally available
        assert!(validate_shell("sh").is_ok());
        assert!(validate_shell("bash").is_ok());
    }

    #[test]
    fn test_validate_shell_unknown() {
        assert!(validate_shell("powershell").is_err());
        assert!(validate_shell("cmd").is_err());
        assert!(validate_shell("/tmp/evil-shell").is_err());
        assert!(validate_shell("node").is_err());
    }

    #[test]
    fn test_null_byte_detection() {
        // Simulate what download_script would reject
        let content = "#!/bin/bash\necho hello\0world";
        assert!(content.contains('\0'));
    }

    #[test]
    fn test_display_second_opinion_agree_no_panic() {
        let primary = SecurityAnalysis {
            risk_level: RiskLevel::Safe,
            confidence: 90,
            findings: vec!["No issues".to_string()],
            recommendation: "Safe.".to_string(),
        };
        let second = SecurityAnalysis {
            risk_level: RiskLevel::Safe,
            confidence: 85,
            findings: vec!["Clean script".to_string()],
            recommendation: "Safe.".to_string(),
        };
        // Should not panic
        display_second_opinion(&primary, &second, "openai");
    }

    #[test]
    fn test_display_second_opinion_disagree_no_panic() {
        let primary = SecurityAnalysis {
            risk_level: RiskLevel::Safe,
            confidence: 80,
            findings: vec!["No issues".to_string()],
            recommendation: "Safe.".to_string(),
        };
        let second = SecurityAnalysis {
            risk_level: RiskLevel::High,
            confidence: 75,
            findings: vec!["Suspicious pattern".to_string()],
            recommendation: "Do not run.".to_string(),
        };
        display_second_opinion(&primary, &second, "anthropic");
    }

    // --- URL validation hardening ---

    #[test]
    fn test_url_validation_file_scheme_rejected() {
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_url_validation_ftp_scheme_rejected() {
        assert!(validate_url("ftp://example.com/script.sh").is_err());
    }

    #[test]
    fn test_url_validation_data_scheme_rejected() {
        assert!(validate_url("data:text/plain;base64,IyEvYmluL2Jhc2g=").is_err());
    }

    #[test]
    fn test_url_validation_javascript_scheme_rejected() {
        assert!(validate_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_url_validation_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(9000));
        assert!(validate_url(&long_url).is_err());
    }

    #[test]
    fn test_url_validation_embedded_credentials_rejected() {
        assert!(validate_url("https://user:pass@example.com/script.sh").is_err());
    }

    #[test]
    fn test_url_validation_localhost_warns_but_succeeds() {
        // Should succeed (just warns)
        assert!(validate_url("http://localhost:8080/script.sh").is_ok());
    }

    #[test]
    fn test_url_validation_ipv6_loopback() {
        // parse may vary, but scheme check should pass
        assert!(validate_url("http://[::1]/script.sh").is_ok());
    }

    #[test]
    fn test_url_validation_private_172_range() {
        assert!(validate_url("http://172.16.0.1/script.sh").is_ok()); // warns, succeeds
    }

    #[test]
    fn test_url_validation_valid_https() {
        assert!(validate_url("https://raw.githubusercontent.com/user/repo/main/install.sh").is_ok());
    }
}

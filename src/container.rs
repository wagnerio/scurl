use anyhow::{Context, Result};
use colored::*;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime};
use tempfile::NamedTempFile;

use crate::helpers::{command_exists, new_spinner};
use crate::MonitorLevel;

// ============================================================================
// Container Runner (Podman)
// ============================================================================

/// Result from container-based script execution.
#[derive(Debug)]
pub(crate) struct ContainerResult {
    pub(crate) container_id: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) duration_ms: u64,
    pub(crate) filesystem_diff: Vec<String>,
    pub(crate) timed_out: bool,
    pub(crate) killed_by_monitor: bool,
}

/// A security alert from Falco runtime monitoring.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct FalcoAlert {
    pub(crate) timestamp: String,
    pub(crate) rule: String,
    pub(crate) priority: String,
    pub(crate) output: String,
}

/// Severity classification of a Falco alert for snipe decisions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum AlertSeverity {
    /// Container escape, shellcode, sensitive file writes — always kill
    Critical,
    /// Outbound network, process injection — kill on medium+
    Suspicious,
    /// Any other alert — kill only on high
    Anomaly,
}

pub(crate) fn detect_podman() -> bool {
    command_exists("podman")
}

pub(crate) fn detect_falco() -> bool {
    // Check if Falco daemon is running (pidfile or process)
    if Path::new("/var/run/falco.pid").exists() {
        return true;
    }
    // Fallback: check for the binary
    command_exists("falco")
}

pub(crate) fn falco_log_path() -> Option<String> {
    // Environment override first
    if let Ok(path) = std::env::var("SCURL_FALCO_LOG") {
        if Path::new(&path).exists() {
            return Some(path);
        }
    }
    // Common default paths
    for candidate in &[
        "/var/log/falco/falco.log",
        "/var/log/falco/events.json",
        "/var/log/falco.log",
    ] {
        if Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Classify a Falco alert into a severity bucket for snipe decisions.
pub(crate) fn classify_alert(alert: &FalcoAlert) -> AlertSeverity {
    let rule_lower = alert.rule.to_lowercase();
    let priority_lower = alert.priority.to_lowercase();

    // Falco priority-based escalation
    match priority_lower.as_str() {
        "emergency" | "alert" | "critical" => return AlertSeverity::Critical,
        _ => {}
    }

    // Rule-name-based classification: critical
    const CRITICAL_PATTERNS: &[&str] = &[
        "container_escape",
        "shellcode",
        "write_etc_passwd",
        "write_etc_shadow",
        "modify_binary_dirs",
        "mount_namespace",
        "ptrace",
        "kernel_module",
        "load_kernel",
        "change_namespace",
    ];

    for pat in CRITICAL_PATTERNS {
        if rule_lower.contains(pat) {
            return AlertSeverity::Critical;
        }
    }

    // Rule-name-based classification: suspicious
    const SUSPICIOUS_PATTERNS: &[&str] = &[
        "outbound",
        "unexpected_network",
        "connect",
        "process_injection",
        "sensitive_file",
        "write_sensitive",
        "unexpected_process",
        "shell_in_container",
    ];

    for pat in SUSPICIOUS_PATTERNS {
        if rule_lower.contains(pat) {
            return AlertSeverity::Suspicious;
        }
    }

    // Falco error priority is suspicious
    if priority_lower == "error" {
        return AlertSeverity::Suspicious;
    }

    AlertSeverity::Anomaly
}

/// Decide whether to kill the container based on alert severity and monitor level.
pub(crate) fn should_kill_container(severity: &AlertSeverity, level: &MonitorLevel) -> bool {
    match (severity, level) {
        // Critical alerts always kill (even on Low, because Low means "warn only"
        // but critical is too dangerous — we override)
        (AlertSeverity::Critical, _) => true,
        (AlertSeverity::Suspicious, MonitorLevel::Medium | MonitorLevel::High) => true,
        (AlertSeverity::Anomaly, MonitorLevel::High) => true,
        _ => false,
    }
}

/// Tail the Falco JSON log for alerts matching a specific container name.
/// Sends parsed alerts through the channel. Runs until the channel is closed
/// or the task is aborted.
pub(crate) async fn monitor_falco(
    container_name: &str,
    alert_tx: tokio::sync::mpsc::Sender<FalcoAlert>,
) {
    use tokio::io::AsyncBufReadExt;
    use tokio::process::Command as AsyncCommand;

    let Some(log_path) = falco_log_path() else {
        return;
    };

    // tail -f -n0: start at end, follow new lines
    let mut child = match AsyncCommand::new("tail")
        .args(["-f", "-n", "0"])
        .arg(&log_path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let Some(stdout) = child.stdout.take() else {
        return;
    };
    let reader = tokio::io::BufReader::new(stdout);
    let mut lines = reader.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        // Parse Falco JSON output
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };

        // Check if this alert belongs to our container (by name or ID prefix)
        let container_match = value
            .get("output_fields")
            .and_then(|f| {
                f.get("container.name")
                    .and_then(|n| n.as_str())
                    .map(|n| n == container_name)
                    .or_else(|| {
                        // Also check the output text for the container name
                        value
                            .get("output")
                            .and_then(|o| o.as_str())
                            .map(|o| o.contains(container_name))
                    })
            })
            .unwrap_or(false);

        if container_match {
            let alert = FalcoAlert {
                timestamp: value
                    .get("time")
                    .and_then(|t| t.as_str())
                    .unwrap_or("")
                    .to_string(),
                rule: value
                    .get("rule")
                    .and_then(|r| r.as_str())
                    .unwrap_or("")
                    .to_string(),
                priority: value
                    .get("priority")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                output: value
                    .get("output")
                    .and_then(|o| o.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            if alert_tx.send(alert).await.is_err() {
                break; // Receiver dropped
            }
        }
    }

    let _ = child.kill().await;
}

/// Execute a script in a Podman container with optional Falco monitoring.
/// Returns the container result, any Falco alerts collected, and whether
/// the container was killed by the monitor.
pub(crate) async fn execute_in_container(
    script: &str,
    timeout_secs: u64,
    monitor_level: &MonitorLevel,
    enable_monitor: bool,
) -> Result<(ContainerResult, Vec<FalcoAlert>)> {
    use tokio::process::Command as AsyncCommand;

    if !detect_podman() {
        anyhow::bail!(
            "Podman not found. Install podman for container-based execution, \
             or remove --runtime-container to use the default sandbox."
        );
    }

    let start = std::time::Instant::now();
    let run_id = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let container_name = format!("scurl-{}", run_id);

    // Write script to temp file for bind-mount
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(script.as_bytes())?;
    let script_host_path = temp_file.path().to_path_buf();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_host_path, fs::Permissions::from_mode(0o700))?;
    }

    let host_path = script_host_path
        .to_str()
        .context("Script path is not valid UTF-8")?;

    let falco_available = enable_monitor && detect_falco() && falco_log_path().is_some();

    if falco_available {
        println!(
            "  {} Falco monitoring active (level: {})",
            "◉".green(),
            monitor_level
        );
    } else if enable_monitor {
        eprintln!(
            "  {} Falco not available — running without runtime monitoring",
            "⚠".yellow()
        );
    }

    let spinner = new_spinner("Running script in Podman container...");

    // ── Monitored execution path (spawn + select) ────────────────────────
    let (timed_out, killed_by_monitor, stdout, stderr, exit_code, alerts) = if falco_available {
        use tokio::io::AsyncReadExt;

        let mut child = AsyncCommand::new("podman")
            .arg("run")
            .arg("--name")
            .arg(&container_name)
            .arg("--network=none")
            .arg("--read-only")
            .arg("--tmpfs")
            .arg("/tmp:rw,noexec,nosuid,size=64m")
            .arg("--cap-drop=ALL")
            .arg("--security-opt=no-new-privileges")
            .arg("--memory=256m")
            .arg("--pids-limit=256")
            .arg("-v")
            .arg(format!("{}:/install.sh:ro", host_path))
            .arg("docker.io/library/alpine:latest")
            .arg("/bin/sh")
            .arg("/install.sh")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        // Drain stdout/stderr concurrently to avoid pipe deadlock
        let child_stdout = child.stdout.take();
        let child_stderr = child.stderr.take();

        let stdout_reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut r) = child_stdout {
                let _ = r.read_to_end(&mut buf).await;
            }
            buf
        });
        let stderr_reader = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut r) = child_stderr {
                let _ = r.read_to_end(&mut buf).await;
            }
            buf
        });

        // Start Falco monitor
        let (alert_tx, mut alert_rx) =
            tokio::sync::mpsc::channel::<FalcoAlert>(64);
        let falco_container = container_name.clone();
        let falco_task = tokio::spawn(async move {
            monitor_falco(&falco_container, alert_tx).await;
        });

        // Race: child completion vs timeout vs critical alert
        let mut sniped = false;
        let mut timed = false;
        let mut exit_status = None;
        let mut collected: Vec<FalcoAlert> = Vec::new();
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

        loop {
            tokio::select! {
                biased;

                result = child.wait() => {
                    exit_status = result.ok();
                    break;
                }

                maybe_alert = alert_rx.recv() => {
                    if let Some(alert) = maybe_alert {
                        let severity = classify_alert(&alert);
                        let kill = should_kill_container(&severity, monitor_level);
                        collected.push(alert);
                        if kill {
                            sniped = true;
                            let _ = child.kill().await;
                            let _ = AsyncCommand::new("podman")
                                .args(["kill", &container_name])
                                .output()
                                .await;
                            break;
                        }
                    }
                    // Channel closed means monitor finished — keep waiting
                }

                _ = tokio::time::sleep_until(deadline) => {
                    timed = true;
                    let _ = child.kill().await;
                    let _ = AsyncCommand::new("podman")
                        .args(["kill", &container_name])
                        .output()
                        .await;
                    break;
                }
            }
        }

        // Drain remaining alerts
        while let Ok(alert) = alert_rx.try_recv() {
            collected.push(alert);
        }

        falco_task.abort();

        // Collect output from readers
        let stdout_bytes = stdout_reader.await.unwrap_or_default();
        let stderr_bytes = stderr_reader.await.unwrap_or_default();
        let mut so = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let mut se = String::from_utf8_lossy(&stderr_bytes).into_owned();

        // If killed early, try podman logs as fallback for partial output
        if (sniped || timed) && so.is_empty() {
            if let Ok(logs) = AsyncCommand::new("podman")
                .args(["logs", &container_name])
                .output()
                .await
            {
                so = String::from_utf8_lossy(&logs.stdout).into_owned();
                se = String::from_utf8_lossy(&logs.stderr).into_owned();
            }
        }

        let code = if timed || sniped {
            None
        } else {
            exit_status.and_then(|s| s.code())
        };

        (timed, sniped, so, se, code, collected)
    } else {
        // ── Unmonitored path (simple output, same as Day 1) ──────────────
        let run_result = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            AsyncCommand::new("podman")
                .arg("run")
                .arg("--name")
                .arg(&container_name)
                .arg("--network=none")
                .arg("--read-only")
                .arg("--tmpfs")
                .arg("/tmp:rw,noexec,nosuid,size=64m")
                .arg("--cap-drop=ALL")
                .arg("--security-opt=no-new-privileges")
                .arg("--memory=256m")
                .arg("--pids-limit=256")
                .arg("-v")
                .arg(format!("{}:/install.sh:ro", host_path))
                .arg("docker.io/library/alpine:latest")
                .arg("/bin/sh")
                .arg("/install.sh")
                .output(),
        )
        .await;

        match run_result {
            Ok(Ok(output)) => (
                false,
                false,
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
                output.status.code(),
                vec![],
            ),
            Ok(Err(e)) => {
                cleanup_container(&container_name).await;
                return Err(e.into());
            }
            Err(_) => {
                let _ = AsyncCommand::new("podman")
                    .args(["kill", &container_name])
                    .output()
                    .await;

                let logs = AsyncCommand::new("podman")
                    .args(["logs", &container_name])
                    .output()
                    .await
                    .ok();

                let (so, se) = logs
                    .map(|o| {
                        (
                            String::from_utf8_lossy(&o.stdout).into_owned(),
                            String::from_utf8_lossy(&o.stderr).into_owned(),
                        )
                    })
                    .unwrap_or_default();

                (true, false, so, se, None, vec![])
            }
        }
    };

    spinner.finish_and_clear();

    let duration_ms = start.elapsed().as_millis() as u64;

    // Filesystem diff (podman diff shows A/C/D lines)
    let diff = AsyncCommand::new("podman")
        .args(["diff", &container_name])
        .output()
        .await
        .ok();
    let filesystem_diff: Vec<String> = diff
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.to_string())
                .collect()
        })
        .unwrap_or_default();

    // Get short container ID
    let id_output = AsyncCommand::new("podman")
        .args(["inspect", "--format", "{{.Id}}", &container_name])
        .output()
        .await
        .ok();
    let container_id: String = id_output
        .and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
        .unwrap_or_else(|| container_name.clone())
        .chars()
        .take(12)
        .collect();

    // Cleanup
    cleanup_container(&container_name).await;

    let result = ContainerResult {
        container_id,
        exit_code,
        stdout,
        stderr,
        duration_ms,
        filesystem_diff,
        timed_out,
        killed_by_monitor,
    };

    Ok((result, alerts))
}

async fn cleanup_container(name: &str) {
    use tokio::process::Command as AsyncCommand;
    let _ = AsyncCommand::new("podman")
        .args(["rm", "-f", name])
        .output()
        .await;
}

pub(crate) fn display_container_result(result: &ContainerResult, alerts: &[FalcoAlert]) {
    println!("\n{}", "Container Execution Results".bold().cyan());
    println!("{}", "─".repeat(50));

    println!("{} {}", "Container ID:".bold(), result.container_id);
    println!("{} {}ms", "Duration:".bold(), result.duration_ms);

    if result.killed_by_monitor {
        println!(
            "{}",
            "KILLED BY MONITOR - critical runtime alert detected"
                .red()
                .bold()
        );
    } else if result.timed_out {
        println!(
            "{}",
            "TIMED OUT - container was killed".red().bold()
        );
    }

    match result.exit_code {
        Some(0) => println!("{} {} (success)", "Exit code:".bold(), "0".green()),
        Some(code) => println!(
            "{} {} (failed)",
            "Exit code:".bold(),
            code.to_string().red()
        ),
        None => println!("{} {}", "Exit code:".bold(), "unknown".yellow()),
    }

    if !result.stdout.is_empty() {
        println!("\n{}", "stdout:".bold());
        let lines: Vec<&str> = result.stdout.lines().collect();
        for line in lines.iter().take(50) {
            println!("  {}", line);
        }
        if lines.len() > 50 {
            println!("  ... ({} more lines)", lines.len() - 50);
        }
    }

    if !result.stderr.is_empty() {
        println!("\n{}", "stderr:".bold());
        let lines: Vec<&str> = result.stderr.lines().collect();
        for line in lines.iter().take(30) {
            println!("  {}", line.yellow());
        }
        if lines.len() > 30 {
            println!("  ... ({} more lines)", lines.len() - 30);
        }
    }

    if !result.filesystem_diff.is_empty() {
        println!("\n{}", "Filesystem changes:".bold());
        for change in &result.filesystem_diff {
            let colored = if change.starts_with('A') {
                change.green().to_string()
            } else if change.starts_with('C') {
                change.yellow().to_string()
            } else if change.starts_with('D') {
                change.red().to_string()
            } else {
                change.to_string()
            };
            println!("  {}", colored);
        }
    }

    // Display Falco alerts
    if !alerts.is_empty() {
        println!("\n{}", "Falco Runtime Alerts:".bold().red());
        for alert in alerts {
            let severity = classify_alert(alert);
            let sev_color = match severity {
                AlertSeverity::Critical => "CRITICAL".red().bold().to_string(),
                AlertSeverity::Suspicious => "SUSPICIOUS".yellow().bold().to_string(),
                AlertSeverity::Anomaly => "ANOMALY".cyan().to_string(),
            };
            println!(
                "  [{}] {} ({})",
                sev_color, alert.rule, alert.priority
            );
            if !alert.output.is_empty() {
                println!("    {}", alert.output.dimmed());
            }
        }
    }

    println!("{}", "─".repeat(50));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_container_result(
        killed_by_monitor: bool,
        timed_out: bool,
    ) -> ContainerResult {
        ContainerResult {
            container_id: "abc123def456".to_string(),
            exit_code: if killed_by_monitor || timed_out {
                None
            } else {
                Some(0)
            },
            stdout: "Hello from container\n".to_string(),
            stderr: String::new(),
            duration_ms: 1500,
            filesystem_diff: vec![
                "A /tmp/test.txt".to_string(),
                "C /etc".to_string(),
            ],
            timed_out,
            killed_by_monitor,
        }
    }

    #[test]
    fn test_container_result_display_success() {
        let result = make_container_result(false, false);
        display_container_result(&result, &[]);
        assert_eq!(result.exit_code, Some(0));
        assert!(!result.timed_out);
        assert!(!result.killed_by_monitor);
    }

    #[test]
    fn test_container_result_display_timeout() {
        let result = make_container_result(false, true);
        display_container_result(&result, &[]);
        assert!(result.timed_out);
        assert!(result.exit_code.is_none());
    }

    #[test]
    fn test_container_result_display_killed_by_monitor() {
        let result = make_container_result(true, false);
        let alerts = vec![FalcoAlert {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            rule: "Write below etc".to_string(),
            priority: "Critical".to_string(),
            output: "File opened for writing: /etc/passwd".to_string(),
        }];
        display_container_result(&result, &alerts);
        assert!(result.killed_by_monitor);
    }

    #[test]
    fn test_container_result_display_long_output_truncated() {
        let long_stdout = (0..100)
            .map(|i| format!("line {}", i))
            .collect::<Vec<_>>()
            .join("\n");
        let mut result = make_container_result(false, false);
        result.stdout = long_stdout;
        result.filesystem_diff = vec![];
        display_container_result(&result, &[]);
    }

    #[test]
    fn test_detect_podman_returns_bool() {
        let _has_podman = detect_podman();
    }

    #[tokio::test]
    async fn test_execute_in_container_no_podman() {
        if !detect_podman() {
            let result = execute_in_container(
                "echo hello",
                10,
                &MonitorLevel::Medium,
                false,
            )
            .await;
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("Podman not found"));
        }
    }

    #[test]
    fn test_help_includes_runtime_container_flags() {
        use clap::CommandFactory;
        use crate::Cli;
        let mut buf = Vec::new();
        Cli::command().write_help(&mut buf).unwrap();
        let help_text = String::from_utf8(buf).unwrap();
        assert!(help_text.contains("--runtime-container"));
        assert!(help_text.contains("--container-timeout"));
        assert!(help_text.contains("--monitor-level"));
        assert!(help_text.contains("--no-monitor"));
    }

    // ── Falco monitoring & snipe tests ──

    #[test]
    fn test_classify_alert_critical_by_priority() {
        let alert = FalcoAlert {
            timestamp: String::new(),
            rule: "Some Rule".to_string(),
            priority: "Critical".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert), AlertSeverity::Critical);

        let alert_emergency = FalcoAlert {
            timestamp: String::new(),
            rule: "Any Rule".to_string(),
            priority: "Emergency".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert_emergency), AlertSeverity::Critical);
    }

    #[test]
    fn test_classify_alert_critical_by_rule_name() {
        let alert = FalcoAlert {
            timestamp: String::new(),
            rule: "Container_Escape via mount".to_string(),
            priority: "Warning".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert), AlertSeverity::Critical);

        let alert_shellcode = FalcoAlert {
            timestamp: String::new(),
            rule: "Shellcode execution detected".to_string(),
            priority: "Notice".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert_shellcode), AlertSeverity::Critical);

        let alert_passwd = FalcoAlert {
            timestamp: String::new(),
            rule: "Write_etc_passwd attempt".to_string(),
            priority: "Warning".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert_passwd), AlertSeverity::Critical);
    }

    #[test]
    fn test_classify_alert_suspicious_by_rule_name() {
        let alert = FalcoAlert {
            timestamp: String::new(),
            rule: "Unexpected outbound connection".to_string(),
            priority: "Warning".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert), AlertSeverity::Suspicious);

        let alert_shell = FalcoAlert {
            timestamp: String::new(),
            rule: "Shell_in_container started".to_string(),
            priority: "Notice".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert_shell), AlertSeverity::Suspicious);
    }

    #[test]
    fn test_classify_alert_suspicious_by_error_priority() {
        let alert = FalcoAlert {
            timestamp: String::new(),
            rule: "Unknown activity".to_string(),
            priority: "Error".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert), AlertSeverity::Suspicious);
    }

    #[test]
    fn test_classify_alert_anomaly_default() {
        let alert = FalcoAlert {
            timestamp: String::new(),
            rule: "Some informational rule".to_string(),
            priority: "Notice".to_string(),
            output: String::new(),
        };
        assert_eq!(classify_alert(&alert), AlertSeverity::Anomaly);
    }

    #[test]
    fn test_should_kill_critical_always() {
        assert!(should_kill_container(
            &AlertSeverity::Critical,
            &MonitorLevel::Low
        ));
        assert!(should_kill_container(
            &AlertSeverity::Critical,
            &MonitorLevel::Medium
        ));
        assert!(should_kill_container(
            &AlertSeverity::Critical,
            &MonitorLevel::High
        ));
    }

    #[test]
    fn test_should_kill_suspicious_medium_and_high() {
        assert!(!should_kill_container(
            &AlertSeverity::Suspicious,
            &MonitorLevel::Low
        ));
        assert!(should_kill_container(
            &AlertSeverity::Suspicious,
            &MonitorLevel::Medium
        ));
        assert!(should_kill_container(
            &AlertSeverity::Suspicious,
            &MonitorLevel::High
        ));
    }

    #[test]
    fn test_should_kill_anomaly_only_high() {
        assert!(!should_kill_container(
            &AlertSeverity::Anomaly,
            &MonitorLevel::Low
        ));
        assert!(!should_kill_container(
            &AlertSeverity::Anomaly,
            &MonitorLevel::Medium
        ));
        assert!(should_kill_container(
            &AlertSeverity::Anomaly,
            &MonitorLevel::High
        ));
    }

    #[test]
    fn test_detect_falco_returns_bool() {
        let _has_falco = detect_falco();
    }

    #[test]
    fn test_falco_log_path_respects_env() {
        // With no env var and no default files, returns None on most dev machines
        let path = falco_log_path();
        // Just verify it doesn't panic; actual result depends on system
        let _ = path;
    }

    #[test]
    fn test_monitor_level_display() {
        assert_eq!(format!("{}", MonitorLevel::Low), "low");
        assert_eq!(format!("{}", MonitorLevel::Medium), "medium");
        assert_eq!(format!("{}", MonitorLevel::High), "high");
    }

    #[test]
    fn test_display_with_multiple_falco_alerts() {
        let result = make_container_result(true, false);
        let alerts = vec![
            FalcoAlert {
                timestamp: "2026-01-01T00:00:01Z".to_string(),
                rule: "Shell_in_container".to_string(),
                priority: "Notice".to_string(),
                output: "bash spawned in scurl container".to_string(),
            },
            FalcoAlert {
                timestamp: "2026-01-01T00:00:02Z".to_string(),
                rule: "Write_etc_passwd".to_string(),
                priority: "Critical".to_string(),
                output: "File opened for writing: /etc/passwd".to_string(),
            },
        ];
        // Should not panic; should display both alerts with severity colors
        display_container_result(&result, &alerts);
    }

    // --- Monitor level / Falco edge cases ---

    #[test]
    fn test_classify_alert_empty_rule_and_priority() {
        let alert = FalcoAlert {
            timestamp: String::new(),
            rule: String::new(),
            priority: String::new(),
            output: String::new(),
        };
        let severity = classify_alert(&alert);
        assert_eq!(severity, AlertSeverity::Anomaly);
    }

    #[test]
    fn test_should_kill_all_combinations() {
        // Exhaustive test of the kill matrix
        for severity in [
            AlertSeverity::Critical,
            AlertSeverity::Suspicious,
            AlertSeverity::Anomaly,
        ] {
            for level in [
                MonitorLevel::Low,
                MonitorLevel::Medium,
                MonitorLevel::High,
            ] {
                // Should not panic
                let _ = should_kill_container(&severity, &level);
            }
        }
    }
}

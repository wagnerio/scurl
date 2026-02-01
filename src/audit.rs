use colored::*;
use std::fs;
use std::io::Write;
use std::time::{Duration, SystemTime};

use crate::config::Config;
use crate::container::{classify_alert, AlertSeverity, ContainerResult, FalcoAlert};

// ============================================================================
// Audit Log
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_audit_log(
    url: &str,
    script_hash: &str,
    script_size: usize,
    static_finding_count: usize,
    has_critical: bool,
    has_prompt_injection: bool,
    ai_risk_level: &str,
    ai_raw_response: &str,
    decision: &str,
    sandboxed: bool,
    container_result: Option<&ContainerResult>,
    falco_alerts: &[FalcoAlert],
    runtime_ai_verdict: Option<&str>,
) {
    let log_result = (|| -> anyhow::Result<()> {
        let dir = Config::config_dir()?;
        fs::create_dir_all(&dir)?;

        let log_path = dir.join("audit.log");

        // Rotate audit log if it exceeds 10 MB
        const MAX_AUDIT_LOG_BYTES: u64 = 10 * 1024 * 1024;
        if log_path.exists() {
            if let Ok(meta) = fs::metadata(&log_path) {
                if meta.len() > MAX_AUDIT_LOG_BYTES {
                    let rotated = dir.join("audit.log.1");
                    let _ = fs::rename(&log_path, &rotated);
                }
            }
        }

        // Get ISO 8601 timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));
        let secs = now.as_secs();
        // Simple ISO 8601 without external crate: seconds since epoch
        // Format: YYYY-MM-DDTHH:MM:SSZ (compute from epoch)
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;

        // Compute date from days since epoch (1970-01-01)
        let (year, month, day) = days_to_date(days);

        let timestamp = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            year, month, day, hours, minutes, seconds
        );

        // Escape JSON string values
        let url_escaped = url.replace('\\', "\\\\").replace('"', "\\\"");
        let response_escaped = ai_raw_response
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");

        let mut entry = format!(
            "{{\"timestamp\":\"{}\",\"url\":\"{}\",\"sha256\":\"{}\",\"size_bytes\":{},\"static_findings\":{},\"has_critical\":{},\"has_prompt_injection\":{},\"ai_risk_level\":\"{}\",\"ai_raw_response\":\"{}\",\"decision\":\"{}\",\"sandboxed\":{}",
            timestamp, url_escaped, script_hash, script_size, static_finding_count, has_critical, has_prompt_injection, ai_risk_level, response_escaped, decision, sandboxed
        );

        // Append container observation fields if present
        if let Some(cr) = container_result {
            entry.push_str(&format!(
                ",\"container_id\":\"{}\",\"runtime_duration_ms\":{},\"container_timed_out\":{},\"container_exit_code\":{},\"killed_by_monitor\":{},\"filesystem_changes\":{}",
                cr.container_id.replace('"', "\\\""),
                cr.duration_ms,
                cr.timed_out,
                cr.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "null".to_string()),
                cr.killed_by_monitor,
                cr.filesystem_diff.len(),
            ));
        }

        // Append Falco alert summary
        if !falco_alerts.is_empty() {
            let highest = falco_alerts
                .iter()
                .map(classify_alert)
                .min_by_key(|s| match s {
                    AlertSeverity::Critical => 0,
                    AlertSeverity::Suspicious => 1,
                    AlertSeverity::Anomaly => 2,
                })
                .unwrap_or(AlertSeverity::Anomaly);
            let highest_str = match highest {
                AlertSeverity::Critical => "critical",
                AlertSeverity::Suspicious => "suspicious",
                AlertSeverity::Anomaly => "anomaly",
            };

            let rules: Vec<String> = falco_alerts
                .iter()
                .map(|a| a.rule.replace('"', "\\\""))
                .collect();

            entry.push_str(&format!(
                ",\"falco_alert_count\":{},\"falco_highest_severity\":\"{}\",\"falco_rules\":[{}]",
                falco_alerts.len(),
                highest_str,
                rules
                    .iter()
                    .map(|r| format!("\"{}\"", r))
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }

        // Append runtime AI re-review verdict if available
        if let Some(verdict) = runtime_ai_verdict {
            entry.push_str(&format!(
                ",\"runtime_ai_verdict\":\"{}\"",
                verdict.replace('"', "\\\"")
            ));
        }

        entry.push_str("}\n");

        use std::fs::OpenOptions;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?;

        // Set permissions to 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600))?;
        }

        file.write_all(entry.as_bytes())?;
        Ok(())
    })();

    if let Err(e) = log_result {
        eprintln!("{} Failed to write audit log: {}", "⚠".yellow(), e);
    }
}

/// Convert days since Unix epoch to (year, month, day)
pub(crate) fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_format() {
        // Verify days_to_date produces correct results
        // 2024-01-01 is day 19723 since epoch
        let (y, m, d) = days_to_date(19723);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 1);

        // 1970-01-01 is day 0
        let (y, m, d) = days_to_date(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_days_to_date_leap_year() {
        // 2024-02-29 (leap day) — day 19782 since epoch
        let (y, m, d) = days_to_date(19782);
        assert_eq!((y, m, d), (2024, 2, 29));
    }

    #[test]
    fn test_days_to_date_year_2000() {
        // 2000-01-01 = day 10957
        let (y, m, d) = days_to_date(10957);
        assert_eq!((y, m, d), (2000, 1, 1));
    }

    #[test]
    fn test_days_to_date_end_of_year() {
        // 2024-12-31 = day 20088
        let (y, m, d) = days_to_date(20088);
        assert_eq!((y, m, d), (2024, 12, 31));
    }
}

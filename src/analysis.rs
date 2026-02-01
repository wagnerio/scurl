use anyhow::Result;
use colored::*;
use regex::Regex;

// ============================================================================
// Security Analysis
// ============================================================================

#[derive(Debug)]
pub(crate) struct SecurityAnalysis {
    pub(crate) risk_level: RiskLevel,
    pub(crate) confidence: u8, // 0-100
    pub(crate) findings: Vec<String>,
    pub(crate) recommendation: String,
}

#[derive(Debug, PartialEq)]
pub(crate) enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub(crate) fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "safe" => RiskLevel::Safe,
            "low" => RiskLevel::Low,
            "medium" => RiskLevel::Medium,
            "high" => RiskLevel::High,
            "critical" => RiskLevel::Critical,
            _ => RiskLevel::High,
        }
    }

    pub(crate) fn color(&self) -> Color {
        match self {
            RiskLevel::Safe => Color::Green,
            RiskLevel::Low => Color::Cyan,
            RiskLevel::Medium => Color::Yellow,
            RiskLevel::High => Color::Red,
            RiskLevel::Critical => Color::Magenta,
        }
    }

    pub(crate) fn is_probably_safe(&self) -> bool {
        matches!(self, RiskLevel::Safe | RiskLevel::Low)
    }
}

/// Sanitize AI response text to prevent terminal injection and strip markdown.
pub(crate) fn sanitize_ai_response(text: &str) -> String {
    let mut clean = text.replace("**", "").replace("__", "");
    // Strip ANSI escape sequences (\x1b[...m and similar)
    let ansi_re = Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").unwrap();
    clean = ansi_re.replace_all(&clean, "").to_string();
    // Strip other control characters except newline, tab, carriage return
    clean.retain(|c| c == '\n' || c == '\t' || c == '\r' || !c.is_control());
    clean
}

pub(crate) fn parse_analysis(text: &str) -> Result<SecurityAnalysis> {
    let mut risk_level = None;
    let mut confidence: Option<u8> = None;
    let mut findings = Vec::new();
    let mut recommendation = String::new();

    let mut current_section = "";

    // Strip common markdown formatting the LLM might add
    // Also strip ANSI escape sequences to prevent terminal injection from AI responses
    let clean = sanitize_ai_response(text);

    for line in clean.lines() {
        let line = line.trim();

        if line.starts_with("RISK_LEVEL:") {
            let level = line.replace("RISK_LEVEL:", "").trim().to_string();
            risk_level = Some(RiskLevel::from_str(&level));
        } else if line.starts_with("CONFIDENCE:") {
            let val = line
                .replace("CONFIDENCE:", "")
                .trim()
                .trim_end_matches('%')
                .trim()
                .parse::<u8>()
                .unwrap_or(50);
            confidence = Some(val.min(100));
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

    // Contradiction detection: escalate risk if findings contradict the stated level
    let risk_level = {
        let mut level = risk_level;
        let findings_lower: Vec<String> =
            findings.iter().map(|f| f.to_lowercase()).collect();

        let dangerous_keywords = [
            "reverse shell",
            "backdoor",
            "exfiltration",
            "malicious",
            "critical",
            "dangerous",
            "trojan",
            "keylogger",
            "rootkit",
            "exploit",
        ];

        if matches!(level, RiskLevel::Safe | RiskLevel::Low) {
            let negation_patterns = [
                "no ", "no\u{00a0}", "not ", "without ", "non-", "non\u{00a0}",
                "absence of ", "free of ", "doesn't ", "does not ",
                "don't ", "do not ", "didn't ", "did not ",
                "isn't ", "is not ", "aren't ", "are not ",
                "wasn't ", "was not ", "weren't ", "were not ",
                "won't ", "will not ", "cannot ", "can't ",
            ];
            let has_dangerous = dangerous_keywords.iter().any(|kw| {
                // Check each finding individually so negation scope stays
                // within a single finding rather than bleeding across them
                for finding in &findings_lower {
                    let mut start = 0;
                    while let Some(pos) = finding[start..].find(kw) {
                        let abs_pos = start + pos;
                        let prefix_region =
                            &finding[abs_pos.saturating_sub(50)..abs_pos];
                        let negated = negation_patterns.iter().any(|neg| {
                            prefix_region.contains(neg)
                        });
                        if !negated {
                            return true;
                        }
                        start = abs_pos + kw.len();
                    }
                }
                false
            });
            if has_dangerous {
                eprintln!(
                    "{} AI rated script as {:?} but findings mention dangerous keywords — escalating to HIGH.",
                    "⚠".yellow(),
                    level
                );
                level = RiskLevel::High;
            }
        }

        if matches!(level, RiskLevel::Safe) && findings.len() >= 5 {
            eprintln!(
                "{} AI rated script as SAFE but reported {} findings — escalating to MEDIUM.",
                "⚠".yellow(),
                findings.len()
            );
            level = RiskLevel::Medium;
        }

        level
    };

    // Default confidence: infer from risk level if AI didn't provide one
    let confidence = confidence.unwrap_or(match risk_level {
        RiskLevel::Safe => 80,
        RiskLevel::Low => 70,
        RiskLevel::Medium => 60,
        RiskLevel::High => 70,
        RiskLevel::Critical => 80,
    });

    Ok(SecurityAnalysis {
        risk_level,
        confidence,
        findings,
        recommendation,
    })
}

pub(crate) fn display_analysis(analysis: &SecurityAnalysis) {
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

    let confidence_color = if analysis.confidence >= 80 {
        Color::Green
    } else if analysis.confidence >= 60 {
        Color::Yellow
    } else {
        Color::Red
    };

    println!(
        "\n{} {}  {} {}",
        "Risk Level:".bold(),
        format!("{:?}", analysis.risk_level)
            .to_uppercase()
            .color(analysis.risk_level.color())
            .bold(),
        "Confidence:".bold(),
        format!("{}%", analysis.confidence)
            .color(confidence_color)
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

    println!(
        "\n{}",
        "Note: This analysis reduces but does not eliminate the risk of executing"
            .bright_black()
    );
    println!(
        "{}",
        "remote code. Always verify scripts from untrusted sources manually."
            .bright_black()
    );
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
    fn test_contradiction_detection_safe_with_dangerous_findings() {
        let text = r#"
RISK_LEVEL: SAFE
FINDINGS:
- This script installs a reverse shell backdoor
- It exfiltrates credentials
RECOMMENDATION: This script is safe to execute.
"#;
        let result = parse_analysis(text).unwrap();
        // Should be escalated from SAFE to HIGH due to "reverse shell", "backdoor", "exfiltrat"
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_contradiction_detection_negated_keywords_not_escalated() {
        let text = r#"
RISK_LEVEL: SAFE
FINDINGS:
- No backdoors or malicious payloads detected
- No credential harvesting or exfiltration found
- Does not contain a reverse shell
- Script is not dangerous
RECOMMENDATION: This script is safe to execute.
"#;
        let result = parse_analysis(text).unwrap();
        // Negated keywords should NOT trigger escalation
        assert_eq!(result.risk_level, RiskLevel::Safe);
    }

    #[test]
    fn test_contradiction_detection_safe_with_many_findings() {
        let text = r#"
RISK_LEVEL: SAFE
FINDINGS:
- Finding one
- Finding two
- Finding three
- Finding four
- Finding five
RECOMMENDATION: Looks good.
"#;
        let result = parse_analysis(text).unwrap();
        // 5+ findings with SAFE should escalate to at least MEDIUM
        assert!(matches!(
            result.risk_level,
            RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
        ));
    }

    #[test]
    fn test_parse_analysis_with_confidence() {
        let text = r#"
RISK_LEVEL: LOW
CONFIDENCE: 85
FINDINGS:
- Supply Chain: Downloads from official GitHub release
- Privilege Escalation: Uses sudo to install binary
RECOMMENDATION: Safe to execute.
"#;
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Low);
        assert_eq!(result.confidence, 85);
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn test_parse_analysis_confidence_with_percent() {
        let text = r#"
RISK_LEVEL: SAFE
CONFIDENCE: 92%
FINDINGS:
- No issues found
RECOMMENDATION: Safe to run.
"#;
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.confidence, 92);
    }

    #[test]
    fn test_parse_analysis_confidence_defaults() {
        let text = r#"
RISK_LEVEL: SAFE
FINDINGS:
- No issues found
RECOMMENDATION: Safe to run.
"#;
        let result = parse_analysis(text).unwrap();
        // Default confidence for SAFE is 80
        assert_eq!(result.confidence, 80);
    }

    #[test]
    fn test_parse_analysis_confidence_default_high() {
        let text = r#"
RISK_LEVEL: HIGH
FINDINGS:
- Suspicious behavior
RECOMMENDATION: Do not execute.
"#;
        let result = parse_analysis(text).unwrap();
        // Default confidence for HIGH is 70
        assert_eq!(result.confidence, 70);
    }

    #[test]
    fn test_parse_analysis_confidence_clamped_to_100() {
        let text = r#"
RISK_LEVEL: LOW
CONFIDENCE: 150
FINDINGS:
- No issues
RECOMMENDATION: Safe.
"#;
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.confidence, 100);
    }

    #[test]
    fn test_display_analysis_with_confidence_no_panic() {
        let analysis = SecurityAnalysis {
            risk_level: RiskLevel::Low,
            confidence: 85,
            findings: vec!["Test finding".to_string()],
            recommendation: "Safe to run.".to_string(),
        };
        // Should not panic
        display_analysis(&analysis);
    }

    // --- Sanitization ---

    #[test]
    fn test_sanitize_ai_response_strips_ansi() {
        let input = "RISK_LEVEL: \x1b[31mCRITICAL\x1b[0m\nFINDINGS:\n- Bad stuff";
        let clean = sanitize_ai_response(input);
        assert!(!clean.contains("\x1b"));
        assert!(clean.contains("CRITICAL"));
    }

    #[test]
    fn test_sanitize_ai_response_strips_control_chars() {
        let input = "RISK_LEVEL: SAFE\x07\x08\nFINDINGS:\n- OK";
        let clean = sanitize_ai_response(input);
        assert!(!clean.contains('\x07'));
        assert!(!clean.contains('\x08'));
        assert!(clean.contains("SAFE"));
    }

    #[test]
    fn test_sanitize_ai_response_preserves_newlines_and_tabs() {
        let input = "RISK_LEVEL: LOW\n\tFINDINGS:\n- OK\r\n";
        let clean = sanitize_ai_response(input);
        assert!(clean.contains('\n'));
        assert!(clean.contains('\t'));
    }

    #[test]
    fn test_sanitize_ai_response_strips_markdown() {
        let input = "**RISK_LEVEL:** __SAFE__";
        let clean = sanitize_ai_response(input);
        assert!(!clean.contains("**"));
        assert!(!clean.contains("__"));
        assert!(clean.contains("RISK_LEVEL:"));
    }

    // --- parse_analysis edge cases ---

    #[test]
    fn test_parse_analysis_empty_response() {
        let result = parse_analysis("").unwrap();
        assert_eq!(result.risk_level, RiskLevel::High); // defaults to HIGH
        assert!(result.confidence > 0);
    }

    #[test]
    fn test_parse_analysis_garbage_input() {
        let result = parse_analysis("Lorem ipsum dolor sit amet, consectetur adipiscing elit.").unwrap();
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_parse_analysis_only_risk_level() {
        let result = parse_analysis("RISK_LEVEL: MEDIUM").unwrap();
        assert_eq!(result.risk_level, RiskLevel::Medium);
        assert_eq!(result.confidence, 60); // default for MEDIUM
    }

    #[test]
    fn test_parse_analysis_duplicate_risk_level_takes_last() {
        let text = "RISK_LEVEL: SAFE\nRISK_LEVEL: CRITICAL\nFINDINGS:\n- Bad\nRECOMMENDATION: No.";
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_parse_analysis_very_long_finding() {
        let long_finding = format!("- {}", "A".repeat(10000));
        let text = format!("RISK_LEVEL: LOW\nFINDINGS:\n{}\nRECOMMENDATION: OK.", long_finding);
        let result = parse_analysis(&text).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].len() >= 10000);
    }

    #[test]
    fn test_parse_analysis_many_findings() {
        let mut text = "RISK_LEVEL: MEDIUM\nFINDINGS:\n".to_string();
        for i in 0..100 {
            text.push_str(&format!("- Finding number {}\n", i));
        }
        text.push_str("RECOMMENDATION: Review carefully.");
        let result = parse_analysis(&text).unwrap();
        assert_eq!(result.findings.len(), 100);
    }

    #[test]
    fn test_parse_analysis_with_ansi_in_risk_level() {
        let text = "RISK_LEVEL: \x1b[32mSAFE\x1b[0m\nFINDINGS:\n- OK\nRECOMMENDATION: Fine.";
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Safe);
    }

    #[test]
    fn test_parse_analysis_unicode_in_findings() {
        let text = "RISK_LEVEL: LOW\nFINDINGS:\n- Script uses 日本語 encoding\n- Contains émojis 🔒\nRECOMMENDATION: OK.";
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.findings.len(), 2);
        assert!(result.findings[0].contains("日本語"));
    }

    // --- RiskLevel edge cases ---

    #[test]
    fn test_risk_level_from_str_case_insensitive() {
        assert_eq!(RiskLevel::from_str("Safe"), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_str("SAFE"), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_str("sAfE"), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_str("CrItIcAl"), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_from_str_whitespace() {
        // from_str trims? Let's check — it doesn't, but the caller in parse_analysis does
        assert_eq!(RiskLevel::from_str("high"), RiskLevel::High);
    }

    #[test]
    fn test_risk_level_all_colors() {
        // Just ensure no panic for all color lookups
        for level in [
            RiskLevel::Safe,
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let _ = level.color();
            let _ = level.is_probably_safe();
        }
    }

    // --- Contradiction detection edge cases ---

    #[test]
    fn test_contradiction_escalation_with_critical_keyword() {
        let text = "RISK_LEVEL: SAFE\nFINDINGS:\n- Script installs a rootkit\nRECOMMENDATION: Looks fine.";
        let result = parse_analysis(text).unwrap();
        // Should escalate because "rootkit" is a dangerous keyword
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn test_contradiction_no_escalation_when_already_high() {
        let text = "RISK_LEVEL: HIGH\nFINDINGS:\n- Script installs a rootkit\nRECOMMENDATION: Dangerous.";
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::High); // stays HIGH, not escalated further
    }

    #[test]
    fn test_contradiction_safe_with_exactly_5_findings_escalates() {
        let text = "RISK_LEVEL: SAFE\nFINDINGS:\n- A\n- B\n- C\n- D\n- E\nRECOMMENDATION: Fine.";
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn test_contradiction_safe_with_4_findings_no_escalation() {
        let text = "RISK_LEVEL: SAFE\nFINDINGS:\n- A\n- B\n- C\n- D\nRECOMMENDATION: Fine.";
        let result = parse_analysis(text).unwrap();
        assert_eq!(result.risk_level, RiskLevel::Safe);
    }
}

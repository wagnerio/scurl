#![allow(deprecated)]

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

#[test]
fn test_version_flag() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("scurl"));
}

#[test]
fn test_help_flag() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Secure curl"))
        .stdout(predicate::str::contains("--proxy"))
        .stdout(predicate::str::contains("--timeout"));
}

#[test]
fn test_no_args_shows_usage() {
    Command::cargo_bin("scurl")
        .unwrap()
        .assert()
        .success()
        .stdout(predicate::str::contains("scurl login"))
        .stdout(predicate::str::contains("scurl <URL>"));
}

#[test]
fn test_config_shows_current_config() {
    let output = Command::cargo_bin("scurl")
        .unwrap()
        .arg("config")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let has_config = stdout.contains("Current Configuration");
    let no_config = stderr.contains("No configuration found");

    assert!(
        has_config || no_config,
        "Should either show config or say not found"
    );
}

// ── Day 6: New integration tests for runtime-scan CLI flags ──

#[test]
fn test_help_includes_day3_flags() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--auto-trust"))
        .stdout(predicate::str::contains("--blacklist-hash"));
}

#[test]
fn test_help_includes_day5_flags() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--second-opinion"))
        .stdout(predicate::str::contains("--second-provider"));
}

#[test]
fn test_blacklist_hash_invalid_hex() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--blacklist-hash")
        .arg("not-a-hex-hash!")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid hash"));
}

#[test]
fn test_blacklist_hash_empty() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--blacklist-hash")
        .arg("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid hash"));
}

#[test]
fn test_blacklist_hash_valid_hex_succeeds() {
    // Use a unique hash that won't collide with real usage
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("--blacklist-hash")
        .arg("deadbeefcafe1234567890abcdef1234567890abcdef1234567890abcdef1234")
        .assert()
        .success()
        .stdout(predicate::str::contains("added to blacklist"));
}

#[test]
fn test_analyze_invalid_url_scheme() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("ftp://example.com/script.sh")
        .assert()
        .failure();
}

#[test]
fn test_analyze_invalid_url_format() {
    Command::cargo_bin("scurl")
        .unwrap()
        .arg("not-a-url")
        .assert()
        .failure();
}

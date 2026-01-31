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

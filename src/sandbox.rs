use anyhow::{Context, Result};
use colored::*;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::NamedTempFile;

use crate::helpers::command_exists;

// ============================================================================
// Sandbox
// ============================================================================

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SandboxBackend {
    Bwrap,
    Firejail,
    SandboxExec,
}

pub(crate) fn detect_sandbox_backend() -> Option<SandboxBackend> {
    #[cfg(target_os = "macos")]
    {
        if command_exists("sandbox-exec") {
            return Some(SandboxBackend::SandboxExec);
        }
    }

    #[cfg(target_os = "linux")]
    {
        if command_exists("bwrap") {
            return Some(SandboxBackend::Bwrap);
        }
        if command_exists("firejail") {
            return Some(SandboxBackend::Firejail);
        }
    }

    None
}

fn execute_sandboxed_bwrap(
    shell: &str,
    script_path: &Path,
) -> Result<std::process::ExitStatus> {
    let script_path_str = script_path
        .to_str()
        .context("Script path is not valid UTF-8")?;

    let mut cmd = Command::new("bwrap");

    // Read-only bind mounts for system directories
    for dir in &["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if Path::new(dir).exists() {
            cmd.arg("--ro-bind").arg(dir).arg(dir);
        }
    }

    // Minimal device access
    cmd.arg("--dev").arg("/dev");
    // PID namespace support
    cmd.arg("--proc").arg("/proc");
    // Fresh writable /tmp
    cmd.arg("--tmpfs").arg("/tmp");
    // Script file read-only
    cmd.arg("--ro-bind").arg(script_path_str).arg(script_path_str);
    // Namespace isolation
    cmd.arg("--unshare-net");
    cmd.arg("--unshare-pid");
    cmd.arg("--unshare-ipc");
    cmd.arg("--unshare-uts");
    cmd.arg("--unshare-cgroup");
    // Security hardening
    cmd.arg("--new-session");
    cmd.arg("--die-with-parent");
    // Drop all capabilities
    cmd.arg("--cap-drop").arg("ALL");
    // Shell and script
    cmd.arg(shell).arg(script_path_str);

    cmd.status()
        .context("Failed to execute script in bwrap sandbox")
}

fn execute_sandboxed_firejail(
    shell: &str,
    script_path: &Path,
) -> Result<std::process::ExitStatus> {
    eprintln!(
        "{} Using firejail (SUID sandbox). For stronger isolation, install bubblewrap: {}",
        "Note:".yellow().bold(),
        "apt install bubblewrap".cyan()
    );

    let script_path_str = script_path
        .to_str()
        .context("Script path is not valid UTF-8")?;

    Command::new("firejail")
        .arg("--noprofile")
        .arg("--net=none")
        .arg("--read-only=/")
        .arg("--whitelist=/tmp")
        .arg("--quiet")
        .arg(shell)
        .arg(script_path_str)
        .status()
        .context("Failed to execute script in firejail sandbox")
}

fn execute_sandboxed_macos(
    shell: &str,
    script_path: &Path,
) -> Result<std::process::ExitStatus> {
    let script_path_str = script_path
        .to_str()
        .context("Script path is not valid UTF-8")?;

    let profile = format!(
        r#"(version 1)
(deny default)
(allow file-read* (subpath "/usr") (subpath "/bin") (subpath "/sbin")
    (subpath "/System") (subpath "/Library") (subpath "/private/etc")
    (subpath "/dev"))
(allow file-read* (literal "{}"))
(allow file-write* (subpath "/private/tmp") (subpath "/tmp"))
(allow process-exec) (allow process-fork)
(deny network*)
(allow sysctl-read) (allow mach-lookup)"#,
        script_path_str
    );

    Command::new("sandbox-exec")
        .arg("-p")
        .arg(&profile)
        .arg(shell)
        .arg(script_path_str)
        .status()
        .context("Failed to execute script in macOS sandbox")
}

pub(crate) fn execute_script(script: &str, shell: &str, sandbox: bool) -> Result<()> {
    let mut temp_file = NamedTempFile::new()?;
    temp_file.write_all(script.as_bytes())?;
    let temp_path = temp_file.path();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(temp_path)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(temp_path, perms)?;
    }

    let status = if sandbox {
        let backend = detect_sandbox_backend();
        match backend {
            Some(SandboxBackend::Bwrap) => {
                println!(
                    "\n{}",
                    "Executing script in sandbox (bwrap)...".cyan()
                );
                execute_sandboxed_bwrap(shell, temp_path)?
            }
            Some(SandboxBackend::Firejail) => {
                println!(
                    "\n{}",
                    "Executing script in sandbox (firejail)...".cyan()
                );
                execute_sandboxed_firejail(shell, temp_path)?
            }
            Some(SandboxBackend::SandboxExec) => {
                println!(
                    "\n{}",
                    "Executing script in sandbox (sandbox-exec)...".cyan()
                );
                execute_sandboxed_macos(shell, temp_path)?
            }
            None => {
                let install_hint = if cfg!(target_os = "linux") {
                    "Install bubblewrap: sudo apt install bubblewrap (Debian/Ubuntu) or sudo dnf install bubblewrap (Fedora)"
                } else if cfg!(target_os = "macos") {
                    "sandbox-exec should be available on macOS by default. Check your PATH."
                } else {
                    "No supported sandbox backend found for this platform."
                };
                anyhow::bail!(
                    "Sandbox backend not found. {}\nTo run without sandboxing, use --no-sandbox",
                    install_hint
                );
            }
        }
    } else {
        println!(
            "\n{}",
            format!("Executing script with {} (no sandbox)...", shell).cyan()
        );
        Command::new(shell)
            .arg(temp_path)
            .status()
            .context(format!("Failed to execute script with {}", shell))?
    };

    if !status.success() {
        anyhow::bail!(
            "Script execution failed with exit code: {:?}",
            status.code()
        );
    }

    println!("\n{}", "Script executed successfully".green().bold());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_sandbox_backend() {
        let backend = detect_sandbox_backend();
        // On macOS, should detect sandbox-exec; on Linux, bwrap or firejail
        #[cfg(target_os = "macos")]
        assert_eq!(backend, Some(SandboxBackend::SandboxExec));
        #[cfg(target_os = "linux")]
        assert!(
            backend == Some(SandboxBackend::Bwrap)
                || backend == Some(SandboxBackend::Firejail)
                || backend.is_none()
        );
    }

    #[test]
    fn test_sandbox_backend_debug() {
        assert_eq!(format!("{:?}", SandboxBackend::Bwrap), "Bwrap");
        assert_eq!(format!("{:?}", SandboxBackend::Firejail), "Firejail");
        assert_eq!(format!("{:?}", SandboxBackend::SandboxExec), "SandboxExec");
    }

    #[test]
    fn test_help_includes_no_sandbox() {
        use clap::CommandFactory;
        use crate::Cli;
        let mut buf = Vec::new();
        Cli::command().write_help(&mut buf).unwrap();
        let help_text = String::from_utf8(buf).unwrap();
        assert!(help_text.contains("--no-sandbox"));
    }

    #[test]
    fn test_command_exists_positive() {
        assert!(command_exists("sh"));
    }

    #[test]
    fn test_command_exists_negative() {
        assert!(!command_exists("nonexistent_binary_xyz"));
    }
}

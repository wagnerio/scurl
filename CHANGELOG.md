# Changelog

## [0.5.1] - 2026-02-02

### Added
- **gVisor (runsc) runtime isolation** — new `--runtime-isolation` flag with `auto|bubblewrap|podman|podman-gvisor` backends for selecting the script execution sandbox
- **runsc auto-detection** — probes `SCURL_RUNSC_PATH` env var, `/usr/local/bin/runsc`, and `/usr/bin/runsc`
- **Rootless Podman + gVisor warning** — alerts users to known cgroup/network namespace issues with rootless mode (google/gvisor#311)
- **`runtime_used` audit field** — container results and audit log entries now record which runtime was used (`podman-gvisor` or `podman`)

### Changed
- Podman arg construction refactored into `configure_podman_run()` helper, eliminating duplication between monitored and unmonitored execution paths
- Explicit `--runtime-isolation=podman` or `podman-gvisor` overrides the risk-level gate (container runs even for HIGH risk scripts)
- `--runtime-container` flag marked deprecated in help text (still functional, now opportunistically tries gVisor when available)

## [0.5.0] - 2026-02-01

### Added
- **Container-based runtime execution** — execute scripts inside a rootless Podman container with no network, read-only root, and seccomp defaults (`--runtime-container`)
- **Falco runtime monitoring** — real-time syscall monitoring during container execution via Falco log tailing, with alert classification (Critical / Suspicious / Anomaly) (`--monitor-level`, `--no-monitor`)
- **Local script cache** — SHA-256-indexed JSON cache at `~/.scurl/cache.json` with trusted/blacklisted status and automatic re-analysis on script change (`--auto-trust`)
- **Hash blacklisting** — revoke trust for known-bad script hashes from the CLI (`--blacklist-hash`)
- **Source whitelisting** — `whitelist_sources` in `config.toml` for domains that skip the interactive prompt
- **Enhanced AI prompt engineering** — 10-category threat taxonomy, anti-evasion directives, few-shot examples
- **Confidence scores** — AI analysis now reports a 0–100 confidence percentage with color-coded display
- **Second-opinion mode** — cross-validate analysis using a second AI provider with agreement/disagreement reporting (`--second-opinion`, `--second-provider`)
- **Custom prompt overrides** — load user-defined prompt templates from `~/.scurl/prompts/` with template variable substitution
- **AI response sanitization** — strips ANSI escape sequences and control characters from AI responses before parsing
- **Audit log rotation** — rotates `~/.scurl/audit.log` at 10 MB to `.log.1`

### Changed
- URL validation hardened: 8 KB length cap, embedded credential rejection, expanded SSRF detection (IPv6, 172.16–31.x.x, fd/fe80 ranges)
- Blacklist hash input validated (hex-only, normalized to lowercase)
- Cache handles empty files and corrupted JSON (auto-backup to `.json.bak`)
- Prompt override loader rejects path traversal and files over 100 KB
- ScriptCache forward-compatible with `#[serde(default)]` on entries

### Security
- Container execution uses `--cap-drop ALL`, `--security-opt no-new-privileges`, `--read-only`, `--network none`
- Falco alerts trigger automatic execution abort on Critical severity
- Prompt override paths cannot escape `~/.scurl/prompts/`

## [0.4.1] - 2026-02-01

### Added
- **Plaintext API key warning** — warns at startup when a key is stored in plaintext config and OS keyring is available, directing users to `scurl login` to migrate
- **Bwrap capability dropping** — bubblewrap sandbox now runs with `--cap-drop ALL`, preventing privilege escalation via Linux capabilities
- **AI response size limit** — all provider responses are capped at 1 MB to guard against excessively large or malicious payloads
- **Raw AI response in audit log** — `ai_raw_response` field added to `~/.scurl/audit.log` entries for forensic analysis
- **Enhanced auto-execute warning** — explicitly warns about sandbox escape risk and recommends restricting auto-execute to local models

### Changed
- `serde_json` added as an explicit dependency for byte-level response parsing

## [0.4.0] - 2026-02-01

### Added
- **OS-level sandboxed execution** on by default — scripts run inside a sandbox with no network access and a read-only filesystem (except `/tmp`)
  - Linux: bubblewrap (preferred) with firejail fallback
  - macOS: sandbox-exec
  - Hard-fails with install instructions if no backend is found
- `--no-sandbox` flag to opt out of sandboxed execution
- `sandboxed` field in audit log entries

### Fixed
- **Contradiction detection false positives** — negated keywords like "No backdoors", "Does not contain a reverse shell" no longer trigger risk escalation

## [0.3.4] - 2026-02-01

### Changed
- Bump version for crates.io release

## [0.3.3] - 2026-02-01

### Added
- `scurl skill` subcommand to output Claude Code skill definition
- Updated README usage section with skill subcommand

### Removed
- `--yolo` flag (replaced by `--auto-execute` / `-a`)

## [0.3.2] - 2026-02-01

### Changed
- Updated README for security hardening changes

## [0.3.1] - 2026-02-01

### Changed
- Updated Gemini to gemini-2.5-flash
- Fixed CI rust-toolchain action

## [0.3.0] - 2026-01-31

### Added
- **Azure OpenAI** and **Google Gemini** providers
- **Security hardening**: shell validation, null byte detection, static analysis (22 patterns), prompt injection detection, AI contradiction detection, audit logging, SHA-256 hashing, OS keyring integration, atomic config writes, split HTTP clients

## [0.2.0] - 2026-01-31

### Added
- **Multi-provider support**: Anthropic, xAI, OpenAI, Ollama
- **Ollama provider** for local AI analysis (no API key, works offline)
- **Interactive `scurl login`** setup wizard
- **Persistent configuration** in `~/.scurl/config.toml` (owner-only permissions)
- **Animated spinners** during download and analysis
- **Network options**: proxy, timeout, retries, custom headers, SSL bypass
- **`scurl config`** command to view current configuration
- **`--version` flag**
- **Content-type validation** with warnings for non-script responses
- **Download size limit** (10 MB)
- **Retry logic** with exponential backoff (skips 4xx errors)

### Security
- Config files restricted to `0600` permissions
- API key masking uses char boundaries (no UTF-8 panic)
- Login respects `--proxy` and other network flags
- Pre-commit hooks block real API keys in code

## [0.1.0] - 2026-01-31

### Added
- Initial release
- AI-powered security analysis for install scripts
- Risk level classification (Safe, Low, Medium, High, Critical)
- Interactive execution with user confirmation
- Auto-execute mode (`-a`) for safe scripts
- Shell selection (`--shell`)
- Example scripts for testing

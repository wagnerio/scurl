# Changelog

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

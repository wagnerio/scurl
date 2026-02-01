# Changelog

## [Unreleased]

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

# Changelog

All notable changes to scurl will be documented in this file.

## [Unreleased]

### Added
- **Animated spinners** for all async operations
  - Download phase with byte count
  - AI analysis with provider name
  - Login API connection test
  - Smooth Braille pattern animations (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏)
  - Color-coded success (✓ green) and failure (✗ red) indicators

## [0.2.0] - 2026-01-31

### Added
- **Multi-provider support**
  - Anthropic (Claude Sonnet 4.5, Opus, Haiku)
  - xAI (Grok 2)
  - OpenAI (GPT-4, GPT-4o)
- **Interactive `scurl login` command**
  - Guided setup wizard
  - Provider selection
  - API key configuration
  - Optional custom model selection
  - Connection testing
- **Persistent configuration**
  - Config stored in `~/.scurl/config.toml`
  - No more environment variables required
- **New subcommands**
  - `scurl login` - Interactive setup
  - `scurl config` - View current configuration
  - `scurl analyze <URL>` - Explicit analyze command
- **CLI improvements**
  - `--provider` flag to override config
  - `--api-key` flag to override config
  - Shorthand `scurl <URL>` still works

### Changed
- Refactored codebase for better modularity
- Improved error messages and user feedback
- Better handling of API responses across providers

### Removed
- Environment variable `ANTHROPIC_API_KEY` support
  - Use `scurl login` or `--api-key` flag instead

### Documentation
- Added QUICKSTART.md for fast setup
- Added MIGRATION.md for upgrade guide
- Added ANIMATIONS.md for visual feedback guide
- Updated README.md with multi-provider info

## [0.1.0] - 2026-01-31

### Added
- Initial release
- AI-powered security analysis for install scripts
- Anthropic Claude integration
- Risk level classification (Safe, Low, Medium, High, Critical)
- Interactive execution with user confirmation
- Auto-execute mode for safe scripts
- YOLO mode (skip review)
- Shell selection (bash, sh, etc.)
- Detailed security findings
- Example scripts for testing
- Comprehensive documentation

### Security Analysis Features
- Detects suspicious commands (eval, base64, curl | bash)
- Identifies untrusted downloads
- Flags privilege escalation attempts
- Spots code obfuscation
- Checks for credential harvesting
- Detects backdoor patterns
- Identifies malicious payloads
- Warns about destructive operations

---

## Version History Summary

- **v0.2.0**: Multi-provider support, interactive setup, animated feedback
- **v0.1.0**: Initial release with Anthropic Claude integration

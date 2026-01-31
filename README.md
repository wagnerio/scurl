# 🔒 scurl - Secure curl

A Rust CLI tool that provides AI-powered security reviews for installation scripts before execution. Stop blindly running `curl -fsSL url | bash` and start making informed decisions about what code you're executing on your system.

## Why scurl?

We've all seen commands like this:

```bash
curl -fsSL https://example.com/install.sh | bash
```

This pattern is dangerous because:
- You're executing code without reviewing it
- The script runs with your user privileges
- Malicious actors can exploit this trust
- Even legitimate scripts can have vulnerabilities

**scurl** downloads the script, analyzes it with AI for security issues, and presents findings before execution.

## ✨ Features

### 🤖 Multi-AI Provider Support
- **Anthropic** (Claude Sonnet 4.5, Opus, Haiku)
- **xAI** (Grok 2)
- **OpenAI** (GPT-4, GPT-4o)

### 🔍 Security Analysis
- AI-powered detection of suspicious patterns
- Clear risk classification (Safe, Low, Medium, High, Critical)
- Detailed findings and recommendations
- Checks for malware, backdoors, privilege escalation
- Identifies code obfuscation and credential harvesting

### 🎨 User Experience
- ✨ **Animated spinners** - Visual feedback during downloads and analysis
- 🚦 **Interactive execution** - Review findings before running
- ⚡ **Auto-execute mode** - Run safe scripts automatically
- 🎯 **Multiple providers** - Choose your preferred AI
- 🔧 **Easy setup** - Interactive `scurl login` wizard

### 🌐 Enterprise Ready
- **Proxy support** - HTTP/HTTPS/SOCKS proxies
- **Custom headers** - API authentication and special headers
- **SSL/TLS options** - Self-signed certificate support
- **Network resilience** - Automatic retries with backoff
- **Timeout control** - Configurable timeouts
- **Corporate friendly** - Works behind firewalls

### 🔒 Security First
- **Git hooks** - Prevents committing API keys
- **Safe by default** - Nothing executes without approval
- **Persistent config** - Encrypted local storage
- **No telemetry** - Your data stays private

## Installation

### From Source

```bash
git clone https://github.com/wagnerio/scurl.git
cd scurl

# Enable git hooks (prevents committing secrets)
git config core.hooksPath .githooks

# Build and install
cargo install --path .
```

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- AI Provider API key:
  - **Anthropic**: [console.anthropic.com](https://console.anthropic.com)
  - **xAI**: [console.x.ai](https://console.x.ai)
  - **OpenAI**: [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

## Quick Start

### 1. Initial Setup

Run the interactive setup wizard:

```bash
scurl login
```

This guides you through:
1. ✅ Selecting your AI provider (Anthropic, xAI, or OpenAI)
2. ✅ Entering your API key
3. ✅ Optional: Choosing a custom model
4. ✅ Testing the connection

Configuration is saved to `~/.scurl/config.toml`

### 2. Analyze a Script

```bash
scurl https://example.com/install.sh
```

You'll see:
```
🔒 scurl - Secure Script Execution

⠋ Downloading script...
✓ Downloaded 1247 bytes

⠋ Analyzing script with xAI (Grok) AI...
✓ Analysis complete!

═══════════════════════════════════════════════════
           SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════

Risk Level: LOW

Findings:
  1. Uses sudo for package installation
  2. Downloads from official GitHub releases
  3. Verifies checksum before installation

Recommendation:
  This script appears safe. It follows best practices.
═══════════════════════════════════════════════════

Execute this script? [y/N]:
```

### 3. Use It!

```bash
# Basic usage
scurl https://get.docker.com

# Auto-execute safe scripts
scurl --auto-execute https://sh.rustup.rs

# Behind a proxy
scurl --proxy http://proxy.company.com:8080 https://example.com/install.sh

# View your config
scurl config
```

## Usage

### Basic Commands

```bash
# Analyze a script (default command)
scurl https://example.com/install.sh

# Interactive setup
scurl login

# View configuration
scurl config

# Help
scurl --help
```

### Common Options

```bash
# Auto-execute if safe
scurl -a https://example.com/install.sh
scurl --auto-execute https://example.com/install.sh

# Use different shell
scurl --shell sh https://example.com/install.sh
scurl --shell zsh https://example.com/install.sh

# Override provider
scurl --provider anthropic https://example.com/install.sh
scurl --provider openai https://example.com/install.sh

# Skip review (dangerous!)
scurl --yolo https://example.com/install.sh
```

### Network Options

Perfect for corporate environments and special network setups:

```bash
# Use proxy
scurl --proxy http://proxy.company.com:8080 URL
scurl -x http://proxy:8080 URL

# Custom timeout and retries
scurl --timeout 60 --retries 5 URL

# Custom headers (for APIs)
scurl -H "Authorization: Bearer token" URL
scurl -H "X-API-Key: secret" -H "X-Custom: value" URL

# Self-signed certificates (dev/test only)
scurl --insecure https://internal-server.corp/script.sh

# Custom User-Agent
scurl -A "MyBot/1.0" URL

# Disable redirects
scurl --max-redirects 0 URL

# Use system proxy
scurl --system-proxy URL

# Disable proxy
scurl --no-proxy URL
```

See [NETWORK.md](NETWORK.md) for comprehensive network configuration guide.

### Full Options Reference

```
Usage: scurl [OPTIONS] [URL] [COMMAND]

Commands:
  login    Configure scurl with your AI provider credentials
  analyze  Analyze and potentially execute a script (default command)
  config   Show current configuration

Arguments:
  [URL]  URL of the install script (shorthand for 'scurl analyze <URL>')

Options:
  -s, --shell <SHELL>                  Shell to use for execution [default: bash]
  -a, --auto-execute                   Auto-execute if classified as probably safe
      --yolo                           Skip AI review (dangerous!)
      --api-key <API_KEY>              Override API key from config
  -p, --provider <PROVIDER>            Override provider from config

Network & Proxy Options:
  -x, --proxy <PROXY>                  HTTP/HTTPS proxy URL [env: HTTPS_PROXY]
  -t, --timeout <TIMEOUT>              Timeout in seconds [default: 30]
      --max-redirects <MAX_REDIRECTS>  Max redirects to follow [default: 10]
  -k, --insecure                       Disable SSL verification (insecure!)
  -A, --user-agent <USER_AGENT>        Custom User-Agent header
  -H, --header <HEADERS>               Additional headers (format: 'Key: Value')
      --retries <RETRIES>              Network retry attempts [default: 3]
      --system-proxy                   Use system proxy settings
      --no-proxy                       Disable proxy

  -h, --help                           Print help
```

## How It Works

1. **Download** - Fetches the script from the provided URL with retry logic
2. **Analyze** - Sends the script to your configured AI provider for security review
3. **Report** - Displays risk level, specific findings, and recommendations with colored output
4. **Decide** - Prompts for user confirmation (or auto-executes if safe + flag set)
5. **Execute** - Runs the script in a temporary file with your chosen shell

## Security Analysis

The AI examines scripts for:

- ✅ Suspicious commands (`eval`, `base64` decoding, nested `curl | bash`)
- ✅ Downloads from untrusted sources
- ✅ Privilege escalation attempts (`sudo`, `chmod 777`, etc.)
- ✅ Code obfuscation
- ✅ Credential harvesting
- ✅ Backdoor installation patterns
- ✅ Malicious payloads
- ✅ Destructive operations (`rm -rf`, `dd`, etc.)

### Risk Levels

| Level | Color | Meaning | Auto-execute? |
|-------|-------|---------|---------------|
| SAFE | Green | No security concerns found | Yes (with -a) |
| LOW | Cyan | Minor concerns, generally acceptable | Yes (with -a) |
| MEDIUM | Yellow | Some concerning patterns, review carefully | No |
| HIGH | Red | Significant security risks | No |
| CRITICAL | Magenta | Severe security threats, do not execute | No |

## Configuration

scurl stores your configuration in `~/.scurl/config.toml`:

```toml
provider = "xai"
api_key = "xai-xxxxxxxxxxxxx"
model = "grok-2-latest"  # optional
```

### Managing Configuration

```bash
# View current config
scurl config

# Reconfigure (change provider or API key)
scurl login

# Override for one command
scurl --provider anthropic --api-key sk-ant-xxx URL
```

### Supported Providers

| Provider | Models | Best For |
|----------|--------|----------|
| **Anthropic** | Claude Sonnet 4.5 (default), Opus, Haiku | Detailed analysis, comprehensive reviews |
| **xAI** | Grok 2 (default) | Fast analysis, real-time awareness |
| **OpenAI** | GPT-4o (default), GPT-4 Turbo | Widely available, familiar interface |

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Fast setup guide with `scurl login`
- **[USAGE.md](USAGE.md)** - Detailed usage examples and workflows
- **[NETWORK.md](NETWORK.md)** - Comprehensive network & proxy configuration
- **[ANIMATIONS.md](ANIMATIONS.md)** - Visual feedback and spinner guide
- **[SECURITY.md](SECURITY.md)** - Security best practices and API key protection
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[MIGRATION.md](MIGRATION.md)** - Upgrade guide from older versions
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes

## Enterprise/Corporate Use

scurl is designed to work seamlessly in enterprise environments:

### Behind Corporate Proxy
```bash
# Set proxy in environment
export HTTPS_PROXY=http://proxy.corporate.com:8080

# Or use flag
scurl --proxy http://proxy.corporate.com:8080 URL
```

### With Self-Signed Certificates
```bash
# For internal servers (dev/test only)
scurl --insecure https://internal-server.corp/script.sh
```

### API Authentication
```bash
# Private APIs with custom headers
scurl -H "Authorization: Bearer $TOKEN" https://api.company.com/script.sh
```

### CI/CD Integration
```yaml
# GitHub Actions
- name: Install tool with scurl
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    scurl login  # Use env var
    scurl --auto-execute https://example.com/install.sh
```

See [NETWORK.md](NETWORK.md) for comprehensive corporate setup guides.

## Safety Notes

- ⚠️ AI analysis is powerful but not perfect
- ⚠️ Always review the findings before executing
- ⚠️ Be especially cautious with CRITICAL or HIGH risk scripts
- ⚠️ The `--auto-execute` flag only triggers for SAFE/LOW risk levels
- ⚠️ When in doubt, manually review the script yourself
- ⚠️ Never use `--yolo` mode unless you trust the source completely
- ⚠️ `--insecure` disables SSL verification - only use for testing

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/wagnerio/scurl.git
cd scurl

# Enable git hooks (IMPORTANT - prevents committing secrets!)
git config core.hooksPath .githooks

# Build and test
cargo build
cargo test
cargo clippy
```

### Git Hooks

This project includes a smart pre-commit hook that prevents accidentally committing API keys:

- ✅ Automatically installed when you run `git config core.hooksPath .githooks`
- ✅ Blocks real API keys in code files (40+ character keys)
- ✅ Allows placeholder examples in documentation (e.g., `sk-ant-xxx`)
- ✅ Prevents committing `config.toml` files
- ✅ Shows clear error messages with suggestions

**Why this matters:** API keys are secrets and should never be committed to version control!

### Areas for Improvement

- Script sandboxing for safer execution
- Checksum verification for downloaded scripts
- Source reputation scoring based on domain
- Caching of known-safe scripts (hash-based)
- Browser extension integration
- Support for additional AI providers
- Enhanced analysis prompts for specific script types
- Batch mode for analyzing multiple scripts
- Web dashboard for analysis history

## Examples

### Real-World Usage

```bash
# Homebrew (macOS)
scurl --auto-execute https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh

# Rustup (Rust toolchain)
scurl --auto-execute https://sh.rustup.rs

# NVM (Node Version Manager)
scurl https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh

# Docker
scurl https://get.docker.com

# Behind corporate proxy
scurl --proxy http://proxy.corp.com:8080 https://get.docker.com
```

### Corporate Environment

```bash
# Set up for corporate use
export HTTPS_PROXY=http://proxy.company.com:8080
scurl login  # Choose your provider

# Daily usage
scurl --auto-execute https://internal-tools.company.com/setup.sh

# With authentication
scurl -H "X-Corp-Token: $TOKEN" https://api.company.com/deploy.sh
```

## Troubleshooting

### "No configuration found"
Run `scurl login` to set up your API provider.

### "API error 401"
Your API key is invalid. Run `scurl login` to update it.

### Connection timeout
```bash
# Increase timeout and retries
scurl --timeout 60 --retries 5 URL
```

### Proxy issues
```bash
# Check proxy is set
echo $HTTPS_PROXY

# Try without proxy
scurl --no-proxy URL

# Or specify different proxy
scurl --proxy http://other-proxy:8080 URL
```

### SSL certificate errors
```bash
# For internal/dev servers only
scurl --insecure URL

# Better: Add CA cert to system trust store
```

See [NETWORK.md](NETWORK.md) for detailed troubleshooting.

## License

MIT License - see [LICENSE](LICENSE) file

## Disclaimer

scurl is a tool to assist with security analysis, not a guarantee of safety. Users are responsible for reviewing the analysis and making informed decisions about script execution. The authors are not liable for any damages resulting from the use of this tool.

## Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) 🦀
- AI analysis powered by:
  - [Anthropic Claude](https://www.anthropic.com/)
  - [xAI Grok](https://x.ai/)
  - [OpenAI GPT](https://openai.com/)
- HTTP client: [reqwest](https://github.com/seanmonstar/reqwest)
- CLI framework: [clap](https://github.com/clap-rs/clap)
- Spinners: [indicatif](https://github.com/console-rs/indicatif)

---

**Made with 🦀 Rust and 🤖 AI**

**Stop running untrusted code. Start using scurl.** 🔒

[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

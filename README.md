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

## Features

- 🤖 **AI Security Analysis** - Uses Claude to detect suspicious patterns, malicious code, and security risks
- 🎨 **Clear Risk Classification** - Safe, Low, Medium, High, or Critical risk levels
- 🚦 **Interactive Execution** - Review findings and decide whether to proceed
- ⚡ **Auto-execute Mode** - Automatically run scripts classified as safe (with `--auto-execute`)
- 🔍 **Detailed Findings** - Get specific security concerns explained
- 🛡️ **Safe by Default** - Nothing executes without your approval

## Installation

### From Source

```bash
git clone https://github.com/yourusername/scurl.git
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

### Initial Setup

After installation, run the interactive setup:

```bash
scurl login
```

This will guide you through:
1. Selecting your AI provider (Anthropic, xAI, or OpenAI)
2. Entering your API key
3. Optional: Choosing a custom model
4. Testing the connection

Your configuration is saved to `~/.scurl/config.toml`

## Usage

### Basic Usage

After running `scurl login`, just use scurl with any install script URL:

```bash
# Review and potentially execute a script
scurl https://example.com/install.sh
```

The script will be:
1. Downloaded
2. Analyzed by your configured AI provider
3. Results displayed with risk level and findings
4. You decide whether to execute

### Auto-execute Safe Scripts

```bash
# Automatically execute if classified as safe/low risk
scurl --auto-execute https://example.com/install.sh
```

### Specify Shell

```bash
# Use sh instead of bash
scurl --shell sh https://example.com/install.sh
```

### YOLO Mode (Not Recommended)

```bash
# Skip security review entirely (defeats the purpose!)
scurl --yolo https://example.com/install.sh
```

### Full Options

```bash
scurl [OPTIONS] <URL>

Arguments:
  <URL>  URL of the install script to download and review

Options:
  -s, --shell <SHELL>          Shell to use for execution [default: bash]
  -a, --auto-execute           Auto-execute if classified as probably safe
  -k, --api-key <API_KEY>      Anthropic API key [env: ANTHROPIC_API_KEY]
      --yolo                   Skip AI review and just download + execute
  -h, --help                   Print help
```

## How It Works

1. **Download** - Fetches the script from the provided URL
2. **Analyze** - Sends the script to Claude for security analysis
3. **Report** - Displays risk level, specific findings, and recommendations
4. **Decide** - Prompts for user confirmation (or auto-executes if safe + flag set)
5. **Execute** - Runs the script in a temporary file with your chosen shell

## Security Analysis

The AI examines scripts for:

- ✅ Suspicious commands (`eval`, `base64` decoding, nested `curl | bash`)
- ✅ Downloads from untrusted sources
- ✅ Privilege escalation attempts
- ✅ Code obfuscation
- ✅ Credential harvesting
- ✅ Backdoor installation patterns
- ✅ Malicious payloads
- ✅ Destructive operations (`rm -rf`, `dd`, etc.)

## Example Output

```
🔒 scurl - Secure Script Execution

Downloading script...
Download complete (1247 bytes)
Analyzing script with AI...

═══════════════════════════════════════════════════
           SECURITY ANALYSIS REPORT
═══════════════════════════════════════════════════

Risk Level: LOW

Findings:
  1. Uses sudo for package installation (expected for system-wide tools)
  2. Downloads binary from GitHub releases (official source)
  3. Verifies checksum before installation

Recommendation:
  This script appears safe. It follows best practices by verifying
  downloads and using official package sources. Safe to execute.
═══════════════════════════════════════════════════

Execute this script? [y/N]:
```

## Configuration

scurl stores your configuration in `~/.scurl/config.toml`:

```toml
provider = "xai"
api_key = "xai-xxxxxxxxxxxxx"
model = "grok-2-latest"  # optional
```

You can:
- **View config**: `scurl config`
- **Update config**: `scurl login` (re-run to change provider or key)
- **Override temporarily**: Use `--provider` and `--api-key` flags

## Safety Notes

- scurl uses AI analysis which, while powerful, is not perfect
- Always review the findings before executing
- Be especially cautious with CRITICAL or HIGH risk scripts
- The `--auto-execute` flag only triggers for SAFE/LOW risk levels
- When in doubt, manually review the script yourself

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/scurl.git
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
- ✅ Blocks real API keys in code files
- ✅ Allows placeholder examples in documentation (e.g., `sk-ant-xxx`)
- ✅ Checks for `config.toml` files

**Why this matters:** API keys are secrets and should never be committed to version control!

### Areas for Improvement

- Additional security checks
- Enhanced AI analysis prompts
- Script sandboxing
- Checksum verification
- Source reputation scoring
- Caching of known-safe scripts
- Browser extension integration

## License

MIT License - see LICENSE file

## Disclaimer

scurl is a tool to assist with security analysis, not a guarantee of safety. Users are responsible for reviewing the analysis and making informed decisions about script execution. The authors are not liable for any damages resulting from the use of this tool.

---

**Made with 🦀 Rust and 🤖 Claude**

*Stop running untrusted code. Start using scurl.*

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
cargo install --path .
```

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- Anthropic API key (get one at [console.anthropic.com](https://console.anthropic.com))

## Usage

### Basic Usage

```bash
# Set your API key
export ANTHROPIC_API_KEY=sk-ant-...

# Review and potentially execute a script
scurl https://example.com/install.sh
```

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

## Environment Variables

- `ANTHROPIC_API_KEY` - Your Anthropic API key (required)

## Safety Notes

- scurl uses AI analysis which, while powerful, is not perfect
- Always review the findings before executing
- Be especially cautious with CRITICAL or HIGH risk scripts
- The `--auto-execute` flag only triggers for SAFE/LOW risk levels
- When in doubt, manually review the script yourself

## Contributing

Contributions welcome! Areas for improvement:

- Additional security checks
- Support for other AI providers
- Script sandboxing
- Checksum verification
- Source reputation scoring
- Caching of known-safe scripts

## License

MIT License - see LICENSE file

## Disclaimer

scurl is a tool to assist with security analysis, not a guarantee of safety. Users are responsible for reviewing the analysis and making informed decisions about script execution. The authors are not liable for any damages resulting from the use of this tool.

---

**Made with 🦀 Rust and 🤖 Claude**

*Stop running untrusted code. Start using scurl.*

# scurl

AI-powered security review for installation scripts. Stop blindly piping `curl | bash`.

## The Problem

```bash
curl -fsSL https://example.com/install.sh | bash
```

You're executing unreviewed code with your user privileges. scurl downloads the script, sends it to an AI for security analysis, shows you the findings, and lets you decide whether to execute.

## Install

```bash
git clone https://github.com/wagnerio/scurl.git
cd scurl
cargo install --path .
```

Requires Rust 1.70+ ([rustup.rs](https://rustup.rs)).

## Setup

```bash
scurl login
```

Choose your AI provider, enter credentials (or skip for Ollama), done. Config is saved to `~/.scurl/config.toml` with `0600` permissions.

### Providers

| Provider | Default Model | API Key |
|----------|---------------|---------|
| **Anthropic** | claude-sonnet-4-5 | [console.anthropic.com](https://console.anthropic.com) |
| **xAI** | grok-2-latest | [console.x.ai](https://console.x.ai) |
| **OpenAI** | gpt-4o | [platform.openai.com](https://platform.openai.com/api-keys) |
| **Ollama** | llama3.2 | None required ([ollama.ai](https://ollama.ai)) |

## Usage

```bash
scurl https://get.docker.com                # Analyze a script
scurl -a https://sh.rustup.rs               # Auto-execute if safe
scurl -p anthropic URL                      # Override provider
scurl config                                # View current config
scurl login                                 # Reconfigure
```

### Example Output

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

### Risk Levels

| Level | Auto-execute (`-a`)? | Meaning |
|-------|----------------------|---------|
| SAFE | Yes | No security concerns |
| LOW | Yes | Minor concerns, generally acceptable |
| MEDIUM | No | Concerning patterns, review carefully |
| HIGH | No | Significant security risks |
| CRITICAL | No | Severe threats, do not execute |

### Network & Proxy

```bash
scurl -x http://proxy.corp.com:8080 URL        # Proxy
scurl -k URL                                    # Skip SSL verification
scurl -H "Authorization: Bearer $TOKEN" URL     # Custom headers
scurl --timeout 60 --retries 5 URL              # Timeouts & retries
```

Environment variables `HTTPS_PROXY` and `HTTP_PROXY` are respected automatically. See [NETWORK.md](NETWORK.md) for full proxy and enterprise configuration.

### Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--auto-execute` | `-a` | Auto-execute safe/low risk scripts |
| `--shell <SHELL>` | `-s` | Shell for execution (default: bash) |
| `--provider <NAME>` | `-p` | Override configured provider |
| `--api-key <KEY>` | | Override configured API key |
| `--proxy <URL>` | `-x` | HTTP/HTTPS proxy |
| `--timeout <SECS>` | `-t` | Request timeout (default: 30) |
| `--retries <N>` | | Retry attempts (default: 3) |
| `--insecure` | `-k` | Disable SSL verification |
| `--header <H>` | `-H` | Add custom header |
| `--user-agent <UA>` | `-A` | Custom User-Agent |
| `--max-redirects <N>` | | Max redirects (default: 10) |
| `--system-proxy` | | Use system proxy settings |
| `--no-proxy` | | Disable proxy |
| `--yolo` | | Skip AI review entirely |
| `--version` | `-V` | Print version |

## How It Works

1. **Download** the script with retry logic and size limits (10 MB max)
2. **Analyze** via your configured AI provider for security issues
3. **Report** risk level, findings, and recommendation
4. **Prompt** for confirmation (or auto-execute with `-a` if safe)
5. **Execute** in a temporary file with your chosen shell

The AI checks for: suspicious commands (`eval`, `base64`, nested `curl | bash`), untrusted downloads, privilege escalation, code obfuscation, credential harvesting, backdoor patterns, and destructive operations.

## CI/CD

```yaml
# GitHub Actions
- name: Install tool with scurl
  run: |
    scurl --provider anthropic --api-key ${{ secrets.ANTHROPIC_API_KEY }} \
      --auto-execute https://example.com/install.sh
```

## Development

```bash
git config core.hooksPath .githooks   # Enable secret-detection hooks
make test                              # Run tests (14 total)
make check                             # fmt + clippy + audit
make lint                              # Strict clippy
make build                             # Release build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Safety

AI analysis is helpful but not infallible. Always review the findings, especially for HIGH and CRITICAL risk scripts. The `--yolo` flag bypasses all review -- use it only with sources you fully trust.

## License

MIT -- see [LICENSE](LICENSE)

## Further Reading

- [NETWORK.md](NETWORK.md) -- Proxy, TLS, headers, enterprise network configuration
- [SECURITY.md](SECURITY.md) -- API key protection and security practices
- [CONTRIBUTING.md](CONTRIBUTING.md) -- Development setup and contribution guidelines
- [CHANGELOG.md](CHANGELOG.md) -- Version history
- [USAGE.md](USAGE.md) -- Extended usage examples and workflows

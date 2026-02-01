# scurl (security check url)

AI-powered security review for installation scripts. Stop blindly piping `curl | bash`.

## The Problem

```bash
curl -fsSL https://example.com/install.sh | bash
```

You're executing unreviewed code with your user privileges. scurl downloads the script, runs static analysis for dangerous patterns and prompt injection, sends it to an AI for security analysis, shows you the findings, and lets you decide whether to execute.

## Install

### From crates.io

```bash
cargo install scurl
```

### From source

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

Choose your AI provider, enter credentials (or skip for Ollama), done. Config is saved to `~/.scurl/config.toml` with `0600` permissions in a `0700` directory. API keys are stored in the OS keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service) when available, falling back to plaintext config with a warning.

For maximum security, use the `SCURL_API_KEY` environment variable instead of storing the key in the config file.

### Providers

| Provider | Default Model | API Key |
|----------|---------------|---------|
| **Anthropic** | claude-haiku-4-5 | [console.anthropic.com](https://console.anthropic.com) |
| **xAI** | grok-4-1-fast-reasoning | [console.x.ai](https://console.x.ai) |
| **OpenAI** | gpt-5-nano | [platform.openai.com](https://platform.openai.com/api-keys) |
| **Azure OpenAI** | gpt-5-nano | [portal.azure.com](https://portal.azure.com) |
| **Google Gemini** | gemini-2.5-flash | [aistudio.google.com](https://aistudio.google.com/app/apikey) |
| **Ollama** | llama3.2 | None required ([ollama.ai](https://ollama.ai)) |

Azure OpenAI requires an endpoint URL and deployment name during setup. These can also be set via `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_DEPLOYMENT` environment variables.

## Usage

```bash
scurl https://get.docker.com                # Analyze a script
scurl -a https://sh.rustup.rs               # Auto-execute if safe
scurl -p anthropic URL                      # Override provider
scurl config                                # View current config
scurl login                                 # Reconfigure
scurl skill                                 # Output Claude Code skill
```

### Example Output

```
🔒 scurl - Secure Script Execution

⠋ Downloading script...
✓ Downloaded 1247 bytes

✓ Static analysis: No suspicious patterns detected

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

Auto-execute is also blocked when static analysis finds critical issues, regardless of the AI risk level.

### Network & Proxy

```bash
scurl -x http://proxy.corp.com:8080 URL        # Proxy
scurl -k URL                                    # Skip SSL verification (script downloads only)
scurl -H "Authorization: Bearer $TOKEN" URL     # Custom headers
scurl --timeout 60 --retries 5 URL              # Timeouts & retries
```

Environment variables `HTTPS_PROXY` and `HTTP_PROXY` are respected automatically. Proxy URLs must use `http`, `https`, `socks5`, or `socks5h` schemes. See [NETWORK.md](NETWORK.md) for full proxy and enterprise configuration.

### Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--auto-execute` | `-a` | Auto-execute safe/low risk scripts |
| `--shell <SHELL>` | `-s` | Shell for execution (default: bash) |
| `--provider <NAME>` | `-p` | Override configured provider |
| `--proxy <URL>` | `-x` | HTTP/HTTPS proxy |
| `--timeout <SECS>` | `-t` | Request timeout (default: 30) |
| `--retries <N>` | | Retry attempts (default: 3) |
| `--insecure` | `-k` | Disable SSL verification (script downloads only) |
| `--header <H>` | `-H` | Add custom header |
| `--user-agent <UA>` | `-A` | Custom User-Agent |
| `--max-redirects <N>` | | Max redirects (default: 10) |
| `--system-proxy` | | Use system proxy settings |
| `--no-proxy` | | Disable proxy |
| `--no-sandbox` | | Disable sandboxed script execution |
| `--version` | `-V` | Print version |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SCURL_API_KEY` | Override API key (preferred over config file) |
| `HTTPS_PROXY` | Proxy URL for all requests |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL |
| `AZURE_OPENAI_DEPLOYMENT` | Azure OpenAI deployment name |

## How It Works

1. **Validate** the URL (only `http`/`https` schemes allowed)
2. **Download** the script with streaming, retry logic, and size limits (10 MB max)
3. **Static analysis** scans for 22 dangerous patterns: shell exploits, reverse shells, data exfiltration, and prompt injection attempts
4. **AI analysis** via your configured provider, with static findings forwarded for context (responses capped at 1 MB)
5. **Report** risk level, findings, and recommendation
6. **Prompt** for confirmation (or auto-execute with `-a` if safe and no critical static findings)
7. **Execute** in a temporary file (`0700` permissions) with your chosen shell

### Static Analysis

Before AI review, scurl runs a built-in pattern scanner that detects:

**Shell Security** -- `eval` with dynamic content, base64-to-shell pipes, curl/wget piped to bash, `chmod 777`, `rm -rf /`, `/dev/tcp` redirections, reverse shells (`nc -e`), `LD_PRELOAD` injection, crontab manipulation, SSH key injection, direct disk writes, Python exec, history evasion, environment exfiltration, silent downloads to `/tmp`

**Prompt Injection** -- fake `RISK_LEVEL: SAFE` embedded in scripts, "ignore previous instructions", fake analysis output, AI role-play attempts, prompt override attempts, hidden base64 payloads in comments, markdown fence escape attempts

When prompt injection is detected, auto-execute is blocked regardless of the AI risk level.

## CI/CD

```yaml
# GitHub Actions
- name: Install tool with scurl
  env:
    SCURL_API_KEY: ${{ secrets.SCURL_API_KEY }}
  run: |
    scurl --provider anthropic --auto-execute https://example.com/install.sh
```

## Security

### Split HTTP Clients

scurl uses separate HTTP clients for script downloads and API calls. The `--insecure` flag only affects script downloads -- API calls to your AI provider always enforce TLS certificate verification.

### Atomic Config Writes

Configuration files are written atomically using temp-file-then-rename to prevent TOCTOU race conditions. Directory permissions are set to `0700` and file permissions to `0600` before any secrets are written.

### Content-Type Validation

Downloads are rejected if the content type indicates a non-script file (images, videos, PDFs, executables, archives). Ambiguous types produce a warning.

### Retry with Backoff

Network retries use exponential backoff with jitter (1s, 2s, 4s... capped at 30s) to avoid thundering herd issues. Client errors (4xx) are not retried.

### Sandboxed Execution

Scripts run inside an OS-level sandbox by default. Network access is denied, the filesystem is read-only (except `/tmp`), and all Linux capabilities are dropped (`--cap-drop ALL`). On Linux, scurl uses [bubblewrap](https://github.com/containers/bubblewrap) (preferred) or firejail as a fallback. On macOS, it uses `sandbox-exec`. If no backend is found, execution is refused with install instructions. Opt out with `--no-sandbox`. See [SECURITY.md](SECURITY.md) for full details.

### Limitations

AI analysis is helpful but not infallible. Always review the findings, especially for HIGH and CRITICAL risk scripts.

## Development

```bash
git config core.hooksPath .githooks   # Enable secret-detection hooks
cargo test --all-features             # Run tests
cargo clippy -- -D warnings           # Lint
cargo build --release                 # Release build
```

The pre-commit hook detects Anthropic, OpenAI, xAI, and AWS keys in staged files.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT -- see [LICENSE](LICENSE)

## Further Reading

- [NETWORK.md](NETWORK.md) -- Proxy, TLS, headers, enterprise network configuration
- [SECURITY.md](SECURITY.md) -- API key protection and security practices
- [CONTRIBUTING.md](CONTRIBUTING.md) -- Development setup and contribution guidelines
- [CHANGELOG.md](CHANGELOG.md) -- Version history
- [USAGE.md](USAGE.md) -- Extended usage examples and workflows

# scurl Usage Guide

## Quick Start

1. **Get an API Key**
   
   Sign up for an Anthropic API key at [console.anthropic.com](https://console.anthropic.com)

2. **Set your API key**
   
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```
   
   Or add to your `~/.bashrc` or `~/.zshrc`:
   
   ```bash
   echo 'export ANTHROPIC_API_KEY=sk-ant-your-key-here' >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Use scurl instead of curl | bash**
   
   Traditional (unsafe):
   ```bash
   curl -fsSL https://example.com/install.sh | bash
   ```
   
   Secure (with scurl):
   ```bash
   scurl https://example.com/install.sh
   ```

## Common Workflows

### Interactive Review (Default)

Review the security analysis and decide:

```bash
scurl https://get.docker.com
```

Output:
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
  1. Uses sudo for package installation
  2. Downloads from official Docker repository
  ...

Execute this script? [y/N]:
```

### Automated Execution for Safe Scripts

Auto-execute if classified as safe/low risk:

```bash
scurl --auto-execute https://rustup.rs
```

This will:
- Download the script
- Analyze it with AI
- **Automatically execute if SAFE or LOW risk**
- Prompt for confirmation if MEDIUM, HIGH, or CRITICAL

### Testing Example Scripts

Try the included examples:

```bash
# Serve examples locally (requires Python)
cd examples
python3 -m http.server 8000 &

# Test safe script
scurl http://localhost:8000/safe-example.sh

# Test suspicious script (DO NOT execute!)
scurl http://localhost:8000/suspicious-example.sh

# Test realistic script
scurl http://localhost:8000/realistic-example.sh
```

## Risk Levels Explained

| Level    | Color   | Meaning | Auto-execute? |
|----------|---------|---------|---------------|
| SAFE     | Green   | No security concerns found | Yes (with -a) |
| LOW      | Cyan    | Minor concerns, generally acceptable | Yes (with -a) |
| MEDIUM   | Yellow  | Some concerning patterns, review carefully | No |
| HIGH     | Red     | Significant security risks | No |
| CRITICAL | Magenta | Severe security threats, do not execute | No |

## Shell Selection

Default is `bash`, but you can specify `sh` or others:

```bash
scurl --shell sh https://example.com/install.sh
scurl --shell zsh https://example.com/install.sh
```

## Providing API Key

Three ways to provide your API key:

1. **Environment variable (recommended)**
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   scurl https://example.com/install.sh
   ```

2. **Command line flag**
   ```bash
   scurl -k sk-ant-... https://example.com/install.sh
   ```

3. **`.env` file** (if you modify the code to load dotenv)
   ```bash
   echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
   scurl https://example.com/install.sh
   ```

## Integration with Existing Scripts

### Alias curl for added safety

Add to your shell config:

```bash
alias curlbash='scurl'
```

Then instead of:
```bash
curl -fsSL url | bash
```

Use:
```bash
curlbash url
```

### Use in CI/CD

```yaml
- name: Install tool
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    cargo install scurl
    scurl --auto-execute https://example.com/install.sh
```

## Troubleshooting

### "API error 401"

Your API key is invalid or not set. Check:
```bash
echo $ANTHROPIC_API_KEY
```

### "Failed to download script"

- Check your internet connection
- Verify the URL is correct
- The server might be rate-limiting (use curl directly to test)

### Script executes but fails

scurl analyzes security, not correctness. A safe script might still:
- Have bugs
- Be incompatible with your system
- Require dependencies not installed

### False positives

AI analysis isn't perfect. If you trust the source:
- Review the findings
- Make an informed decision
- Use `--yolo` mode at your own risk (not recommended)

## Advanced Usage

### Inspect without executing

1. Run scurl
2. Review the analysis
3. Answer "N" to the execution prompt
4. Manually download and inspect:
   ```bash
   curl -fsSL https://example.com/install.sh > script.sh
   less script.sh
   ```

### Combine with other tools

```bash
# Download, analyze, but execute in Docker
scurl https://example.com/install.sh  # Review only
docker run -it ubuntu bash -c "$(curl -fsSL https://example.com/install.sh)"
```

## Best Practices

1. ✅ **Always review the findings** - Don't blindly trust any automation
2. ✅ **Verify the source** - Even if scurl says safe, ensure you trust the origin
3. ✅ **Use HTTPS URLs** - Avoid plain HTTP to prevent MITM attacks
4. ✅ **Check official sources** - Compare URL with official documentation
5. ❌ **Don't use --yolo** unless you know what you're doing
6. ❌ **Don't auto-execute on untrusted sources** - Reserve -a for known repos

## Example Real-World Usage

```bash
# Homebrew (if you trust it)
scurl --auto-execute https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh

# Rustup
scurl --auto-execute https://sh.rustup.rs

# NVM (Node Version Manager)
scurl https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh

# Unknown script - review carefully
scurl https://random-site.com/install.sh
```

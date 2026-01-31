# Security Policy

## Protecting Your API Keys

scurl stores your API keys in `~/.scurl/config.toml`. Here's how to keep them secure:

### ⚠️ NEVER Commit API Keys

**Files that contain secrets:**
- `~/.scurl/config.toml` - Your personal config (in home directory)
- `config.toml` - Any test configs in the project directory
- `.env` files - Environment variable files

These are already in `.gitignore`, but always double-check before committing!

### ✅ Secure Your Config File

```bash
# Set restrictive permissions on your config
chmod 600 ~/.scurl/config.toml

# Verify permissions
ls -la ~/.scurl/config.toml
# Should show: -rw------- (only you can read/write)
```

### 🔒 Best Practices

#### 1. Keep API Keys Private
- Never share your `config.toml`
- Don't post screenshots with API keys visible
- Don't commit config files to version control
- Rotate keys if they're exposed

#### 2. Use Read-Only or Limited Scopes
When available, use API keys with minimal required permissions:
- **Anthropic**: Use keys with API access only
- **xAI**: Limit to model access
- **OpenAI**: Use project-scoped keys
- **Ollama**: No API key needed -- runs locally

#### 3. Rotate Keys Regularly
```bash
# Update your API key
scurl login  # Re-run to update

# Or manually edit config
nano ~/.scurl/config.toml
```

#### 4. Secure Your System
- Use full-disk encryption
- Lock your screen when away
- Don't run scurl as root unnecessarily
- Keep your OS updated

#### 5. CI/CD Secrets Management
When using scurl in CI/CD, use proper secret management:

**GitHub Actions:**
```yaml
- name: Run scurl
  env:
    API_KEY: ${{ secrets.SCURL_API_KEY }}
  run: |
    scurl --api-key "$API_KEY" --provider xai https://example.com/install.sh
```

**GitLab CI:**
```yaml
script:
  - scurl --api-key $SCURL_API_KEY --provider anthropic https://example.com/install.sh
```

Never hardcode keys in CI config files!

## Reporting Security Issues

If you discover a security vulnerability in scurl:

### What to Report
- Security bugs in scurl code
- Vulnerabilities in dependencies
- Issues with secret handling
- API key exposure risks

### How to Report

**For sensitive issues:**
1. **DO NOT** open a public GitHub issue
2. Email: [your-security-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

**For non-sensitive issues:**
- Open a GitHub issue with `[SECURITY]` prefix
- Provide details without exposing actual vulnerabilities

### Response Timeline
- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix timeline**: Depends on severity
  - Critical: 1-3 days
  - High: 1 week
  - Medium: 2 weeks
  - Low: Best effort

## Security Features in scurl

### What scurl Does

✅ **Stores keys locally** - Not sent anywhere except to configured API  
✅ **HTTPS only** - All API calls use secure connections  
✅ **No telemetry** - We don't collect usage data  
✅ **Open source** - Code is auditable  
✅ **Sandboxed execution** - Scripts run in temporary files  

### What scurl Doesn't Do

❌ **No key encryption** - Config file is plain text (OS-level encryption recommended)  
❌ **No key rotation** - You must manually update keys  
❌ **No audit logging** - No built-in logging of API calls  
❌ **No multi-user support** - One config per user account  

## API Key Security by Provider

### Anthropic
- Keys format: `sk-ant-...`
- Dashboard: https://console.anthropic.com
- Can delete keys anytime
- No automatic expiration

**If compromised:**
1. Delete key in Anthropic console
2. Generate new key
3. Run `scurl login` with new key

### xAI
- Keys format: `xai-...`
- Dashboard: https://console.x.ai
- Can revoke keys anytime

**If compromised:**
1. Revoke key in xAI console
2. Generate new key
3. Run `scurl login` with new key

### OpenAI
- Keys format: `sk-...`
- Dashboard: https://platform.openai.com/api-keys
- Can set expiration dates
- Project-scoped keys available

**If compromised:**
1. Revoke key in OpenAI dashboard
2. Generate new project-scoped key
3. Run `scurl login` with new key

### Ollama
- No API key stored (uses placeholder)
- Runs entirely on localhost
- No credentials to compromise
- Scripts are only sent to your local machine

## Script Execution Security

scurl analyzes scripts but execution is still risky:

### Before Executing
- ✅ Review the AI analysis findings
- ✅ Check the source URL is trusted
- ✅ Verify HTTPS is used
- ✅ Read the recommendation
- ✅ Consider the risk level

### Safe Execution Practices
```bash
# Always review first (don't auto-execute untrusted sources)
scurl https://unknown-site.com/install.sh

# Only auto-execute from trusted sources
scurl -a https://sh.rustup.rs  # Rust's official installer

# Test in a container first
docker run -it ubuntu bash
# Inside container: scurl https://example.com/install.sh
```

### Understanding Risk Levels

| Level | Meaning | Action |
|-------|---------|--------|
| **SAFE** | No concerns found | Generally safe to execute |
| **LOW** | Minor concerns | Review findings, usually safe |
| **MEDIUM** | Some risks | Carefully review before executing |
| **HIGH** | Significant risks | Only execute if you understand the risks |
| **CRITICAL** | Severe threats | DO NOT EXECUTE |

### AI Analysis Limitations

⚠️ **Important**: AI analysis is not perfect!

- Can miss sophisticated attacks
- May have false positives
- Context-dependent (official repo vs. random site)
- No guarantee of safety

**Always use your judgment!**

## Secure Development

If you're contributing to scurl:

### Guidelines
- Never log API keys or secrets
- Validate all user input
- Use secure dependencies
- Follow Rust security best practices
- Run `cargo audit` regularly

### Testing
```bash
# Check for vulnerabilities
cargo audit

# Run security-focused lints
cargo clippy -- -D warnings

# Format code
cargo fmt
```

## Additional Resources

- [OWASP API Security](https://owasp.org/www-project-api-security/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [Anthropic API Security](https://docs.anthropic.com/claude/reference/security)

## Questions?

Security questions? Open an issue with the `[SECURITY]` tag or contact the maintainers.

---

**Stay secure. Review scripts. Protect your keys.** 🔒

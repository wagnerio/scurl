# Migration Guide: scurl v0.1.0 → v0.2.0

## What's New

### 🎯 Multi-Provider Support
- **Anthropic (Claude)** - Sonnet, Opus, Haiku
- **xAI (Grok)** - Grok 2
- **OpenAI (GPT)** - GPT-4, GPT-4o

### 🔧 Interactive Setup
- New `scurl login` command for easy configuration
- No more manual environment variables
- Config stored in `~/.scurl/config.toml`

### 📦 Subcommands
- `scurl login` - Configure provider
- `scurl config` - View configuration
- `scurl analyze <URL>` - Explicit analyze command
- `scurl <URL>` - Shorthand still works!

## Breaking Changes

### Old Way (v0.1.0)
```bash
export ANTHROPIC_API_KEY=sk-ant-xxx
scurl https://example.com/install.sh
```

### New Way (v0.2.0)
```bash
# One-time setup
scurl login

# Then use normally
scurl https://example.com/install.sh
```

## Migration Steps

### 1. Run Initial Setup
```bash
scurl login
```

Select your provider and enter your API key.

### 2. Update Scripts/Aliases
**Before:**
```bash
#!/bin/bash
export ANTHROPIC_API_KEY=sk-ant-xxx
scurl https://example.com/install.sh
```

**After:**
```bash
#!/bin/bash
# No env vars needed - config is persistent
scurl https://example.com/install.sh
```

### 3. CI/CD Updates

**Before:**
```yaml
- name: Install tool
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: scurl --auto-execute https://example.com/install.sh
```

**After (Option 1 - Use config override):**
```yaml
- name: Install tool
  run: |
    scurl --api-key ${{ secrets.XAI_API_KEY }} \
          --provider xai \
          --auto-execute \
          https://example.com/install.sh
```

**After (Option 2 - Use login):**
```yaml
- name: Setup scurl
  run: |
    echo -e "2\n${{ secrets.XAI_API_KEY }}\n" | scurl login

- name: Install tool
  run: scurl --auto-execute https://example.com/install.sh
```

## Backward Compatibility

### Environment Variables (Removed)
- `ANTHROPIC_API_KEY` is **no longer used**
- Use `scurl login` or `--api-key` flag instead

### CLI Flags (Changed)
- `-k, --api-key` now **overrides** config (was: required or from env)
- `-p, --provider` is **new** - override provider from config

### Positional Arguments (Same)
- `scurl <URL>` still works as shorthand!
- No changes to core workflow

## Feature Comparison

| Feature | v0.1.0 | v0.2.0 |
|---------|--------|--------|
| Providers | Anthropic only | Anthropic, xAI, OpenAI |
| Configuration | Env vars only | Persistent config file |
| Setup | Manual | Interactive `scurl login` |
| API Key | Required per-invocation | Stored securely |
| Custom models | ❌ | ✅ |
| Provider switching | ❌ | ✅ |

## Examples

### Switching from Anthropic to xAI

```bash
# Run login again
scurl login

# Select xAI (option 2)
# Enter your xai API key

# Done! Now all commands use xAI
scurl https://example.com/install.sh
```

### One-Time Provider Override

```bash
# Configured with xAI, but want to use Anthropic once
scurl --provider anthropic \
      --api-key sk-ant-xxx \
      https://example.com/install.sh
```

### View Current Config

```bash
scurl config
```

Output:
```
Current Configuration
══════════════════════════════════════════════════

Provider:       xAI (Grok)
API Key:        xai-ab...xyz
Model:          grok-2-latest (default)
Config File:    /Users/you/.scurl/config.toml

══════════════════════════════════════════════════

To reconfigure, run: scurl login
```

## Troubleshooting

### "No configuration found"
**Solution:** Run `scurl login` to create your config file.

### "API error 401"
**Solution:** Your API key is invalid. Run `scurl login` to update it.

### Want to use old environment variable?
**Workaround:** Use the override flag:
```bash
scurl --api-key $ANTHROPIC_API_KEY --provider anthropic <URL>
```

### Config file location
**Location:** `~/.scurl/config.toml`

**Permissions:** `chmod 600 ~/.scurl/config.toml` (recommended)

## Rollback

If you need to revert to v0.1.0:

```bash
git checkout v0.1.0
cargo install --path .

# Restore environment variable usage
export ANTHROPIC_API_KEY=sk-ant-xxx
```

---

Questions? Open an issue: https://github.com/yourusername/scurl/issues

# scurl Quick Start Guide

Stop running `curl | bash` blindly. Use scurl for AI-powered security reviews!

## Installation

```bash
cargo install --path .
# OR
sudo make install
```

## First Time Setup (NEW!)

Run the interactive setup to configure your AI provider:

```bash
scurl login
```

### What happens during login:

1. **Choose your AI provider:**
   - Anthropic (Claude Sonnet 4.5, Haiku, Opus)
   - xAI (Grok 2)
   - OpenAI (GPT-4, GPT-4o)

2. **Enter your API key:**
   - Get one from your provider's console
   - Anthropic: https://console.anthropic.com
   - xAI: https://console.x.ai
   - OpenAI: https://platform.openai.com/api-keys

3. **Optional: Choose a custom model**
   - Or press Enter to use the default

4. **API connection test**
   - scurl will verify your credentials work

5. **Config saved!**
   - Stored in `~/.scurl/config.toml`

### Example login session:

```
$ scurl login

🔒 scurl - Initial Setup

Welcome to scurl! Let's configure your AI provider.

Available providers:
  1. Anthropic (Claude Sonnet 4.5, Haiku, Opus)
  2. xAI (Grok 2)
  3. OpenAI (GPT-4, GPT-4o)

Select provider [1-3]: 2

Selected: xAI (Grok)

Get your API key:
  → https://console.x.ai

Enter your API key: xai-xxxxxxxxxxxxx

Default model: grok-2-latest
Custom model (press Enter to use default): 

Testing API connection...
✓ API connection successful!

✓ Configuration saved to /Users/you/.scurl/config.toml

You're all set! Try:
  scurl https://example.com/install.sh
```

## Usage

Once configured, using scurl is simple:

```bash
# Analyze and review a script
scurl https://example.com/install.sh

# Auto-execute if safe
scurl --auto-execute https://sh.rustup.rs

# Override provider for one-time use
scurl --provider anthropic https://example.com/install.sh

# View current configuration
scurl config
```

## Multi-Provider Support

scurl now supports multiple AI providers:

### Anthropic (Claude)
- **Models**: claude-sonnet-4-5-20250929 (default), claude-opus-4, claude-haiku-4
- **Best for**: Detailed security analysis, comprehensive reviews
- **API**: https://console.anthropic.com

### xAI (Grok)
- **Models**: grok-2-latest (default), grok-2-vision
- **Best for**: Fast analysis, real-time data awareness
- **API**: https://console.x.ai

### OpenAI (GPT)
- **Models**: gpt-4o (default), gpt-4-turbo, gpt-4
- **Best for**: Widely available, familiar interface
- **API**: https://platform.openai.com

## Configuration File

Your config is stored at `~/.scurl/config.toml`:

```toml
provider = "xai"
api_key = "xai-xxxxxxxxxxxxx"
model = "grok-2-latest"  # optional
```

You can manually edit this file or run `scurl login` to reconfigure.

## Commands

| Command | Description |
|---------|-------------|
| `scurl login` | Configure AI provider and credentials |
| `scurl <URL>` | Analyze and potentially execute a script |
| `scurl config` | Show current configuration |
| `scurl analyze <URL>` | Explicitly analyze a script (same as shorthand) |

## Flags

| Flag | Description |
|------|-------------|
| `-a, --auto-execute` | Auto-execute if classified as safe |
| `-s, --shell <SHELL>` | Shell to use (default: bash) |
| `-k, --api-key <KEY>` | Override API key from config |
| `-p, --provider <PROVIDER>` | Override provider from config |
| `--yolo` | Skip review (dangerous!) |

## Examples

```bash
# First time: configure your provider
scurl login

# Analyze a script (with review)
scurl https://get.docker.com

# Auto-execute safe scripts
scurl -a https://sh.rustup.rs

# Use a different provider temporarily
scurl -p anthropic https://example.com/install.sh

# Check what's configured
scurl config

# Override with custom API key
scurl -k xai-custom-key https://example.com/install.sh
```

## Switching Providers

Want to try a different AI provider?

```bash
# Reconfigure with a new provider
scurl login

# Or just override for one command
scurl --provider openai https://example.com/install.sh
```

## Troubleshooting

### "No configuration found"
Run `scurl login` to set up your provider.

### "API error 401"
Your API key is invalid. Run `scurl login` to reconfigure.

### "Unknown provider"
Check your config file. Valid providers: `anthropic`, `xai`, `openai`

## Security

- API keys are stored in `~/.scurl/config.toml`
- Make sure this file has proper permissions: `chmod 600 ~/.scurl/config.toml`
- Never commit your config file to version control

## Next Steps

1. Run `scurl login` to get started
2. Try it on a safe example: `scurl http://localhost:8000/safe-example.sh`
3. Use it in your daily workflow instead of `curl | bash`
4. Share scurl with your team!

---

**Stop running untrusted code. Start using scurl.** 🔒

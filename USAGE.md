# Usage Guide

For quick start, see the [README](README.md). This guide covers extended workflows.

## Ollama (Local AI)

Run analysis entirely on your machine with no API costs:

1. Install from [ollama.ai](https://ollama.ai)
2. Pull a model: `ollama pull llama3.2`
3. Start the server: `ollama serve`
4. Configure: `scurl login` and select Ollama

No API key needed. Works offline. Your scripts never leave your machine.

## Shell Selection

```bash
scurl --shell sh https://example.com/install.sh
scurl --shell zsh https://example.com/install.sh
```

## Inspect Without Executing

Run scurl, review the analysis, and answer "N" at the prompt. The script is never written to disk unless you approve execution.

## Shell Alias

```bash
# Add to ~/.bashrc or ~/.zshrc
alias curlbash='scurl'
```

## CI/CD

Override provider and key inline -- no `scurl login` needed:

```yaml
# GitHub Actions
- name: Install tool with scurl
  run: |
    scurl --provider anthropic --api-key ${{ secrets.ANTHROPIC_API_KEY }} \
      --auto-execute https://example.com/install.sh
```

```yaml
# GitLab CI
script:
  - scurl --provider xai --api-key $SCURL_API_KEY --auto-execute URL
```

## Testing Example Scripts

```bash
cd examples
python3 -m http.server 8000 &

scurl http://localhost:8000/safe-example.sh
scurl http://localhost:8000/suspicious-example.sh
scurl http://localhost:8000/realistic-example.sh
```

## Real-World Examples

```bash
# Homebrew
scurl -a https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh

# Rustup
scurl -a https://sh.rustup.rs

# NVM
scurl https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh

# Docker
scurl https://get.docker.com
```

## Troubleshooting

**"No configuration found"** -- Run `scurl login`.

**"API error 401"** -- Invalid API key. Run `scurl login` to reconfigure, or check with `scurl config`.

**"Unknown provider"** -- Valid providers: `anthropic`, `xai`, `openai`, `ollama`.

**Script executes but fails** -- scurl analyzes security, not correctness. A safe script can still have bugs or missing dependencies.

**Ollama connection refused** -- Ensure `ollama serve` is running and listening on `localhost:11434`.

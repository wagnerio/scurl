# Contributing to scurl

## Development Setup

```bash
git clone https://github.com/wagnerio/scurl.git
cd scurl
git config core.hooksPath .githooks   # Prevents committing API keys
cargo build
```

Requires Rust 1.70+ ([rustup.rs](https://rustup.rs)) and an AI provider configured via `scurl login`.

## Build & Test

```bash
make test       # Run all tests (42 unit + 4 integration)
make check      # fmt + clippy + audit
make lint       # Strict clippy lints
make fmt        # Format code
make coverage   # Code coverage report
make watch      # Auto-run tests on changes
```

## Submitting Changes

1. Fork and create a feature branch
2. Make your changes
3. Run `make check` -- must pass
4. Commit with a clear message
5. Open a Pull Request

## Git Hooks

The pre-commit hook blocks real API keys (40+ characters) in code files while allowing placeholders in documentation. It also prevents committing `config.toml` files. Activate with:

```bash
git config core.hooksPath .githooks
```

## Code Style

- Follow Rust conventions
- `cargo fmt` before committing
- Handle errors with `anyhow` -- don't `unwrap()` unless provably safe
- Never log API keys or credentials
- Default to the most secure option

## Areas for Contribution

- Split `main.rs` into modules (`config.rs`, `provider.rs`, `network.rs`, `analysis.rs`)
- Source reputation scoring based on domain
- Caching of known-safe scripts (hash-based)
- Batch mode for analyzing multiple scripts
- `--quiet` / `--json` output modes
- Property-based testing (proptest)
- Mock AI responses for deterministic tests
- Seccomp BPF filter for bwrap sandbox (block dangerous syscalls like `ptrace`, `mount`)
- SBOM generation for supply-chain transparency

## License

By contributing, you agree your contributions will be licensed under the MIT License.

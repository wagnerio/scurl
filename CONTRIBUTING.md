# Contributing to scurl

Thank you for your interest in making scurl better! This project aims to improve security for millions of users who run installation scripts.

## How to Contribute

### Reporting Issues

Found a bug or have a feature request?

1. Check [existing issues](https://github.com/yourusername/scurl/issues)
2. Create a new issue with:
   - Clear description
   - Steps to reproduce (for bugs)
   - Expected vs actual behavior
   - Your environment (OS, Rust version, etc.)

### Submitting Code

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow Rust conventions
   - Add tests if applicable
   - Update documentation

4. **Test your changes**
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```

5. **Commit with clear messages**
   ```bash
   git commit -m "Add feature: describe what you did"
   ```

6. **Push and create a Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Rust 1.70+ ([rustup.rs](https://rustup.rs))
- Anthropic API key

### Build from source

```bash
git clone https://github.com/yourusername/scurl.git
cd scurl
cargo build
```

### Run locally

```bash
cargo run -- https://example.com/install.sh
```

### Run tests

```bash
cargo test
```

### Linting

```bash
cargo clippy -- -D warnings
```

### Formatting

```bash
cargo fmt
```

## Areas for Contribution

### High Priority

- [ ] **Unit tests** - Add comprehensive test coverage
- [ ] **Integration tests** - Test with real-world scripts
- [ ] **Error handling** - Improve error messages and recovery
- [ ] **Performance** - Optimize API calls and script analysis

### Feature Ideas

- [ ] **Local caching** - Cache analysis results for known scripts
- [ ] **Multiple AI providers** - Support OpenAI, Gemini, etc.
- [ ] **Script sandboxing** - Execute in isolated environment
- [ ] **Checksum verification** - Verify script integrity
- [ ] **Source reputation** - Score based on domain/source
- [ ] **Diff analysis** - Compare script versions over time
- [ ] **Plugin system** - Custom security checks
- [ ] **Web dashboard** - Review past analyses
- [ ] **Team sharing** - Share approved scripts across team
- [ ] **Batch mode** - Analyze multiple scripts at once

### Documentation

- [ ] More usage examples
- [ ] Video tutorials
- [ ] Security best practices guide
- [ ] API documentation
- [ ] Architecture docs

### Quality Improvements

- [ ] Better error messages
- [ ] More detailed security findings
- [ ] Improved risk classification
- [ ] Progress indicators for long operations
- [ ] Configuration file support (~/.scurlrc)

## Code Style

- Follow Rust conventions
- Use meaningful variable names
- Add comments for complex logic
- Keep functions focused and small
- Handle errors properly (don't unwrap unless safe)

## Security Considerations

This is a security tool, so:

- **Never decrease security** - Changes should maintain or improve security
- **Validate all inputs** - URLs, API responses, user input
- **No credential logging** - Never log API keys or sensitive data
- **Safe defaults** - Default to most secure option
- **Clear warnings** - User should understand risks

## Testing Guidelines

### Test Coverage

Aim for tests that cover:
- Happy paths
- Error cases
- Edge cases
- Security scenarios

### Example Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_parsing() {
        assert_eq!(RiskLevel::from_str("safe"), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_str("CRITICAL"), RiskLevel::Critical);
    }

    #[tokio::test]
    async fn test_download_valid_url() {
        // Test implementation
    }
}
```

## Commit Message Format

Use clear, descriptive commit messages:

```
Add feature: brief description

Longer explanation of what changed and why.
Include motivation and context.
```

Examples:
```
Add: Support for custom AI models
Fix: Handle timeout errors gracefully
Docs: Update README with installation steps
Refactor: Simplify risk level parsing
Test: Add unit tests for analysis parser
```

## Pull Request Process

1. **Update documentation** if you change functionality
2. **Add tests** for new features
3. **Ensure CI passes** (when set up)
4. **Request review** from maintainers
5. **Address feedback** promptly
6. **Squash commits** if requested

## Code Review

We review for:
- ✅ Correctness
- ✅ Security
- ✅ Performance
- ✅ Code style
- ✅ Test coverage
- ✅ Documentation

## Questions?

- Open an issue for discussion
- Tag it with "question" label
- Be respectful and patient

## License

By contributing, you agree your contributions will be licensed under the MIT License.

---

**Thank you for making the internet safer!** 🔒

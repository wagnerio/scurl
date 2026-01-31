.PHONY: build install test check lint fmt clean run help audit bench coverage

# Default target
help:
	@echo "scurl - Secure curl for install scripts"
	@echo ""
	@echo "Available targets:"
	@echo "  make build     - Build the project in release mode"
	@echo "  make install   - Install scurl to /usr/local/bin (requires sudo)"
	@echo "  make test      - Run all tests"
	@echo "  make check     - Run all checks (fmt + clippy + audit)"
	@echo "  make lint      - Run clippy with strict lints"
	@echo "  make fmt       - Format code with rustfmt"
	@echo "  make audit     - Check for security vulnerabilities"
	@echo "  make clean     - Clean build artifacts"
	@echo "  make run       - Run scurl with URL=<url>"
	@echo "  make bench     - Run benchmarks"
	@echo "  make coverage  - Generate code coverage report"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make run URL=https://example.com/install.sh"
	@echo "  make check"

build:
	cargo build --release

install: build
	sudo cp target/release/scurl /usr/local/bin/
	@echo "scurl installed to /usr/local/bin/scurl"

test:
	cargo test --all-features

lint:
	@echo "Running clippy..."
	@cargo clippy --all-targets --all-features -- \
		-D warnings \
		-D clippy::all \
		-D clippy::correctness \
		-D clippy::suspicious \
		-D clippy::complexity \
		-D clippy::perf

check: fmt-check lint audit
	@echo "✓ All checks passed!"

fmt:
	cargo fmt

fmt-check:
	@echo "Checking code formatting..."
	@cargo fmt --all -- --check

audit:
	@echo "Checking for security vulnerabilities..."
	@command -v cargo-audit >/dev/null 2>&1 || { echo "Installing cargo-audit..."; cargo install cargo-audit; }
	@cargo audit

bench:
	cargo bench

coverage:
	@echo "Generating code coverage..."
	@command -v cargo-tarpaulin >/dev/null 2>&1 || { echo "Installing cargo-tarpaulin..."; cargo install cargo-tarpaulin; }
	cargo tarpaulin --out Html --output-dir coverage

clean:
	cargo clean
	rm -rf coverage/

run:
	@if [ -z "$(URL)" ]; then \
		echo "Error: URL not specified. Use: make run URL=https://example.com/install.sh"; \
		exit 1; \
	fi
	cargo run -- $(URL)

.PHONY: watch
watch:
	@command -v cargo-watch >/dev/null 2>&1 || { echo "Installing cargo-watch..."; cargo install cargo-watch; }
	cargo watch -x test -x clippy

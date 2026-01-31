.PHONY: build install test check clean run help

# Default target
help:
	@echo "scurl - Secure curl for install scripts"
	@echo ""
	@echo "Available targets:"
	@echo "  make build    - Build the project in release mode"
	@echo "  make install  - Install scurl to /usr/local/bin (requires sudo)"
	@echo "  make test     - Run tests"
	@echo "  make check    - Run clippy and fmt checks"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make run URL=<url> - Run scurl with a URL"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make run URL=https://example.com/install.sh"

build:
	cargo build --release

install: build
	sudo cp target/release/scurl /usr/local/bin/
	@echo "scurl installed to /usr/local/bin/scurl"

test:
	cargo test

check:
	cargo clippy -- -D warnings
	cargo fmt --check

fmt:
	cargo fmt

clean:
	cargo clean

run:
	@if [ -z "$(URL)" ]; then \
		echo "Error: URL not specified. Use: make run URL=https://example.com/install.sh"; \
		exit 1; \
	fi
	cargo run -- $(URL)

.PHONY: fmt fmt-check test build clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  fmt        - Format all Rust files in the workspace"
	@echo "  fmt-check  - Check if all files are formatted"
	@echo "  test       - Run all tests"
	@echo "  build      - Build all workspace members"
	@echo "  clean      - Clean build artifacts"

# Format all Rust files
fmt:
	@find crate -name "*.rs" -type f -exec rustfmt --edition 2024 --config-path rustfmt.toml {} +
	@echo "Done!"

# Check if all files are formatted
fmt-check:
	@echo "Checking formatting..."
	@find crate -name "*.rs" -type f -exec rustfmt --edition 2024 --config-path rustfmt.toml --check {} +

# Run tests
test:
	cargo test --all

# Build all workspace members
build:
	cargo build --all

# Clean build artifacts
clean:
	cargo clean

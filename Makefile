# vault42 — Docker-first build/test/security (no host cargo; mirrors grobase's
# cargo-in-Docker pattern). Reuses grobase's prebuilt toolchain image by default;
# override RUST_TOOLCHAIN_IMG to build standalone.
.DEFAULT_GOAL := help

RUST_TOOLCHAIN_IMG ?= mini-baas-rust-toolchain:latest
CARGO_VOLS := \
	-v vault42-cargo-registry:/usr/local/cargo/registry \
	-v vault42-cargo-git:/usr/local/cargo/git \
	-v vault42-target:/work/target
CARGO := docker run --rm -v "$(CURDIR)":/work -w /work $(CARGO_VOLS) $(RUST_TOOLCHAIN_IMG)

.PHONY: help fmt fmt-check rust-check rust-test rust-build security verify

help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

fmt: ## Format the workspace (in Docker)
	@$(CARGO) cargo fmt --all

fmt-check: ## Verify formatting (in Docker)
	@$(CARGO) cargo fmt --all -- --check

rust-check: ## Clippy the workspace — warnings are errors (in Docker)
	@$(CARGO) cargo clippy --workspace --all-targets -- -D warnings

rust-test: ## Run the workspace test suite (in Docker)
	@$(CARGO) cargo test --workspace

rust-build: ## Release-build the deployables (in Docker)
	@$(CARGO) cargo build --release

security: ## Supply-chain + secret scan (cargo-audit/deny + gitleaks; CI enforces)
	@$(CARGO) sh -c 'cargo audit || true; cargo deny check || true'
	@command -v gitleaks >/dev/null 2>&1 && gitleaks detect --no-banner || echo "gitleaks not installed locally (CI enforces)"

verify: ## Run the vault42 gate battery (Docker-first)
	@bash scripts/verify/run-gate-battery.sh --fast

# sfi CLI — task runner: build/test/lint/fmt/clean/install, a cheap `smoke`
# check, and an aggregate `verify` gate. Thin wrappers over cargo so a green
# local run predicts a green CI run.

BIN := sfi
CARGO := cargo

.PHONY: all build release test lint fmt fmt-check clean install deps smoke verify dev

all: verify

# Every target that produces a binary signs it. Anything you actually run
# against the keychain — including `./target/release/$(BIN)` during testing —
# needs the stable identity, or each rebuild mints a fresh ad-hoc one and macOS
# asks for "Always Allow" again.
build: SIGN_TARGET = target/debug/$(BIN)
build:
	$(CARGO) build
	@$(SIGN)

release: SIGN_TARGET = target/release/$(BIN)
release:
	$(CARGO) build --release
	@$(SIGN)

test:
	$(CARGO) test --all

lint:
	$(CARGO) clippy --all-targets -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clean:
	$(CARGO) clean

# `cargo install` ad-hoc signs, which gives the binary a *new* code identity
# every time. macOS scopes keychain "Always Allow" grants to that identity, so
# an unsigned reinstall silently revokes them and the next run prompts again.
# Re-signing with the stable shared identity keeps one grant valid across every
# future install.
# `--locked` builds from Cargo.lock, the versions `verify` tested; without it
# `cargo install` re-resolves to the newest semver-compatible crates.
install: SIGN_TARGET = $${CARGO_INSTALL_ROOT:-$$HOME/.cargo}/bin/$(BIN)
install:
	$(CARGO) install --locked --path . --force
	@$(SIGN)

deps:
	$(CARGO) fetch

# Debug build re-signed with the same stable identity, so the dev loop doesn't
# re-prompt either.
dev: SIGN_TARGET = target/debug/$(BIN)
dev:
	cargo build
	@$(SIGN)

# Shared re-signing step. No-ops with a note when the helper or identity is
# absent (CI, Linux, a fresh machine that hasn't run setup-dev-signing.sh).
define SIGN
if [ -x "$$HOME/Dev/cli-common/scripts/dev-sign.sh" ]; then \
	"$$HOME/Dev/cli-common/scripts/dev-sign.sh" "$(SIGN_TARGET)"; \
else echo "cli-common/scripts/dev-sign.sh not found — $(SIGN_TARGET) left ad-hoc signed"; fi
endef

# Cheap sanity checks needing no config, network, or keychain. Deliberately no
# `auth status` here: it reads keychain entries, which on macOS puts up a
# permission dialog per item for a freshly-signed binary. Keychain behaviour is
# covered by dogfooding the installed binary, not by the offline gate.
smoke: release
	./target/release/$(BIN) --version
	./target/release/$(BIN) --help > /dev/null
	./target/release/$(BIN) info > /dev/null
	./target/release/$(BIN) completions bash > /dev/null

verify: fmt-check lint test smoke

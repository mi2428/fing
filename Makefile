SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := help

# Project
APP             := fing
PACKAGE_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)

# Output directories
BINDIR  := bin
DISTDIR := dist
VHSDIR  := .vhs

# Toolchain
RUSTUP           ?= rustup
RUSTUP_TOOLCHAIN ?= 1.95.0
CARGO            ?= $(shell if command -v $(RUSTUP) >/dev/null 2>&1 && $(RUSTUP) which cargo --toolchain $(RUSTUP_TOOLCHAIN) >/dev/null 2>&1; then $(RUSTUP) which cargo --toolchain $(RUSTUP_TOOLCHAIN); else command -v cargo; fi)
RUSTC            ?= $(shell if command -v $(RUSTUP) >/dev/null 2>&1 && $(RUSTUP) which rustc --toolchain $(RUSTUP_TOOLCHAIN) >/dev/null 2>&1; then $(RUSTUP) which rustc --toolchain $(RUSTUP_TOOLCHAIN); else command -v rustc; fi)
RUSTDOC          ?= $(shell if command -v $(RUSTUP) >/dev/null 2>&1 && $(RUSTUP) which rustdoc --toolchain $(RUSTUP_TOOLCHAIN) >/dev/null 2>&1; then $(RUSTUP) which rustdoc --toolchain $(RUSTUP_TOOLCHAIN); else command -v rustdoc; fi)
RUST_BINDIR      := $(patsubst %/,%,$(dir $(CARGO)))
CARGO_ENV        := PATH="$(RUST_BINDIR):$(PATH)" RUSTC="$(RUSTC)" RUSTDOC="$(RUSTDOC)"

# Commands
INSTALL ?= install
DOCKER  ?= docker
VHS     ?= vhs

# Install
INSTALL_PREFIX ?= $(HOME)/.local
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/bin

# Demo
VHS_TAPE             ?= $(VHSDIR)/$(APP).tape
VHS_OUTPUT           ?= screencast.gif
VHS_DEMO_COMMAND     ?= $(APP) scan en0 en7 --scan.range 192.0.2.0/24,198.51.100.0/24 --output.live always
VHS_DEMO_DELAY_SCALE ?= 4
VHS_FRAMERATE        ?= 24

# Release
GIT_REMOTE   ?= origin
RELEASE_MAKE ?= $(MAKE)
OS           ?= darwin,linux
ARCH         ?= amd64,arm64
DIST_TAG     ?= $(if $(TAG),$(TAG),v$(PACKAGE_VERSION))
DIST_APP     := $(APP)-$(DIST_TAG)

# Homebrew tap
HOMEBREW_TAP              ?= 1
HOMEBREW_TAP_DIR          ?= ../homebrew-$(APP)
HOMEBREW_TAP_REMOTE       ?= origin
HOMEBREW_TAP_SLUG         ?=
HOMEBREW_TAP_README_TITLE ?= homebrew-$(APP)
HOMEBREW_DESC             ?= Local IPv4 network scanner with device fingerprints
HOMEBREW_FORMULA_CLASS    ?= $(shell printf '%s' '$(APP)' | awk -F- '{ for (i = 1; i <= NF; i++) printf toupper(substr($$i, 1, 1)) substr($$i, 2) }')

# Release matrix
DARWIN_ARCHS := amd64 arm64
LINUX_ARCHS  := amd64 arm64
RUST_TARGETS := x86_64-apple-darwin aarch64-apple-darwin

DARWIN_amd64_TARGET := x86_64-apple-darwin
DARWIN_amd64_SUFFIX := darwin-amd64
DARWIN_arm64_TARGET := aarch64-apple-darwin
DARWIN_arm64_SUFFIX := darwin-arm64

LINUX_amd64_PLATFORM := linux/amd64
LINUX_amd64_SUFFIX   := linux-amd64
LINUX_arm64_PLATFORM := linux/arm64
LINUX_arm64_SUFFIX   := linux-arm64

# Linux release builds
LINUX_BUILD_IMAGE           ?= rust:1.95-bookworm
LINUX_SMOKE_IMAGE           ?= debian:bookworm-slim
LINUX_CACHE_KEY             := $(shell printf '%s' '$(LINUX_BUILD_IMAGE)' | sed 's/[^A-Za-z0-9_.-]/-/g')
LINUX_OPENSSL_STATIC        ?= 1
LINUX_PKG_CONFIG_ALL_STATIC ?= 1
DOCKER_UID                  ?= $(shell id -u)
DOCKER_GID                  ?= $(shell id -g)

# Host and help
HOST_OS            := $(shell uname -s)
HELP_NAME_WIDTH    := 27
HELP_EXAMPLE_WIDTH := 44

##@ Development

.PHONY: build
build: ## Build the host binary into bin/
	@mkdir -p $(BINDIR)
	@$(CARGO_ENV) $(CARGO) build --release
	@cp target/release/$(APP) $(BINDIR)/$(APP)
	@chmod +x $(BINDIR)/$(APP)
	@printf 'Wrote %s/%s\n' "$(BINDIR)" "$(APP)"

.PHONY: install
install: ## Build and install the host binary into INSTALL_BINDIR
	@$(CARGO_ENV) $(CARGO) build --release
	@mkdir -p "$(INSTALL_BINDIR)"
	@$(INSTALL) -m 0755 "target/release/$(APP)" "$(INSTALL_BINDIR)/$(APP)"
	@printf 'Installed %s\n' "$(INSTALL_BINDIR)/$(APP)"

.PHONY: fmt
fmt: ## Format Rust sources. Use CHECK_ONLY=1 to check without writing
	@if [ "$(CHECK_ONLY)" = "1" ]; then \
		$(CARGO_ENV) $(CARGO) fmt --all --check; \
	else \
		$(CARGO_ENV) $(CARGO) fmt --all; \
	fi

.PHONY: lint
lint: ## Run clippy with warnings treated as errors
	@$(CARGO_ENV) $(CARGO) clippy --all-targets --all-features -- -D warnings

.PHONY: doc
doc: ## Build rustdoc with warnings treated as errors
	@RUSTDOCFLAGS="-D warnings" $(CARGO_ENV) $(CARGO) doc --no-deps

.PHONY: test
test: ## Run unit tests
	@$(CARGO_ENV) $(CARGO) test

.PHONY: check
check: ## Run formatting, lint, rustdoc, and tests
	@$(MAKE) --no-print-directory fmt CHECK_ONLY=1
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory doc
	@$(MAKE) --no-print-directory test

.PHONY: clean
clean: ## Remove local build artifacts
	@rm -rf $(BINDIR) $(DISTDIR) $(VHSDIR) .cargo-linux .home-linux
	@$(CARGO_ENV) $(CARGO) clean

##@ Demo

.PHONY: vhs
vhs: ## Record the README live TUI demo GIF with VHS
	@command -v "$(VHS)" >/dev/null 2>&1 || { \
		echo "vhs is required to record $(VHS_OUTPUT): https://github.com/charmbracelet/vhs" >&2; \
		exit 1; \
	}
	@$(CARGO_ENV) $(CARGO) build --example tui_demo
	@mkdir -p "$(VHSDIR)/bin" "$$(dirname "$(VHS_OUTPUT)")"
	@printf '%s\n' \
		'#!/bin/sh' \
		'FING_DEMO_DELAY_SCALE="$(VHS_DEMO_DELAY_SCALE)" FING_DEMO_FRAMERATE="$(VHS_FRAMERATE)" exec "$(CURDIR)/target/debug/examples/tui_demo" "$$@"' \
		> "$(VHSDIR)/bin/$(APP)"
	@chmod +x "$(VHSDIR)/bin/$(APP)"
	@printf '%s\n' \
		'Output $(VHS_OUTPUT)' \
		'Require $(APP)' \
		'' \
		'Set Shell "bash"' \
		'Set Theme "Builtin Dark"' \
		'Set FontSize 16' \
		'Set Width 1664' \
		'Set Height 936' \
		'Set Padding 14' \
		'Set Framerate $(VHS_FRAMERATE)' \
		'Set PlaybackSpeed 1.0' \
		'Set TypingSpeed 45ms' \
		'Set CursorBlink false' \
		'' \
		'Type "$(VHS_DEMO_COMMAND)"' \
		'Sleep 500ms' \
		'Enter' \
		'Wait+Screen@30s /status=complete/' \
		'Sleep 1.2s' \
		'Ctrl+C' \
		'Sleep 500ms' \
		> "$(VHS_TAPE)"
	@rm -f "$(VHS_OUTPUT)"
	@env -u NO_COLOR PATH="$(CURDIR)/$(VHSDIR)/bin:$(PATH)" TERM=xterm-truecolor COLORTERM=truecolor "$(VHS)" "$(VHS_TAPE)"
	@test -f "$(VHS_OUTPUT)" || { \
		echo "VHS completed but $(VHS_OUTPUT) was not written" >&2; \
		exit 1; \
	}
	@rm -rf "$(VHSDIR)"
	@printf 'Wrote %s\n' "$(VHS_OUTPUT)"

define RELEASE_SCRIPT
# shellcheck shell=bash
set -Eeuo pipefail

fail() {
  echo "release: $$*" >&2
  exit 1
}

run() {
  printf '+'
  printf ' %q' "$$@"
  printf '\n'
  "$$@"
}

need() {
  command -v "$$1" >/dev/null 2>&1 || fail "$$1 is required for release"
}

value_at_ref() {
  git show "$$1:Cargo.toml" | sed -n "s/^$$2 = \"\\(.*\\)\"/\\1/p" | head -n 1
}

sha256_file() {
  shasum -a 256 "$$1" | awk '{print $$1}'
}

clean_git_dir() {
  local dir="$$1" label="$$2" status

  git -C "$$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "$$label repo not found at $$dir"

  status="$$(git -C "$$dir" status --porcelain)"
  if [[ -n "$$status" ]]; then
    git -C "$$dir" status --short >&2
    fail "$$label must be clean before release"
  fi
}

github_repo() {
  local repo="$${GH_REPO:-$${GITHUB_REPOSITORY:-}}" url

  if [[ -z "$$repo" ]]; then
    url="$$(git config --get "remote.$$GIT_REMOTE.url" || true)"
    case "$$url" in
      git@github.com:*) repo="$${url#git@github.com:}" ;;
      https://github.com/*) repo="$${url#https://github.com/}" ;;
      ssh://git@github.com/*) repo="$${url#ssh://git@github.com/}" ;;
      *) fail "could not infer GitHub repository from remote $$GIT_REMOTE; set GH_REPO=owner/repo" ;;
    esac
  fi

  repo="$${repo#https://github.com/}"
  repo="$${repo%.git}"
  [[ "$$repo" == */* ]] || fail "GitHub repository must look like owner/repo, got $$repo"
  printf '%s\n' "$$repo"
}

cleanup() {
  local status=$$?

  if [[ "$$created_tag" == 1 && "$$pushed_tag" != 1 ]]; then
    git tag -d "$$TAG" >/dev/null 2>&1 || true
  fi

  exit "$$status"
}

semver='^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?([+][0-9A-Za-z][0-9A-Za-z.-]*)?$$'
created_tag=0
pushed_tag=0

[[ -n "$$TAG" ]] || fail "TAG is required, for example: make release TAG=v0.1.0"
[[ "$$TAG" =~ $$semver ]] || fail "TAG must look like vMAJOR.MINOR.PATCH"

cd "$$(git rev-parse --show-toplevel)"
clean_git_dir . "working tree"
need git
need gh
need shasum

repo="$$(github_repo)"
version="$${TAG#v}"
tap_slug="$${HOMEBREW_TAP_SLUG:-$${repo%%/*}/$$APP}"
tap_readme_title="$${HOMEBREW_TAP_README_TITLE:-homebrew-$$APP}"
remote_line="$$(git ls-remote --tags "$$GIT_REMOTE" "refs/tags/$$TAG" | sed -n '1p')"
remote_oid="$${remote_line%%[[:space:]]*}"
trap cleanup EXIT

if git rev-parse -q --verify "refs/tags/$$TAG" >/dev/null; then
  local_oid="$$(git rev-parse "refs/tags/$$TAG")"
  [[ -z "$$remote_oid" || "$$remote_oid" == "$$local_oid" ]] || \
    fail "local tag $$TAG does not match $$GIT_REMOTE/tags/$$TAG"
  printf 'Using existing tag %s at %s\n' "$$TAG" "$$(git rev-list -n 1 "$$TAG")"
elif [[ -n "$$remote_oid" ]]; then
  run git fetch "$$GIT_REMOTE" "refs/tags/$$TAG:refs/tags/$$TAG"
  printf 'Using fetched tag %s at %s\n' "$$TAG" "$$(git rev-list -n 1 "$$TAG")"
else
  run git tag "$$TAG"
  created_tag=1
  printf 'Created tag %s at %s\n' "$$TAG" "$$(git rev-parse HEAD)"
fi

release_commit="$$(git rev-list -n 1 "$$TAG")"
head_commit="$$(git rev-parse HEAD)"
[[ "$$release_commit" == "$$head_commit" ]] || \
  fail "$$TAG points to $$release_commit, but HEAD is $$head_commit; checkout the release commit first"

[[ "$$(value_at_ref "refs/tags/$$TAG" name)" == "$$APP" ]] || fail "Cargo.toml package name does not match $$APP"
[[ "$$(value_at_ref "refs/tags/$$TAG" version)" == "$$version" ]] || fail "Cargo.toml version does not match $$TAG"

run "$$RELEASE_MAKE" dist TAG="$$TAG" OS="$$OS" ARCH="$$ARCH"
run git push "$$GIT_REMOTE" "refs/tags/$$TAG"
pushed_tag=1

shopt -s nullglob
assets=("$$DISTDIR"/*)
shopt -u nullglob
(($${#assets[@]} > 0)) || fail "no release assets found in $$DISTDIR"

release_flags=()
[[ "$$TAG" == *-* ]] && release_flags=(--prerelease)

if gh release view "$$TAG" --repo "$$repo" >/dev/null 2>&1; then
  run gh release upload "$$TAG" "$${assets[@]}" --clobber --repo "$$repo"
else
  run gh release create "$$TAG" \
    --repo "$$repo" \
    --target "$$release_commit" \
    --title "$$TAG" \
    --generate-notes \
    "$${release_flags[@]}" \
    "$${assets[@]}"
fi

case "$$HOMEBREW_TAP" in
  0|false|FALSE|no|NO)
    printf 'Skipping Homebrew tap update because HOMEBREW_TAP=0\n'
    ;;
  *)
    dist_app="$$APP-$$TAG"
    darwin_amd64_bin="$$DISTDIR/$$dist_app-darwin-amd64"
    darwin_arm64_bin="$$DISTDIR/$$dist_app-darwin-arm64"
    formula_dir="$$HOMEBREW_TAP_DIR/Formula"
    formula_file="$$formula_dir/$$APP.rb"

    [[ -f "$$darwin_amd64_bin" ]] || fail "missing Homebrew artifact $$darwin_amd64_bin"
    [[ -f "$$darwin_arm64_bin" ]] || fail "missing Homebrew artifact $$darwin_arm64_bin"
    clean_git_dir "$$HOMEBREW_TAP_DIR" "Homebrew tap working tree"

    mkdir -p "$$formula_dir"
    darwin_amd64_sha="$$(sha256_file "$$darwin_amd64_bin")"
    darwin_arm64_sha="$$(sha256_file "$$darwin_arm64_bin")"

    printf '%s\n' \
      "# $$tap_readme_title" \
      '' \
      "Homebrew tap for \`$$APP\`." \
      '' \
      '```console' \
      "\$$ brew tap $$tap_slug" \
      "\$$ brew install --formula $$tap_slug/$$APP" \
      '```' \
      > "$$HOMEBREW_TAP_DIR/README.md"

    printf '%s\n' \
      '# typed: false' \
      '# frozen_string_literal: true' \
      '' \
      "class $$HOMEBREW_FORMULA_CLASS < Formula" \
      "  desc \"$$HOMEBREW_DESC\"" \
      "  homepage \"https://github.com/$$repo\"" \
      "  version \"$$version\"" \
      '  license "MIT"' \
      '  depends_on :macos' \
      '' \
      '  on_macos do' \
      '    on_arm do' \
      "      url \"https://github.com/$$repo/releases/download/$$TAG/$$APP-$$TAG-darwin-arm64\"," \
      '          using: :nounzip' \
      "      sha256 \"$$darwin_arm64_sha\"" \
      '    end' \
      '' \
      '    on_intel do' \
      "      url \"https://github.com/$$repo/releases/download/$$TAG/$$APP-$$TAG-darwin-amd64\"," \
      '          using: :nounzip' \
      "      sha256 \"$$darwin_amd64_sha\"" \
      '    end' \
      '  end' \
      '' \
      '  def install' \
      "    bin.install Dir[\"$$APP-v#{version}-darwin-*\"].first => \"$$APP\"" \
      "    chmod 0755, bin/\"$$APP\"" \
      '  end' \
      '' \
      '  test do' \
      "    assert_match \"$$APP #{version}\", shell_output(\"#{bin}/$$APP --version\")" \
      "    assert_match \"Usage:\", shell_output(\"#{bin}/$$APP --help\")" \
      '  end' \
      'end' \
      > "$$formula_file"

    if command -v brew >/dev/null 2>&1; then
      run env HOMEBREW_DEVELOPER=1 brew style \
        --except-cops FormulaAudit/Homepage,FormulaAudit/Desc,FormulaAuditStrict \
        --fix "$$formula_file" || true
    else
      printf 'Skipping Homebrew style; brew not found\n'
    fi

    run git -C "$$HOMEBREW_TAP_DIR" add README.md "Formula/$$APP.rb"
    if git -C "$$HOMEBREW_TAP_DIR" diff --cached --quiet; then
      printf 'Homebrew formula is already up to date for %s\n' "$$TAG"
    else
      run git -C "$$HOMEBREW_TAP_DIR" commit -m "$$APP $$version"
      run git -C "$$HOMEBREW_TAP_DIR" push "$$HOMEBREW_TAP_REMOTE" HEAD
    fi
    ;;
esac

printf 'Published %s from local release artifacts and updated Homebrew.\n' "$$TAG"
endef
export RELEASE_SCRIPT

##@ Distribution

.PHONY: release
release: ## Build dist, publish a GitHub release, and update Homebrew. Requires TAG=vX.Y.Z
	@APP="$(APP)" TAG="$(TAG)" GIT_REMOTE="$(GIT_REMOTE)" DISTDIR="$(DISTDIR)" OS="$(OS)" ARCH="$(ARCH)" HOMEBREW_TAP="$(HOMEBREW_TAP)" HOMEBREW_TAP_DIR="$(HOMEBREW_TAP_DIR)" HOMEBREW_TAP_REMOTE="$(HOMEBREW_TAP_REMOTE)" HOMEBREW_TAP_SLUG="$(HOMEBREW_TAP_SLUG)" HOMEBREW_TAP_README_TITLE="$(HOMEBREW_TAP_README_TITLE)" HOMEBREW_DESC="$(HOMEBREW_DESC)" HOMEBREW_FORMULA_CLASS="$(HOMEBREW_FORMULA_CLASS)" RELEASE_MAKE="$(RELEASE_MAKE)" PATH="$(RUST_BINDIR):$(PATH)" bash -c "$$RELEASE_SCRIPT"

.PHONY: dist
dist: ## Build release binaries into dist/. Use OS=darwin,linux and ARCH=amd64,arm64
	@rm -rf $(DISTDIR)
	@mkdir -p $(DISTDIR)
	@os_list="$(OS)"; \
	arch_list="$(ARCH)"; \
	if [ -z "$$os_list" ]; then \
		echo "OS is required. Supported values: darwin,linux" >&2; \
		exit 1; \
	fi; \
	if [ -z "$$arch_list" ]; then \
		echo "ARCH is required. Supported values: amd64,arm64" >&2; \
		exit 1; \
	fi; \
	for os in $$(printf '%s' "$$os_list" | tr ',' ' '); do \
		case "$$os" in \
			darwin|linux) ;; \
			*) echo "Unsupported OS '$$os'. Supported values: darwin,linux" >&2; exit 1 ;; \
		esac; \
	done; \
	for arch in $$(printf '%s' "$$arch_list" | tr ',' ' '); do \
		case "$$arch" in \
			amd64|arm64) ;; \
			*) echo "Unsupported ARCH '$$arch'. Supported values: amd64,arm64" >&2; exit 1 ;; \
		esac; \
	done; \
	for os in $$(printf '%s' "$$os_list" | tr ',' ' '); do \
		for arch in $$(printf '%s' "$$arch_list" | tr ',' ' '); do \
			$(MAKE) _dist.$$os.$$arch || exit $$?; \
		done; \
	done; \
	$(MAKE) dist-smoke || exit $$?; \
	$(MAKE) checksums || exit $$?

.PHONY: dist-smoke
dist-smoke: ## Smoke-test Linux dist binaries in a Debian container
	@if ! ls "$(DISTDIR)"/$(DIST_APP)-linux-* >/dev/null 2>&1; then \
		printf 'Skipping Linux dist smoke test; no Linux artifacts found\n'; \
		exit 0; \
	fi; \
	$(MAKE) --no-print-directory _docker-check; \
	for arch in $(LINUX_ARCHS); do \
		case "$$arch" in \
			amd64) binary="$(DISTDIR)/$(DIST_APP)-$(LINUX_amd64_SUFFIX)"; platform="$(LINUX_amd64_PLATFORM)" ;; \
			arm64) binary="$(DISTDIR)/$(DIST_APP)-$(LINUX_arm64_SUFFIX)"; platform="$(LINUX_arm64_PLATFORM)" ;; \
			*) echo "Unsupported Linux ARCH '$$arch'" >&2; exit 1 ;; \
		esac; \
		if [ ! -f "$$binary" ]; then \
			continue; \
		fi; \
		printf 'Smoke-testing %s on %s in %s\n' "$$binary" "$$platform" "$(LINUX_SMOKE_IMAGE)"; \
		$(DOCKER) run --rm \
			--platform "$$platform" \
			-v "$(CURDIR):/workspace:ro" \
			-w /workspace \
			$(LINUX_SMOKE_IMAGE) \
			"/workspace/$$binary" --help >/dev/null; \
		$(DOCKER) run --rm \
			--platform "$$platform" \
			-v "$(CURDIR):/workspace:ro" \
			-w /workspace \
			$(LINUX_SMOKE_IMAGE) \
			"/workspace/$$binary" --version >/dev/null; \
	done

.PHONY: checksums
checksums: ## Write SHA-256 checksums for dist artifacts
	@if [ ! -d "$(DISTDIR)" ] || ! ls "$(DISTDIR)"/$(DIST_APP)-* >/dev/null 2>&1; then \
		echo "No dist artifacts found" >&2; \
		exit 1; \
	fi
	@cd "$(DISTDIR)" && shasum -a 256 $(DIST_APP)-* > checksums.txt
	@printf 'Wrote %s/checksums.txt\n' "$(DISTDIR)"

.PHONY: _docker-check
_docker-check:
	@command -v $(DOCKER) >/dev/null 2>&1 || { \
		echo "Docker is required for Linux release builds" >&2; \
		exit 1; \
	}
	@$(DOCKER) info >/dev/null 2>&1 || { \
		echo "A running Docker daemon is required for Linux release builds" >&2; \
		exit 1; \
	}

define TARGET_RULE
.PHONY: _target.$(1)
_target.$(1):
	@command -v $(RUSTUP) >/dev/null 2>&1 || { \
		echo "rustup is required to install cross-compilation targets" >&2; \
		exit 1; \
	}
	@$(RUSTUP) target add --toolchain $(RUSTUP_TOOLCHAIN) $(1)
endef
$(foreach target,$(RUST_TARGETS),$(eval $(call TARGET_RULE,$(target))))

define DARWIN_DIST_RULE
.PHONY: _dist.darwin.$(1)
_dist.darwin.$(1): _target.$$(DARWIN_$(1)_TARGET)
	@if [ "$(HOST_OS)" != "Darwin" ]; then \
		echo "Darwin release builds must run on macOS" >&2; \
		exit 1; \
	fi
	@printf 'Building %s for %s\n' "$(APP)" "$$(DARWIN_$(1)_TARGET)"
	@mkdir -p $(DISTDIR)
	@$(CARGO_ENV) $(CARGO) build --locked --release --target $$(DARWIN_$(1)_TARGET)
	@cp target/$$(DARWIN_$(1)_TARGET)/release/$(APP) $(DISTDIR)/$(DIST_APP)-$$(DARWIN_$(1)_SUFFIX)
	@chmod +x $(DISTDIR)/$(DIST_APP)-$$(DARWIN_$(1)_SUFFIX)
	@printf 'Wrote %s/%s-%s\n' "$(DISTDIR)" "$(DIST_APP)" "$$(DARWIN_$(1)_SUFFIX)"
endef
$(foreach arch,$(DARWIN_ARCHS),$(eval $(call DARWIN_DIST_RULE,$(arch))))

define LINUX_DIST_RULE
.PHONY: _dist.linux.$(1)
_dist.linux.$(1): _docker-check
	@printf 'Building %s for %s via Docker\n' "$(APP)" "$$(LINUX_$(1)_PLATFORM)"
	@mkdir -p $(DISTDIR) .cargo-linux/$(1) .home-linux/$(LINUX_CACHE_KEY)/$(1)
	@$(DOCKER) run --rm \
		--platform $$(LINUX_$(1)_PLATFORM) \
		-e HOME=/workspace/.home-linux/$(LINUX_CACHE_KEY)/$(1) \
		-e CARGO_HOME=/workspace/.cargo-linux/$(1) \
		-e CARGO_TARGET_DIR=/workspace/target/linux-$(1)-$(LINUX_CACHE_KEY) \
		-e OPENSSL_STATIC=$(LINUX_OPENSSL_STATIC) \
		-e PKG_CONFIG_ALL_STATIC=$(LINUX_PKG_CONFIG_ALL_STATIC) \
		-v "$(CURDIR):/workspace" \
		-w /workspace \
		$(LINUX_BUILD_IMAGE) \
		bash -eu -o pipefail -c ' \
			cargo build --locked --release; \
			cp target/linux-$(1)-$(LINUX_CACHE_KEY)/release/$(APP) dist/$(DIST_APP)-$$(LINUX_$(1)_SUFFIX); \
			chmod +x dist/$(DIST_APP)-$$(LINUX_$(1)_SUFFIX); \
			chown -R $(DOCKER_UID):$(DOCKER_GID) dist target/linux-$(1)-$(LINUX_CACHE_KEY) .cargo-linux/$(1) .home-linux/$(LINUX_CACHE_KEY)/$(1)'
	@printf 'Wrote %s/%s-%s\n' "$(DISTDIR)" "$(DIST_APP)" "$$(LINUX_$(1)_SUFFIX)"
endef
$(foreach arch,$(LINUX_ARCHS),$(eval $(call LINUX_DIST_RULE,$(arch))))

##@ Help

.PHONY: help
help: ## Show this help message
	@awk -v width="$(HELP_NAME_WIDTH)" 'BEGIN {FS = ":.*##"} \
		{ lines[NR] = $$0 } \
		END { \
			section = ""; \
			for (i = 1; i <= NR; i++) { \
				$$0 = lines[i]; \
				if ($$0 ~ /^##@/) { \
					section = substr($$0, 5); \
				} else if ($$0 ~ /^[a-zA-Z0-9_.-]+:.*##/) { \
					split($$0, parts, ":.*##"); \
					sub(/^[[:space:]]+/, "", parts[2]); \
					if (section != "") printf "\n\033[1m%s\033[0m\n", section; \
					section = ""; \
					printf "  \033[36m%-*s\033[0m%s\n", width, parts[1], parts[2]; \
				} \
			} \
		}' $(MAKEFILE_LIST)
	@printf "\n\033[1mVariables:\033[0m\n"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "TAG" "Release tag for make release, for example v0.1.0"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "GIT_REMOTE" "Release git remote, defaults to $(GIT_REMOTE)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_TAP" "Set to 0 to skip Homebrew tap updates, defaults to $(HOMEBREW_TAP)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_TAP_DIR" "Homebrew tap checkout, defaults to $(HOMEBREW_TAP_DIR)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_TAP_REMOTE" "Homebrew tap git remote, defaults to $(HOMEBREW_TAP_REMOTE)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_TAP_SLUG" "brew tap slug, defaults to GitHub owner/$(APP)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_TAP_README_TITLE" "Homebrew tap README title, defaults to $(HOMEBREW_TAP_README_TITLE)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_DESC" "Homebrew formula description"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "HOMEBREW_FORMULA_CLASS" "Homebrew Ruby class, defaults to $(HOMEBREW_FORMULA_CLASS)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "OS" "Release OS list for make dist, defaults to $(OS)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "ARCH" "Release arch list for make dist, defaults to $(ARCH)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "INSTALL_BINDIR" "Install directory, defaults to $(INSTALL_BINDIR)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "VHS" "VHS command for make vhs, defaults to $(VHS)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "VHS_DEMO_COMMAND" "Demo command for make vhs"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "VHS_DEMO_DELAY_SCALE" "Demo scan delay scale for make vhs, defaults to $(VHS_DEMO_DELAY_SCALE)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "VHS_FRAMERATE" "VHS recording framerate, defaults to $(VHS_FRAMERATE)"
	@printf "\n\033[1mExamples:\033[0m\n"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make fmt CHECK_ONLY=1" "# Check formatting without writing"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make check" "# Run local quality gates"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make vhs" "# Record screencast.gif from deterministic demo data"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make dist OS=darwin,linux ARCH=amd64,arm64" "# Build release binaries and checksums"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make release TAG=v0.1.0" "# Publish a GitHub release and update Homebrew"

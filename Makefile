SHELL         := /bin/bash
.SHELLFLAGS   := -eu -o pipefail -c
.DEFAULT_GOAL := help

RUSTUP           ?= rustup
RUSTUP_TOOLCHAIN ?= 1.95.0
CARGO            ?= $(shell if command -v $(RUSTUP) >/dev/null 2>&1 && $(RUSTUP) which cargo --toolchain $(RUSTUP_TOOLCHAIN) >/dev/null 2>&1; then $(RUSTUP) which cargo --toolchain $(RUSTUP_TOOLCHAIN); else command -v cargo; fi)
RUSTC            ?= $(shell if command -v $(RUSTUP) >/dev/null 2>&1 && $(RUSTUP) which rustc --toolchain $(RUSTUP_TOOLCHAIN) >/dev/null 2>&1; then $(RUSTUP) which rustc --toolchain $(RUSTUP_TOOLCHAIN); else command -v rustc; fi)
RUSTDOC          ?= $(shell if command -v $(RUSTUP) >/dev/null 2>&1 && $(RUSTUP) which rustdoc --toolchain $(RUSTUP_TOOLCHAIN) >/dev/null 2>&1; then $(RUSTUP) which rustdoc --toolchain $(RUSTUP_TOOLCHAIN); else command -v rustdoc; fi)
RUST_BINDIR      := $(patsubst %/,%,$(dir $(CARGO)))
CARGO_ENV        := PATH="$(RUST_BINDIR):$(PATH)" RUSTC="$(RUSTC)" RUSTDOC="$(RUSTDOC)"
RELEASE_MAKE     ?= $(MAKE)

INSTALL    ?= install
DOCKER     ?= docker
GIT_REMOTE ?= origin
VHS        ?= vhs
VHS_DEMO_DELAY_SCALE ?= 4

APP     := fing
BINDIR  := bin
DISTDIR := dist
VHSDIR  := .vhs
VHS_TAPE   := $(VHSDIR)/fing.tape
VHS_OUTPUT := screencast.gif
PACKAGE_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
DIST_TAG        ?= $(if $(TAG),$(TAG),v$(PACKAGE_VERSION))
DIST_APP        := $(APP)-$(DIST_TAG)

INSTALL_PREFIX ?= $(HOME)/.local
INSTALL_BINDIR ?= $(INSTALL_PREFIX)/bin
OS             ?= darwin,linux
ARCH           ?= amd64,arm64

DARWIN_ARCHS := amd64 arm64
LINUX_ARCHS  := amd64 arm64
RUST_TARGETS := x86_64-apple-darwin aarch64-apple-darwin

DARWIN_amd64_TARGET := x86_64-apple-darwin
DARWIN_amd64_SUFFIX := darwin-amd64
DARWIN_arm64_TARGET := aarch64-apple-darwin
DARWIN_arm64_SUFFIX := darwin-arm64

LINUX_amd64_PLATFORM        := linux/amd64
LINUX_amd64_SUFFIX          := linux-amd64
LINUX_arm64_PLATFORM        := linux/arm64
LINUX_arm64_SUFFIX          := linux-arm64
LINUX_BUILD_IMAGE           ?= rust:1.95-bookworm
LINUX_SMOKE_IMAGE           ?= debian:bookworm-slim
LINUX_CACHE_KEY             := $(shell printf '%s' '$(LINUX_BUILD_IMAGE)' | sed 's/[^A-Za-z0-9_.-]/-/g')
LINUX_OPENSSL_STATIC        ?= 1
LINUX_PKG_CONFIG_ALL_STATIC ?= 1

DOCKER_UID ?= $(shell id -u)
DOCKER_GID ?= $(shell id -g)
HOST_OS    := $(shell uname -s)

HELP_NAME_WIDTH    := 18
HELP_EXAMPLE_WIDTH := 46

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
		'FING_DEMO_DELAY_SCALE="$(VHS_DEMO_DELAY_SCALE)" exec "$(CURDIR)/target/debug/examples/tui_demo" "$$@"' \
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
		'Set Framerate 24' \
		'Set PlaybackSpeed 1.0' \
		'Set TypingSpeed 45ms' \
		'Set CursorBlink false' \
		'' \
		'Type "$(APP) scan en0 en7 --scan.range 192.0.2.0/24,198.51.100.0/24 --output.live always"' \
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

##@ Distribution

.PHONY: release
release: ## Build 4 local dist binaries, push the tag, and publish a GitHub release. Requires TAG=vX.Y.Z
	@set -Eeuo pipefail; \
	SEMVER_TAG_RE='^v[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?([+][0-9A-Za-z][0-9A-Za-z.-]*)?$$'; \
	APP="$(APP)"; \
	tag="$(TAG)"; \
	remote="$(GIT_REMOTE)"; \
	release_os="darwin,linux"; \
	release_arch="amd64,arm64"; \
	dist_dir="$(DISTDIR)"; \
	fail() { echo "release: $$*" >&2; exit 1; }; \
	run() { printf '+'; printf ' %q' "$$@"; printf '\n'; "$$@"; }; \
	require_tool() { command -v "$$1" >/dev/null 2>&1 || fail "$$1 is required for local release publishing"; }; \
	manifest_value_at_ref() { git show "$$1:Cargo.toml" | sed -n "s/^$$2 = \"\\(.*\\)\"/\\1/p" | head -n 1; }; \
	is_prerelease_tag() { [[ "$$1" == *-* ]]; }; \
	repository_slug() { \
		local repo="$${GH_REPO:-$${GITHUB_REPOSITORY:-}}" url; \
		if [[ -z "$$repo" ]]; then \
			url="$$(git config --get "remote.$$remote.url" || true)"; \
			case "$$url" in \
				git@github.com:*) repo="$${url#git@github.com:}" ;; \
				https://github.com/*) repo="$${url#https://github.com/}" ;; \
				ssh://git@github.com/*) repo="$${url#ssh://git@github.com/}" ;; \
				*) fail "could not infer GitHub repository from remote $$remote; set GH_REPO=owner/repo" ;; \
			esac; \
		fi; \
		repo="$${repo#https://github.com/}"; \
		repo="$${repo%.git}"; \
		[[ "$$repo" == */* ]] || fail "GitHub repository must look like owner/repo, got $$repo"; \
		printf '%s\n' "$$repo"; \
	}; \
	require_clean_worktree() { \
		local status; \
		status="$$(git status --porcelain)"; \
		if [[ -n "$$status" ]]; then \
			git status --short >&2; \
			fail "working tree must be clean before release"; \
		fi; \
	}; \
	release_assets() { \
		local assets=(); \
		shopt -s nullglob; \
		assets=("$$dist_dir"/*); \
		shopt -u nullglob; \
		(($${#assets[@]} > 0)) || fail "no release assets found in $$dist_dir"; \
		printf '%s\0' "$${assets[@]}"; \
	}; \
	publish_github_release() { \
		local release_tag="$$1" release_commit="$$2" repository="$$3" assets=(); \
		while IFS= read -r -d '' asset; do assets+=("$$asset"); done < <(release_assets); \
		if gh release view "$$release_tag" --repo "$$repository" >/dev/null 2>&1; then \
			run gh release upload "$$release_tag" "$${assets[@]}" --clobber --repo "$$repository"; \
			return; \
		fi; \
		if is_prerelease_tag "$$release_tag"; then \
			run gh release create "$$release_tag" \
				--repo "$$repository" \
				--target "$$release_commit" \
				--title "$$release_tag" \
				--generate-notes \
				--prerelease \
				"$${assets[@]}"; \
		else \
			run gh release create "$$release_tag" \
				--repo "$$repository" \
				--target "$$release_commit" \
				--title "$$release_tag" \
				--generate-notes \
				"$${assets[@]}"; \
		fi; \
	}; \
	[[ -n "$$tag" ]] || fail "TAG is required, for example: make release TAG=v0.1.0"; \
	[[ "$$tag" =~ $$SEMVER_TAG_RE ]] || fail "TAG must look like vMAJOR.MINOR.PATCH"; \
	cd "$$(git rev-parse --show-toplevel)"; \
	require_clean_worktree; \
	require_tool git; \
	require_tool gh; \
	require_tool shasum; \
	repository="$$(repository_slug)"; \
	remote_line="$$(git ls-remote --tags "$$remote" "refs/tags/$$tag" | sed -n '1p')"; \
	remote_oid="$${remote_line%%[[:space:]]*}"; \
	if git rev-parse -q --verify "refs/tags/$$tag" >/dev/null; then \
		local_oid="$$(git rev-parse "refs/tags/$$tag")"; \
		if [[ -n "$$remote_oid" && "$$remote_oid" != "$$local_oid" ]]; then \
			fail "local tag $$tag does not match $$remote/tags/$$tag"; \
		fi; \
		printf 'Using existing tag %s at %s\n' "$$tag" "$$(git rev-list -n 1 "$$tag")"; \
	elif [[ -n "$$remote_oid" ]]; then \
		run git fetch "$$remote" "refs/tags/$$tag:refs/tags/$$tag"; \
		printf 'Using fetched tag %s at %s\n' "$$tag" "$$(git rev-list -n 1 "$$tag")"; \
	else \
		run git tag "$$tag"; \
		created_tag=1; \
		printf 'Created tag %s at %s\n' "$$tag" "$$(git rev-parse HEAD)"; \
	fi; \
	cleanup() { \
		status=$$?; \
		if [[ "$${created_tag:-0}" == "1" && "$${pushed_created_tag:-0}" != "1" ]]; then \
			git tag -d "$$tag" >/dev/null 2>&1 || true; \
		fi; \
		exit "$$status"; \
	}; \
	trap cleanup EXIT; \
	release_ref="refs/tags/$$tag"; \
	release_commit="$$(git rev-list -n 1 "$$tag")"; \
	head_commit="$$(git rev-parse HEAD)"; \
	[[ "$$release_commit" == "$$head_commit" ]] || fail "$$tag points to $$release_commit, but HEAD is $$head_commit; checkout the release commit first"; \
	tag_version="$${tag#v}"; \
	package_name="$$(manifest_value_at_ref "$$release_ref" name)"; \
	package_version="$$(manifest_value_at_ref "$$release_ref" version)"; \
	[[ "$$package_name" == "$$APP" ]] || fail "Cargo.toml package name is $$package_name, expected $$APP"; \
	[[ "$$package_version" == "$$tag_version" ]] || fail "Cargo.toml version $$package_version does not match $$tag"; \
	run "$(RELEASE_MAKE)" dist TAG="$$tag" OS="$$release_os" ARCH="$$release_arch"; \
	run git push "$$remote" "refs/tags/$$tag"; \
	pushed_created_tag=1; \
	publish_github_release "$$tag" "$$release_commit" "$$repository"; \
	printf 'Published %s from local release artifacts.\n' "$$tag"

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
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "OS" "Release OS list for make dist, defaults to $(OS)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "ARCH" "Release arch list for make dist, defaults to $(ARCH)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "INSTALL_BINDIR" "Install directory, defaults to $(INSTALL_BINDIR)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "VHS" "VHS command for make vhs, defaults to $(VHS)"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_NAME_WIDTH)" "VHS_DEMO_DELAY_SCALE" "Demo scan delay scale for make vhs, defaults to $(VHS_DEMO_DELAY_SCALE)"
	@printf "\n\033[1mExamples:\033[0m\n"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make fmt CHECK_ONLY=1" "# Check formatting without writing"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make check" "# Run local quality gates"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make vhs" "# Record screencast.gif from deterministic demo data"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make dist OS=darwin,linux ARCH=amd64,arm64" "# Build release binaries and checksums"
	@printf "  \033[36m%-*s\033[0m%s\n" "$(HELP_EXAMPLE_WIDTH)" "make release TAG=v0.1.0" "# Publish a GitHub release with local artifacts"

# Fing

A generic Fing made of Rust TUI - scans local IPv4 networks and uses ARP, OUI, DNS, mDNS, NetBIOS, UPnP, DHCP, SNMP, LLDP, CDP, SMB, HTTP, and TLS evidence as device fingerprints.

[![](https://github.com/mi2428/fing/blob/main/screencast.gif?raw=true)](https://github.com/mi2428/fing/blob/main/screencast.gif)

## Installation

### macOS (Homebrew)

Install the prebuilt macOS binary from the Homebrew tap.

```console
$ brew tap mi2428/fing
$ brew install --formula mi2428/fing/fing
```

### Build from source

Install Rust 1.95.0 with the `rustfmt` and `clippy` components first, then build and install the binary with `make install`.
`rust-toolchain.toml` selects this toolchain for rustup; `make` fails if it is missing rather than silently using another Rust installation.
Native toolchains without rustup (including Nix) use their tools on `PATH`; explicit `CARGO`, `RUSTC`, and `RUSTDOC` overrides are also supported.
See [the compiler policy](docs/maintenance-dependencies.md) for alternative toolchains and validation limits.
By default, the binary is installed to `~/.local/bin/fing`.
Set `INSTALL_BINDIR` if you want to install it somewhere else.

```console
$ git clone https://github.com/mi2428/fing
$ make -C fing install
```

>[!TIP]
> Prebuilt binaries are also available from GitHub Releases for macOS and Linux, with amd64 and arm64 builds for each platform.
> Pick the asset that matches your machine, make it executable, and place it on your `PATH`.
>
> ```console
> $ curl -L -o fing https://github.com/mi2428/fing/releases/download/v0.12.3/fing-v0.12.3-darwin-arm64
> $ chmod +x ./fing
> ```

## Usage

```console
$ fing scan --help

Generic Fing - scan local IPv4 networks and enrich device identities

Usage: fing scan [OPTIONS] <Interfaces>...

Arguments:
  <Interfaces>...  Interfaces to scan, such as en0, eth0, or en0.100

Options:
      --scan.range <CIDR>               Limit scanning to one or more IPv4 CIDR ranges. Can be repeated or comma-separated
      --scan.profile <PROFILE>          Scan profile [default: normal] [possible values: none, fast, normal, deep]
      --scan.interval <MS>              Delay between continuous scan rounds in milliseconds. Zero starts the next round immediately [default: 0]
      --scan.timeout <MS>               Per-protocol timeout in milliseconds
      --scan.concurrency <CONCURRENCY>  Concurrent scan/probe worker limit [default: 128]
      --output.format <FORMAT>          Output format [default: table] [possible values: table, json, csv]
      --output.live <LIVE>              Live TUI mode: auto uses it only for interactive table output [default: auto] [possible values: auto, always, never]
      --output.mask-mac                 Mask the lower 24 bits of MAC addresses in output
  -h, --help                            Print help
  -V, --version                         Print version

Fingerprint Options:
      --fingerprint.source <SOURCE>
          Enable additional fingerprint sources on top of the selected profile [possible values: oui, rdns, mdns, netbios, upnp, deep, ssh, http, tls, smb, snmp, lldp, cdp, dhcp]
      --no-fingerprint.source <SOURCE>
          Disable specific fingerprint sources after profile and additive selection [possible values: oui, rdns, mdns, netbios, upnp, deep, ssh, http, tls, smb, snmp, lldp, cdp, dhcp]
      --dhcp.leases <DHCP_LEASES>
          Read DHCP leases from an explicit lease file. Can be repeated
      --snmp.community <SNMP_COMMUNITY>
          SNMP community used when SNMP fingerprinting is enabled [default: public]
```

Scan one or more interfaces. Raw ARP discovery may require elevated privileges on some systems.

```console
$ sudo fing scan en0
$ sudo fing scan en0 --scan.range 192.168.1.0/24
$ sudo fing scan en0 --scan.profile deep --output.format json --output.live never
$ sudo fing scan en0 --scan.profile none --fingerprint.source ssh
$ sudo fing scan en0 --scan.profile deep --no-fingerprint.source ssh
```

Update the local IEEE OUI vendor database:

```console
$ fing oui update
$ fing oui update --output.path ./oui.json
```

>[!NOTE]
> LLDP and CDP collection are passive and run by default with the `deep` profile.
> In live/continuous mode, both listeners stay up across scan rounds and update matching devices as advertisements arrive.
> In one-shot output mode, an enabled LLDP listener waits at least 30 seconds and an enabled CDP listener waits at least 65 seconds because common Cisco defaults advertise every 60 seconds.
> You can also request them explicitly with `--fingerprint.source lldp` or `--fingerprint.source cdp`.

## Development

The Quality workflow runs `make check` on macOS and Linux for every pull request and pushes to `main`/`develop`, using `rust-toolchain.toml` and locked dependencies.
The default tests use synthetic data and loopback services; CI does not perform privileged LAN scans or publish artifacts.
Run `ruby .github/tests/ci_contract.rb` to check the CI configuration contract locally.

### Dependency maintenance

The separate Dependency advisories workflow checks the entire `Cargo.lock` against OSV (RustSec and GitHub advisories) on PRs, pushes to `main`/`develop`, and weekly, including inactive and platform-specific packages.
It fails on findings or scanner errors without exceptions, OS/architecture filters, or call-analysis suppression; a version match is not proof of application-level exploitability.
With [OSV-Scanner v2.6.0](https://github.com/google/osv-scanner/releases/tag/v2.6.0), reproduce it using `osv-scanner scan source --lockfile=./Cargo.lock`.
Dependabot proposes weekly individual Cargo updates (including transitives), with at most five open version-update PRs; updates run the same Quality checks and are not automatically merged or released.

Baseline triage (`830239d`; no advisory exceptions are configured):

| Package | Advisory | Reachability and disposition |
| --- | --- | --- |
| rustls 0.23.40 | RUSTSEC-2026-0285 | Active through reqwest TLS; update to >=0.23.45 in [#26](https://github.com/mi2428/fing/issues/26). |
| quinn-proto 0.11.14 | RUSTSEC-2026-0185 / GHSA-4w2j-m93h-cj5j | Locked but no active host dependency path; reqwest HTTP/3 is disabled. Update to >=0.11.15 in #26. |
| anyhow 1.0.102 | RUSTSEC-2026-0190 | No application `downcast_mut` calls; update to >=1.0.103 in [#27](https://github.com/mi2428/fing/issues/27). |
| crossbeam-epoch 0.9.18 | RUSTSEC-2026-0204 | hickory-resolver -> moka; affected pointer-formatting reachability is unproven. Update to >=0.9.20 in [#28](https://github.com/mi2428/fing/issues/28). |
| lru 0.16.4 | RUSTSEC-2026-0253 | ratatui-core cache; affected panic/unwind/key-Drop behavior is not demonstrated. Update the parent graph to lru >=0.18.2 in [#29](https://github.com/mi2428/fing/issues/29). |
| openssl 0.10.79 | GHSA-phqj-4mhp-q6mq | Linux native-tls certificate probes; no application `cipher_update_inplace` calls. Update to >=0.10.80 in [#30](https://github.com/mi2428/fing/issues/30). |
| quick-xml 0.39.4 | RUSTSEC-2026-0194 / RUSTSEC-2026-0195 | UPnP uses plain `Reader`, not attribute iteration or `NsReader`; update to >=0.41.0 in [#31](https://github.com/mi2428/fing/issues/31). |

The advisory job stays red for affected lockfiles until the scoped dependency fixes land; do not suppress findings to make it green.
Any future exception must identify the advisory, affected versions, reachability evidence, owner and review/removal condition in a reviewed change.

### Release

`make release TAG=vX.Y.Z` validates the selected release revision and runs `make check` before creating a new tag, then builds four local release binaries, pushes the Git tag, creates or updates the GitHub Release with generated release notes, uploads the release artifacts, and updates the Homebrew formula in `../homebrew-fing`.
The default release matrix is macOS/Linux for amd64/arm64.
Set `HOMEBREW_TAP=0` to skip the Homebrew tap update, or `HOMEBREW_TAP_DIR=/path/to/tap` to use another checkout.
Before releasing, this repository must have a clean working tree; it is checked again after the quality gate. Existing local/remote tags must still match HEAD and the package version, and retries run the quality gate again.
Run `python3 .github/tests/release_gate.py` for the synthetic, fully stubbed release regression (no real git/gh, builds, tags, pushes, releases or tap updates).

```console
$ make

Development
  build                      Build the host binary into bin/
  install                    Build and install the host binary into INSTALL_BINDIR
  fmt                        Format Rust sources. Use CHECK_ONLY=1 to check without writing
  lint                       Run clippy with warnings treated as errors
  doc                        Build rustdoc with warnings treated as errors
  test                       Run unit tests
  check                      Run formatting, lint, rustdoc, and tests
  clean                      Remove local build artifacts

Demo
  vhs                        Record the README live TUI demo GIF with VHS

Distribution
  release                    Build dist, publish a GitHub release, and update Homebrew. Requires TAG=vX.Y.Z
  dist                       Build release binaries into dist/. Use OS=darwin,linux and ARCH=amd64,arm64
  dist-smoke                 Smoke-test Linux dist binaries in a Debian container
  checksums                  Write SHA-256 checksums for dist artifacts

Help
  help                       Show this help message

Variables:
  TAG                        Release tag for make release, for example v0.1.0
  GIT_REMOTE                 Release git remote, defaults to origin
  HOMEBREW_TAP               Set to 0 to skip Homebrew tap updates, defaults to 1
  HOMEBREW_TAP_DIR           Homebrew tap checkout, defaults to ../homebrew-fing
  HOMEBREW_TAP_REMOTE        Homebrew tap git remote, defaults to origin
  HOMEBREW_TAP_SLUG          brew tap slug, defaults to GitHub owner/fing
  HOMEBREW_TAP_README_TITLE  Homebrew tap README title, defaults to homebrew-fing
  HOMEBREW_DESC              Homebrew formula description
  HOMEBREW_FORMULA_CLASS     Homebrew Ruby class, defaults to Fing
  OS                         Release OS list for make dist, defaults to darwin,linux
  ARCH                       Release arch list for make dist, defaults to amd64,arm64
  INSTALL_BINDIR             Install directory, defaults to ~/.local/bin
  VHS                        VHS command for make vhs, defaults to vhs
  VHS_DEMO_COMMAND           Demo command for make vhs
  VHS_DEMO_DELAY_SCALE       Demo scan delay scale for make vhs, defaults to 4
  VHS_FRAMERATE              VHS recording framerate, defaults to 24

Examples:
  make fmt CHECK_ONLY=1                       # Check formatting without writing
  make check                                  # Run local quality gates
  make vhs                                    # Record screencast.gif from deterministic demo data
  make dist OS=darwin,linux ARCH=amd64,arm64  # Build release binaries and checksums
  make release TAG=v0.1.0                     # Publish a GitHub release and update Homebrew
```

## License

MIT

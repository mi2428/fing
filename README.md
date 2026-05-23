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

Install Rust and Cargo first, then build and install the binary with `make install`.
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
> $ curl -L -o fing https://github.com/mi2428/fing/releases/download/v0.9.0/fing-v0.9.0-darwin-arm64
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
      --scan.profile <PROFILE>          Scan profile [default: normal] [possible values: fast, normal, deep]
      --scan.interval <MS>              Delay between continuous scan rounds in milliseconds. Zero starts the next round immediately [default: 0]
      --scan.timeout <MS>               Per-protocol timeout in milliseconds
      --scan.concurrency <CONCURRENCY>  Concurrent scan/probe worker limit [default: 128]
      --output.format <FORMAT>          Output format [default: table] [possible values: table, json, csv]
      --output.live <LIVE>              Live TUI mode: auto uses it only for interactive table output [default: auto] [possible values: auto, always, never]
      --output.mask-mac                 Mask the lower 24 bits of MAC addresses in output
  -h, --help                            Print help

Fingerprint Options:
      --fingerprint.source <SOURCE>
          Limit fingerprint sources. Defaults to profile-appropriate sources when omitted [possible values: oui, rdns, mdns, netbios, upnp, snmp, lldp, cdp, dhcp]
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

`make release TAG=vX.Y.Z` builds four local release binaries, pushes the Git tag, creates or updates the GitHub Release with generated release notes, uploads the release artifacts, and updates the Homebrew formula in `../homebrew-fing`.
The default release matrix is macOS/Linux for amd64/arm64.
Set `HOMEBREW_TAP=0` to skip the Homebrew tap update, or `HOMEBREW_TAP_DIR=/path/to/tap` to use another checkout.
Before releasing, this repository must have a clean working tree.

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

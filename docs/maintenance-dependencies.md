# Dependency and toolchain maintenance

## Compiler policy (#5)

The development/release compiler is Rust 1.95.0. `rust-toolchain.toml` and the Makefile select 1.95.0 for rustup users, including macOS release builds; the Linux release image is `rust:1.95-bookworm`. Install it with `rustup toolchain install 1.95.0 --component rustfmt --component clippy`. If rustup cannot find the selected tools, Make fails with an actionable error instead of falling back to PATH. Make targets unrelated to compilation do not require Rust.

Without rustup, native installations such as Nix use their tools on PATH. Explicit `CARGO`, `RUSTC`, and `RUSTDOC` paths still take precedence. An installed alternative can be selected with `cargo +VERSION` or `make RUSTUP_TOOLCHAIN=VERSION`; run `make check` for that environment. The manifest declares a compiler floor of 1.88, matching the highest declared requirement in the original graph. **Rust 1.88 has not been built/tested here: this declaration is not a verified MSRV guarantee.** The verified host is macOS arm64 with Rust 1.95.0; Linux/macOS cross-architecture release builds require their own validation.

The following non-building regression must fail with `Rust tools unavailable` even when Cargo is on PATH (no toolchain installation or release operation occurs):

```sh
if output=$(make -n test RUSTUP_TOOLCHAIN=fing-missing-toolchain 2>&1); then
    exit 1
fi
case "$output" in *"Rust tools unavailable"*) ;; *) exit 1 ;; esac
```

## Dependency decisions

Versions and advisories were rechecked against crates.io, upstream notes and OSV on 2026-10-03. Existing manifest ranges are retained when compatible lockfile updates suffice; no application API, direct dependency or requested feature is added.

| Issue | Resolution and compatibility evidence |
| --- | --- |
| #26 | reqwest 0.13.5 (declared Rust 1.85), rustls 0.23.45 (1.71), webpki-root-certs 1.0.9 (1.70), quinn-proto 0.11.15 (1.85). [reqwest notes](https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md) describe additive APIs and redirect/proxy fixes; existing blocking/rustls APIs compile unchanged. [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html) requires rustls >=0.23.45. Inactive QUIC lock entries are refreshed for RUSTSEC-2026-0185; HTTP/3 stays disabled, so no reachable QUIC vulnerability is claimed. Redirect denial, local binding, body limits, OUI verification and intentional local-certificate tolerance remain unchanged in source. |
| #27 | anyhow 1.0.104 (declared Rust 1.68). [1.0.103 notes](https://github.com/dtolnay/anyhow/releases/tag/1.0.103) fix `Error::downcast_mut` UB; 1.0.104 only updates a development dependency. Source search finds no downcasting; error contexts/propagation are untouched. RUSTSEC-2026-0190 no longer matches, without claiming reachable application UB. |

The smallest dependency regression checks the resolved patched versions and disabled HTTP/3 (it fails against the original lockfile; it is not an exploit test):

```sh
cargo metadata --locked --format-version 1 | python3 -c '
import json, sys
m = json.load(sys.stdin)
floors = {"rustls": "0.23.45", "quinn-proto": "0.11.15", "anyhow": "1.0.103"}
version = lambda v: tuple(map(int, v.split(".")))
for name, floor in floors.items():
    packages = [p for p in m["packages"] if p["name"] == name]
    assert packages and all(version(p["version"]) >= version(floor) for p in packages), name
reqwest = next(p["id"] for p in m["packages"] if p["name"] == "reqwest")
features = next(n["features"] for n in m["resolve"]["nodes"] if n["id"] == reqwest)
assert "http3" not in features and "quinn" not in features, features
print("dependency version/feature regression: passed")
'
```

Each update is checked with `make fmt CHECK_ONLY=1`, `make check`, locked metadata/tree and an all-platform OSV query. macOS arm64 is verified; Linux build/static-link smoke and isolated TLS-certificate extraction are not verified here because the Docker daemon is unavailable. Existing loopback HTTP redirect/body-limit and bundled OUI-root tests pass; these do not substitute for an end-to-end TLS fixture or MSRV build.

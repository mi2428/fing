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

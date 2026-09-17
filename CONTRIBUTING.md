# Contributing

Setting up from a machine with no Rust on it, building, and what CI checks. Written for a person; agents also read
[`AGENTS.md`](AGENTS.md).

## 1. Install Rust

Rust is installed with **rustup**, which manages compiler versions. Do not use a distribution or Homebrew `rust`
package: this repository pins its compiler in `rust-toolchain.toml`, and only rustup reads that file.

**macOS and Linux:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
```

The installer adds that `. "$HOME/.cargo/env"` line to your shell profile (`~/.zshenv` for zsh, `~/.profile` or
`~/.bashrc` otherwise), so new terminals find `cargo`. If `cargo` is "not found" in a new terminal, that line is
missing: add it yourself.

On macOS the compiler needs Apple's linker. If a build fails with `linker 'cc' not found`, run
`xcode-select --install`. On Debian or Ubuntu, `sudo apt install build-essential`.

**Windows:** download and run `rustup-init.exe` from <https://rustup.rs>, and install the "Desktop development with
C++" workload of the Visual Studio Build Tools when it asks.

**Already have rustup?** Nothing to do. Check with `rustup --version`.

## 2. Clone and build

```bash
git clone git@github.com:parawanderer/window-ml-hub.git
cd window-ml-hub
cargo test --workspace
```

The first `cargo` command in the directory installs the pinned toolchain (`rust-toolchain.toml`, with rustfmt and
clippy) automatically. That takes a minute once, and prints a note saying it did.

## 3. Editor

VS Code: install the **rust-analyzer** extension (`rust-lang.rust-analyzer`). It uses the pinned toolchain on its
own. Other editors: any rust-analyzer integration.

## What CI runs, and how to run it first

Every push to a pull request runs the same four checks. Run them before pushing:

```bash
cargo fmt --all --check                                   # formatting (cargo fmt --all fixes it)
cargo clippy --workspace --all-targets -- -D warnings     # lints, warnings are errors
cargo test --workspace
cargo doc --workspace --no-deps                           # doc comments must build
```

CI also builds and tests on the minimum supported Rust version (`rust-version` in `Cargo.toml`), so a feature newer
than that fails there even when it passes locally. It fuzzes every target for 30 seconds (`fuzz/`, nightly;
[docs/FUZZING.md](docs/FUZZING.md) has how to run it locally) and builds the Docker image.

## Updating the toolchain

The pin is deliberate: a new stable Rust brings new clippy lints, and those should not turn CI red on an unrelated
change. To move to a newer compiler, change `channel` in `rust-toolchain.toml` in its own commit and fix whatever
the new clippy reports there.

## Working with window-ml

The specs this server implements live in [window-ml](https://github.com/parawanderer/window-ml) (`docs/spec/`). A
change to the session contract is a pull request there, not here. For the probe in `tools/mv3-ws-probe` you need
Node 20 or later and any Chromium build; see the header of the script.

## Pull requests

Work on a branch and open a pull request against `main`; merge once CI is green.

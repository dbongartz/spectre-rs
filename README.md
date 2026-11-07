# spectre-rs

A Rust implementation of the Spectre password generator, inspired by the original Master Password algorithm.

This repository is organized as a Cargo workspace with:

- `spectre-rs-core`: core password-generation logic
- `spectre-rs-cli`: interactive command-line interface
- `spectre-rs-gui`: GUI application

## Quick start

```bash
cargo run -p spectre-rs-cli -- --help
```

Example:

```bash
cargo run -p spectre-rs-cli -- \
  --user-name alice \
  --site-name github.com \
  --secret "my secret" \
  --pw-type long
```

## Notes

- Secrets are read securely from a prompt by default.
- The project uses the Master Password-style derivation scheme to generate site-specific passwords.
- It is intended as a Rust-native alternative to the original Spectre password manager.

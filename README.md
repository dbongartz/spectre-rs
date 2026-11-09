# spectre-rs

A Rust implementation of the Spectre password generator, inspired by the original Master Password algorithm.

<img width="455" height="528" alt="image" src="https://github.com/user-attachments/assets/24430819-feec-44ba-a098-2ca993536d7f" />

This repository is organized as a Cargo workspace with:

- `spectre-rs-core`: core password-generation logic
- `spectre-rs-cli`: interactive command-line interface
- `spectre-rs-gui`: GUI application

## Quick start

```bash
cargo run -p spectre-rs-cli -- --help
```

Example (prompts for the secret without echoing it):

```bash
cargo run -p spectre-rs-cli -- --user-name alice --pw-type long github.com
```

For scripts, pipe the secret in with `--secret-stdin` instead of passing it as an argument, where
it would be visible in process listings and shell history.

## Notes

- The project uses the Master Password-style derivation scheme to generate site-specific passwords,
  and produces the same passwords as other Spectre clients.
- It is intended as a Rust-native alternative to the original Spectre password manager.

## Security

- The secret and passwords never leave the machine. Only the user name is saved (by the GUI).
- The GUI copies passwords marked as secret, so clipboard managers that honour the hint
  (KDE's Klipper among others) leave them out of their history. It clears the clipboard after
  30 seconds and on exit, unless something else has been copied since.
- Keeping secrets out of memory is best-effort. The core and CLI hold them in buffers that are
  wiped when dropped; the GUI also wipes its own copy, but its UI toolkit keeps short-lived
  copies of what is typed and shown that it cannot wipe.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

The fonts bundled with the GUI are licensed under the SIL Open Font License 1.1; see
[spectre-rs-gui/assets/fonts](spectre-rs-gui/assets/fonts/README.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.

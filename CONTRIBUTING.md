# Contributing

Read `AGENTS.md`, the relevant architecture decisions, and the affected specification sections before changing code.

## Required workflow

- Work from an issue or requirement ID once the requirement registry exists.
- Write a failing test before production behavior.
- Keep application-specific behavior in adapters.
- Do not weaken capability, package-identity, state, or update checks to make a fixture pass.
- Document unsafe interoperability and licensing boundaries.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Generated schemas must be reproducible and clean after `cargo xtask schema` once the schema generator is introduced.

Windows protocol and process changes also follow the
[runtime protocol testing matrix](docs/testing/runtime-protocol-matrix.md). Linux
Cargo under WSL is not native Windows evidence; use the documented PowerShell/native
Cargo lane with a separate Windows target directory.

## Licensing contributions

By submitting a contribution, you agree that it may be distributed under the
repository's [MIT License](LICENSE).

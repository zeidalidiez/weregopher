# Weregopher engineering instructions

## Read first

- The architecture specification is `docs/spec/weregopher-electron-transformation-runtime-spec.md`.
- Architecture decision records are under `docs/adr/`.
- Canonical serialized contracts live in Rust domain types and generated schemas. Do not hand-edit generated artifacts.

## Non-negotiable product boundaries

- Weregopher transforms installed desktop application packages. It is not a public-web wrapper.
- Never modify a vendor installation in place.
- Never hide a full vendor Electron application tree behind the term helper or ABI island.
- Exact package hashes identify evidence; durable family adapters provide compatibility.
- Functional compatibility, security posture, and efficiency are separate claims.

## Security defaults

- Treat Bun, vendor helpers, and ABI islands as unrestricted same-user processes unless an independently tested OS sandbox proves otherwise.
- Generated build overlays may rebind signed rules but may not expand authority, capabilities, native/helper content, privileged operations, state migrations, or security exceptions.
- Candidate verification must not touch production state.
- Job Objects are lifecycle/accounting controls, not sandboxes.
- Unknown transport data is not authorization. Privileged effects fail closed.
- Do not place secrets, tokens, proprietary package bytes, or raw traces in the repository.

## Development workflow

1. Add a failing behavior test and run it.
2. Implement the minimum code that passes.
3. Run the focused test, then the full affected suite.
4. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features`.
5. Update schemas, ADRs, and requirement traceability when a public contract changes.

## Rust conventions

- Stable Rust only unless an ADR says otherwise.
- Production code must not use `unwrap`, `expect`, or `panic`.
- Unsafe code is forbidden by default and must be isolated behind a crate-level exception plus documented invariants.
- Use bounded inputs and explicit error types at trust boundaries.
- Keep platform handles out of platform-neutral domain crates.

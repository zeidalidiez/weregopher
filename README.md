# Weregopher

Weregopher is an adapter-driven runtime for transforming installed Electron desktop applications into leaner, observable, and controllable execution forms while preserving the installed application's packaged behavior.

> **Status:** architecture validation and foundational implementation. No application adapter is currently certified for production use.

## Project boundaries

Weregopher:

- consumes installed application packages or immutable snapshots;
- preserves vendor package logic where practical;
- substitutes Electron, Node, renderer, and native boundaries through explicit adapters;
- does not replace desktop applications with public websites;
- does not patch vendor installations in place;
- does not claim universal Electron compatibility.

## Current milestone

The committed foundation contains the Rust workspace, canonical platform-neutral domain and protocol contracts, deterministic checked-in JSON Schemas, pure package-tree manifest construction from pre-observed records, and a bounded Windows primitive that hashes one direct regular file while retaining its identity handle opened without write/delete sharing. The single-file primitive does not establish package-root containment or coherent recursive-tree observation; package discovery, directory traversal, complete package scanning, and executable runtime components remain separate follow-up increments.

## Build

Prerequisites: Windows x64, Rust 1.97.1 with `rustfmt` and `clippy`.

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## Documentation

- Architecture specification: [`docs/spec/weregopher-electron-transformation-runtime-spec.md`](docs/spec/weregopher-electron-transformation-runtime-spec.md)
- Architecture decisions: [`docs/adr/`](docs/adr/)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE), at your option. Application assets, vendor helpers, adapter inputs, and third-party components retain their own licenses and are not relicensed by Weregopher.

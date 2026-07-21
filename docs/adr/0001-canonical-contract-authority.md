# ADR-0001: Canonical contract authority

- Status: Accepted
- Date: 2026-07-20

## Context

The architecture specification duplicated domain and protocol pseudocode with incompatible field names and types. Independent implementations require one authoritative source.

## Decision

The `weregopher-domain` crate is the canonical semantic model during the foundation milestone. Public Rust types derive serialization and JSON Schema metadata. Repository automation generates external schemas and documentation from those types. Generated files are verified in CI and are not edited manually.

UUID newtypes identify applications, runtimes, and protocol sessions. Renderer and broker-object numeric IDs are app-scoped `u64` values and are always transported with the owning application identity. Serialized enum and field spellings are snake_case unless an explicitly versioned external protocol requires otherwise.

A future binary codec ADR may change wire encoding but may not change semantic types without a versioned contract migration.

## Consequences

- Appendix pseudocode is nonnormative.
- Schemas, TypeScript definitions, and examples must be generated or validated against the canonical model.
- Breaking serialized changes require a protocol/schema version change and migration documentation.

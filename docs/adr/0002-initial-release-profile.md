# ADR-0002: Initial delivery profile and stage gates

- Status: Accepted
- Date: 2026-07-20

## Context

The complete specification describes several product generations. Building every runtime, renderer, topology, adapter, state system, and certification path before exercising a vertical slice would defer the highest-risk discoveries.

## Decision

Implementation proceeds through explicit gates:

1. **G0 Contract foundation:** canonical types, schemas, CLI identity, security postures, and repository quality gates.
2. **G1 Synthetic vertical slice:** package fingerprint, immutable view, standalone worker/shell protocol fixture, packaged renderer fixture, and deterministic shutdown.
3. **G2 Target feasibility:** installed OpenAI discovery, package identity, preload/contextBridge fidelity, exact bundled app-server discovery and handshake.
4. **G3 Exact-build Codex preview:** one pinned fingerprint, dedicated state, core thread/turn/approval/helper-cleanup workflows.
5. **G4 Update-capable certification:** a second compatible build, nonexpanding generated overlay, transactional state evidence, and fixed certification profile.
6. **G5 Broader compatibility:** QuickJS optimization, shared topology, optional CEF, additional surfaces and adapters as evidence justifies them.

Bun or a pinned Node-compatible reference worker may establish compatibility before QuickJS supports the target call graph. Standalone shell and dedicated renderer data are the initial defaults.

## Consequences

This sequencing narrows delivery gates, not the project thesis. Features remain in the north-star specification but do not block earlier evidence-producing milestones.

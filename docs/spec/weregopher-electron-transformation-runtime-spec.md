# Weregopher: Adapter-Driven Electron Application Transformation Runtime

**Status:** Architecture and implementation specification  
**Audience:** Codex and experienced systems/application engineers  
**Primary platform:** Windows 11, with Windows 10 support where the required APIs are available  
**Primary implementation languages:** Rust, TypeScript/JavaScript, and small C/C++ interoperability layers where unavoidable  
**Project name:** **Weregopher**  
**Design thesis:** Preserve the application. Transform the runtime.  
**Transformation theme:** Convert installed Electron applications from their vendor Electron form into leaner, controllable Weregopher forms without substituting public web clients.  
**License:** MIT  
**Research baseline:** 2026-07-19  
**Document intent:** This is the build specification and research record. It is not a product pitch, tutorial, phased “starter project,” or proposal to replace desktop clients with websites.

---

## Project identity and transformation vocabulary

**Weregopher is the formal and locked project name.** It is the identity of the architecture, runtime, tooling, adapter ecosystem, and resulting application transformations. All public binaries, crates, package formats, protocol namespaces, environment variables, storage roots, documentation, and adapter metadata MUST use the Weregopher name unless an operating-system constraint requires a shorter identifier.

The project metaphor is controlled transformation rather than wrapping, emulation for its own sake, or resource throttling after Electron has already started. An installed Electron desktop package is treated as the application’s **source form**. Weregopher discovers its components, preserves the application-specific behavior that matters, substitutes runtime infrastructure where appropriate, and executes a **transformed form** under a leaner and more controllable host.

The transformation pipeline is:

```text
Electron application source form
├── packaged renderer assets
├── main-process JavaScript
├── preload and IPC contracts
├── Node dependencies
├── native modules and helpers
├── local state and storage formats
└── desktop integrations
             │
             ▼
      Weregopher adapter
├── discovers and fingerprints the package
├── preserves, transforms, or replaces each boundary
├── selects QuickJS-NG, Bun, or a bounded compatibility island
├── selects WebView2, CEF, or a specialized renderer surface
├── binds native desktop capabilities
└── verifies behavior against the original package
             │
             ▼
Weregopher-transformed application form
├── actual packaged application behavior
├── no public-web substitute
├── reduced or better-controlled Electron infrastructure
├── explicit native compatibility components
└── measured compatibility and resource characteristics
```

Normative vocabulary:

- **Source form:** the installed Electron application package or an immutable snapshot of it.
- **Transformation:** the complete adapter-controlled process of discovering, preserving, rewriting, substituting, brokering, and executing application components outside the vendor’s normal full Electron desktop process tree.
- **Transformed form:** the runnable result produced by Weregopher for a specific application build and adapter contract.
- **Transformation adapter:** the application-family logic, generated build descriptor, semantic overlays, compatibility components, tests, and certification evidence required to create the transformed form. The shorter term **adapter** remains acceptable in code and prose.
- **Preserved component:** vendor code or data executed substantially unchanged because preserving it best maintains application behavior.
- **Transformed component:** vendor code rewritten or rebound through deterministic adapter logic.
- **Substituted component:** Electron, Node, renderer, native, or operating-system infrastructure supplied by Weregopher instead of the vendor runtime.
- **Compatibility island:** a narrowly bounded process that preserves an ABI-dependent component without restoring the vendor’s complete Electron application architecture.

The theme MUST remain technically meaningful. Names and UI copy MAY use metamorphosis imagery, but engineering terminology must stay precise. Weregopher is not a website wrapper, a cosmetic skin, or a generic RAM cleaner. Its defining action is transforming the installed Electron desktop application into a different executable runtime form.

---

## Table of contents

- [Project identity and transformation vocabulary](#project-identity-and-transformation-vocabulary)

1. [Executive summary](#1-executive-summary)
2. [Normative language and decision status](#2-normative-language-and-decision-status)
3. [Problem statement](#3-problem-statement)
4. [Hard constraints](#4-hard-constraints)
5. [Explicit non-goals](#5-explicit-non-goals)
6. [Research conclusions](#6-research-conclusions)
7. [Product and engineering goals](#7-product-and-engineering-goals)
8. [Success metrics](#8-success-metrics)
9. [Compatibility and parity model](#9-compatibility-and-parity-model)
10. [High-level architecture](#10-high-level-architecture)
11. [Process topology and executables](#11-process-topology-and-executables)
12. [Core domain model](#12-core-domain-model)
13. [Installed-application discovery](#13-installed-application-discovery)
14. [Build fingerprinting](#14-build-fingerprinting)
15. [Package views, live mode, and immutable snapshots](#15-package-views-live-mode-and-immutable-snapshots)
16. [ASAR-aware virtual filesystem](#16-asar-aware-virtual-filesystem)
17. [Adapter architecture](#17-adapter-architecture)
18. [Adapter package format and trust](#18-adapter-package-format-and-trust)
19. [High-frequency vendor update compatibility](#19-high-frequency-vendor-update-compatibility)
20. [JavaScript runtime abstraction](#20-javascript-runtime-abstraction)
21. [QuickJS-NG runtime](#21-quickjs-ng-runtime)
22. [Bun runtime and hybrid roles](#22-bun-runtime-and-hybrid-roles)
23. [Node compatibility subsystem](#23-node-compatibility-subsystem)
24. [Electron compatibility object model](#24-electron-compatibility-object-model)
25. [Renderer backends](#25-renderer-backends)
26. [Preload, context isolation, and renderer bridging](#26-preload-context-isolation-and-renderer-bridging)
27. [IPC and serialization](#27-ipc-and-serialization)
28. [Native modules, vendor helpers, and ABI islands](#28-native-modules-vendor-helpers-and-abi-islands)
29. [Windows shell implementation](#29-windows-shell-implementation)
30. [Capability and security model](#30-capability-and-security-model)
31. [State, authentication, migration, and rollback](#31-state-authentication-migration-and-rollback)
32. [Resource accounting and governance](#32-resource-accounting-and-governance)
33. [Behavioral oracle and differential tracing](#33-behavioral-oracle-and-differential-tracing)
34. [Inference-assisted adapter development](#34-inference-assisted-adapter-development)
35. [Testing and certification](#35-testing-and-certification)
36. [Codex and unified ChatGPT desktop adapter](#36-codex-and-unified-chatgpt-desktop-adapter)
37. [Other target application profiles](#37-other-target-application-profiles)
38. [Repository architecture](#38-repository-architecture)
39. [CLI and developer workflows](#39-cli-and-developer-workflows)
40. [Engineering work packages and dependency graph](#40-engineering-work-packages-and-dependency-graph)
41. [Definition of done](#41-definition-of-done)
42. [Known risks and unresolved questions](#42-known-risks-and-unresolved-questions)
43. [Instructions for Codex](#43-instructions-for-codex)
44. [Appendix A: manifest example](#appendix-a-manifest-example)
45. [Appendix B: protocol types](#appendix-b-protocol-types)
46. [Appendix C: parity scenario DSL](#appendix-c-parity-scenario-dsl)
47. [Appendix D: research bibliography](#appendix-d-research-bibliography)

---

# 1. Executive summary

Weregopher is a Windows-first, open-source transformation runtime for installed Electron desktop applications. It treats the vendor’s installed Electron package as transformation input: the application keeps its identity, packaged desktop interface, local behavior, data formats, native integrations, and helper machinery while its runtime form is replaced with an adapter-controlled Weregopher form. It does **not** load public web versions of applications. It consumes the application’s installed desktop package—its packaged renderer assets, Electron main-process JavaScript, preload scripts, native modules, helper executables, storage formats, plugins, media components, and other desktop-only machinery—and transforms that package for execution through Weregopher’s native shell, alternate JavaScript runtimes, renderer backends, brokers, and supervised compatibility components.

The project’s main technical objective is to transform Electron applications into leaner and more controllable runtime forms by removing or reducing duplicated Electron infrastructure while preserving desktop behavior. Electron applications normally include a Node-capable main process, Chromium renderer processes, preload contexts, IPC, and native desktop APIs. Weregopher replaces those layers with:

- a native Rust/Win32 shell;
- a shared or standalone renderer host using WebView2 by default, CEF when required, or a specialized vendor surface when neither general backend is sufficient;
- a QuickJS-NG main-process runtime with Node APIs implemented or brokered in Rust;
- Bun as a full alternate runtime, transpiler/bundler, and optional helper runtime;
- an Electron object broker that implements the application-used Electron API surface;
- per-application adapters containing package discovery rules, transforms, module aliases, native replacements, compatibility contracts, tests, and declared exceptions;
- narrowly scoped native helper processes or matching-ABI islands for proprietary or ABI-bound components that cannot be sensibly rewritten;
- a package scanner, behavioral oracle, differential test harness, and inference-assisted adapter-generation toolchain;
- integrated resource accounting, process ownership, leak/runaway detection, lifecycle management, and update verification.

The compatibility unit is not “all Electron applications.” The compatibility unit is an application family plus a discovered build contract. Manual, application-specific compatibility work is accepted and expected. The project may support Discord, GitHub Desktop, Notion, Obsidian, Slack, TIDAL, Visual Studio Code, Blockbench, and the unified ChatGPT desktop application, with Codex workflows as the first and most important acceptance target.

The application’s exact package hash remains important for identity, reproducibility, certification, and rollback. It is **not** a requirement to hand-author a new adapter for every update. This distinction is mandatory for Codex and other fast-moving desktop packages. Weregopher maintains durable family adapters, automatically generates build descriptors, semantically rebinds transforms, probes runtime and renderer contracts, runs smoke and parity tests, and promotes compatible builds under one of three update policies:

- `follow-verified`: use the newest build that passes the configured contract and test gates;
- `follow-current`: attempt the currently installed vendor build after mandatory safety and compatibility probes;
- `pinned`: continue using a chosen immutable snapshot.

The default execution topology is one lightweight JavaScript worker process per application and one native shell process per application or a shared shell, selected by policy. WebView2 instances may share one user-data folder and browser process infrastructure while using separate profiles for application/account isolation. Shared browser infrastructure is an optimization, not a claim that all applications share one renderer or JavaScript heap.

The default JavaScript engine is QuickJS-NG because it is small and embeddable and has usable Rust bindings and prior art in LLRT. Bun is the compatibility shield for applications whose Node assumptions exceed the implemented QuickJS/Node surface. A matching-ABI island is the last resort for a narrowly bounded native module or module group. The vendor’s original full Electron desktop executable and browser process tree are not valid “helper” components in an optimized adapter.

The unified ChatGPT/Codex adapter is contract-driven. It preserves as much packaged OpenAI main-process logic as possible, treats application IPC channels as opaque unless they cross a replaced native boundary, supervises the exact bundled `codex app-server`, generates version-specific schemas from that binary, passes unknown app-server methods and fields through by default, and preserves Windows sandbox, WSL, MCP, plugin, worktree, Git, browser, preview, skill, and scheduled-task behaviors. Frequent vendor updates are handled by automated discovery and contract verification rather than hand-written per-build mappings.

---

# 2. Normative language and decision status

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

A statement marked **Locked decision** is not an implementation suggestion. Codex should implement against it unless a contradiction is discovered and documented with evidence.

A statement marked **Implementation choice** may be changed if the replacement preserves the surrounding contracts and is documented in an architecture decision record.

A statement marked **Research hypothesis** requires measurement or a compatibility experiment before it becomes a product claim.

## 2.1 Locked decisions

| Area | Locked decision |
|---|---|
| Project model | Adapter-driven transformation runtime for installed Electron desktop application packages |
| Public websites | Never used as a substitute for installed desktop clients |
| Primary platform | Windows-first |
| Core license | MIT |
| Core implementation | Rust |
| Windows shell | Raw Win32/COM with DirectComposition where composition hosting requires it |
| Primary renderer | Direct WebView2 |
| Alternate renderer | Optional CEF backend |
| Additional renderer | Adapter-specific specialized vendor surface |
| Primary JS engine | QuickJS-NG |
| Future JS engine | Preserve a backend interface capable of supporting Boa |
| Runtime isolation | Configurable; one worker process per application by default |
| Bun | Full alternate runtime, build/transpilation tool, and optional helper runtime |
| Shell topology | Shared multi-application host and standalone per-application shell are both supported |
| Package mode | Live read-only package view and immutable snapshot; `auto` selects; snapshot is the safe default |
| WebView2 version | Evergreen for normal use; fixed versions in compatibility CI or adapter-specific cases |
| Privileges | Capability-limited by default with an explicit, visible full-user-access escape hatch |
| Adapter matching | Durable family contracts plus generated build descriptors; exact hashes identify and certify builds |
| Proprietary native code | Permitted only as bounded helper, N-API module, ABI island, or specialized surface |
| Behavioral oracle | Temporary local instrumentation of proprietary installed packages is permitted |
| Authentication | One explicit reauthentication is acceptable |
| Stable label | Stable adapters may contain declared exceptions; critical security/data-integrity deficits still block stability |
| Adapter trust | Signed public registry plus unrestricted local developer mode |
| Trace storage | Redacted local traces by default; encrypted raw traces only by explicit opt-in |
| WebView2 data layout | Adapter-selectable; shared UDF with separate profiles is the default |
| OpenAI scope | Complete installed unified ChatGPT desktop package is in scope; Codex is the priority surface |
| OpenAI updates | Contract-driven, generated deltas; no hand-maintained adapter for every update |

---

# 3. Problem statement

Electron’s architecture is useful because it packages Chromium, Node, native desktop APIs, and application code into a predictable cross-platform unit. Its cost is that unrelated applications typically carry and execute separate copies of the same broad runtime architecture. Each application has its own main process and commonly multiple renderer, GPU, network, utility, crash-reporting, and helper processes. The application’s own JavaScript, DOM, caches, images, media, databases, extensions, and native modules add to that baseline.

The source relationship between two Electron applications does not place them in one memory space. Windows processes have distinct address spaces. Some executable and mapped-file pages may be shared by the operating system when the binaries are identical and mapped compatibly, but the applications do not share their V8 heaps, JavaScript objects, DOMs, Node state, renderer state, or application caches.

External resource governors can monitor and constrain Electron applications, but they cannot free live objects inside an application’s heap or replace an initialized Chromium renderer. A meaningful reduction in architectural overhead requires launching the application package in a different runtime before the original Electron process tree is created.

Weregopher therefore targets the following problem:

> Given an installed Electron desktop application package and an application-specific transformation adapter, convert that package from its vendor Electron execution form into a Weregopher-managed execution form without launching the vendor’s full Electron desktop runtime, while preserving the application’s declared desktop behavior and measurably improving or more precisely controlling its aggregate resource usage.

---

# 4. Hard constraints

## 4.1 Installed desktop package is the source application

Weregopher MUST operate on the installed desktop package or a managed snapshot of it.

For a target such as TIDAL, this means the packaged desktop renderer, main-process code, native audio/media/DRM components, offline-storage behavior, helper executables, and device integrations. It does not mean `listen.tidal.com` in an embedded browser.

For Discord, it means the installed desktop package, including its voice/video/streaming/native modules and overlay components where supported. It does not mean the Discord website.

For Codex/ChatGPT, it means the installed desktop package, its packaged shell and renderer, its exact bundled Codex executable/app-server and helpers, its state, its MCP/plugin/skill machinery, and its Windows/WSL integration. It does not mean the Codex or ChatGPT website.

## 4.2 Manual per-application compatibility is acceptable

The runtime does not need to make arbitrary Electron packages work without intervention. Every supported application MAY have:

- package-family discovery rules;
- build-contract rules;
- main/preload/renderer transforms;
- module aliases;
- native replacements;
- vendor helper manifests;
- renderer-backend selection;
- state migrations;
- application-specific tests;
- version-specific generated overlays;
- declared feature exceptions.

## 4.3 Full desktop behavior is the target

The target is the installed desktop application’s behavior, not parity with a browser edition.

An adapter MAY be labeled stable with declared exceptions because that decision is locked. However, exceptions MUST be explicit and machine-readable. Silent loss of security boundaries, data integrity, approval semantics, sandbox semantics, or process cleanup is not an acceptable exception.

## 4.4 Original vendor install remains untouched

Weregopher MUST NOT patch the vendor installation in place.

It MAY:

- read the package through a read-only live view;
- copy or deduplicate it into a managed snapshot;
- expose an overlay filesystem;
- transform code into a separate cache;
- materialize ASAR contents into a content-addressed cache;
- create separate state/profile directories.

## 4.5 Frequent updates are first-class

The architecture MUST assume that some target applications, especially Codex/ChatGPT, may update repeatedly in one day.

Exact build fingerprints MUST NOT imply exact hand-authored adapters. The runtime MUST distinguish:

- durable family adapter logic;
- generated per-build descriptors;
- generated delta overlays;
- per-build certification evidence.

## 4.6 Resource claims require measurements

Weregopher MUST NOT market lower memory usage based solely on a lower working-set number.

Primary resource metrics include aggregate private commit, process count, CPU time, handle count, thread count, renderer count, helper count, startup latency, interaction latency, and steady-state/peak behavior. Shared browser/GPU/network memory MUST be reported separately from app-exclusive memory.

---

# 5. Explicit non-goals

Weregopher is not:

1. a PWA installer;
2. a website wrapper;
3. a multi-service web workspace;
4. a browser profile manager;
5. an application that replaces desktop clients with public web versions;
6. a generic “RAM cleaner” that periodically empties working sets;
7. a DLL-injection system that hooks every `CreateProcess`;
8. a kernel driver;
9. a global process-launch interceptor;
10. a transparent binary compatibility layer for every Electron release and application;
11. an attempt to migrate a live V8/DOM heap into WebView2 or CEF;
12. a mechanism for bypassing vendor authentication, licensing, DRM, code signing, or security controls;
13. a reason to redistribute proprietary application assets;
14. a wrapper around the original vendor Electron executable presented as an optimization;
15. a requirement that all native modules be rewritten before any adapter can work;
16. a single shared JavaScript heap for unrelated applications.

A product may later include an external Electron resource governor, but that is supplementary. The core of this specification is the transformation runtime.

---

# 6. Research conclusions

## 6.1 Electron maps naturally to a compatibility broker

Electron formally separates the main process, renderer processes, preload scripts, utility processes, and IPC. The main process runs in a Node environment and creates `BrowserWindow` instances; each window loads content in a renderer process. Preload scripts run before page content and can expose narrow APIs through `contextBridge`. This separation creates a viable compatibility boundary: the original JavaScript can receive proxy implementations of Electron modules while a native host owns windows, renderers, sessions, and desktop services.[R1]

## 6.2 ASAR must be modeled as a filesystem, not merely unpacked

Electron treats ASAR archives as virtual directories for many Node and Chromium operations. Some APIs require materialization to a real path, including executable and native-module paths. A correct replacement needs an ASAR-aware VFS, overlay resolution, real-path materialization, and path virtualization rather than a one-time extract-and-pray approach.[R2]

## 6.3 Context isolation is a behavioral and security contract

Context isolation uses separate JavaScript contexts for preload logic and page logic and is enabled by default in modern Electron. Weregopher must reproduce enough of the isolation, object-copy/proxy semantics, frame lifecycle, and origin checks for application compatibility and security. A simple global object injection is not sufficient.[R3]

## 6.4 Native modules are a compatibility boundary, not a project-ending impossibility

Electron native modules are frequently built for a particular Electron/Node/V8 ABI and may require rebuilding. Weregopher needs multiple strategies: Rust replacement, Bun/N-API loading, vendor helper process, matching-ABI island, or explicit rejection. The adapter, not the generic runtime, decides the strategy per module and build.[R4]

## 6.5 WebView2 can share browser infrastructure while separating profiles

WebView2 controls can share one user-data folder to optimize resources and use separate profiles under that folder to isolate cookies, permissions, settings, and caches. Multiple application processes may also share a browser process when environment options and the UDF match. This supports both shared-shell and standalone-shell topologies.[R5][R6][R7]

This sharing does not guarantee one renderer process or one JavaScript heap. Site isolation, renderer policy, backend behavior, and application content still determine renderer-process count.

## 6.6 Evergreen and fixed WebView2 both have roles

Evergreen WebView2 provides shared installation and automatic security updates. Fixed Version provides deterministic renderer bits but increases distribution size and reduces sharing. The locked policy—Evergreen for normal use, fixed versions for test matrices or adapter-specific requirements—is consistent with Microsoft’s supported distribution models.[R8]

## 6.7 CEF is the correct compatibility fallback

CEF provides stable embedding APIs and tracks Chromium releases while retaining Chromium’s multi-process architecture. It is appropriate when WebView2 lacks required browser switches, render-process control, extension behavior, codecs, schemes, or precise V8 integration. It is not the default because bundling Chromium weakens the resource-sharing objective.[R9]

## 6.8 QuickJS-NG plus Rust is feasible but not Node-compatible by itself

QuickJS is small and embeddable. `rquickjs` provides async Rust integration, custom allocators, module resolvers/loaders, and Rust/JavaScript conversion. It deliberately does not supply Node or browser APIs. LLRT demonstrates a Rust/QuickJS runtime with partial Node-style modules and is useful source material, while explicitly stating that it is not a drop-in Node replacement.[R10][R11][R12]

This is compatible with Weregopher because compatibility is adapter-scoped rather than universal.

## 6.9 Bun is a useful compatibility shield, not a guarantee

Bun provides runtime plugin hooks such as `onResolve`/`onLoad` and aims for broad Node compatibility. It is suitable as an alternate runtime, bundler/transpiler, and helper runtime. Its Node compatibility remains an implementation to test, not an assumption to trust for every package or native module.[R13][R14]

## 6.10 Existing projects prove parts of the design

- Electrico directly experiments with running Electron-like applications through Rust/WRY and emulated Electron/Node APIs. It validates the concept but is not a production, broad-compatibility runtime.[R15]
- Electrobun combines a Bun main process, native system webviews, typed RPC, and optional CEF. It is a framework for new applications rather than an Electron package compatibility layer, but its process and packaging design are useful prior art.[R16]
- DeskGap combines Node and system webviews with Electron-shaped APIs, but does not promise unmodified Electron compatibility and is primarily historical reference.[R17]
- LLRT demonstrates Rust-backed JavaScript runtime modules and QuickJS integration.[R12]

## 6.11 Codex app-server is a strong durable boundary

OpenAI documents `codex app-server` as a bidirectional JSON-RPC-like protocol over JSONL stdio by default. It requires an `initialize` request followed by `initialized`, and it can generate exact-version TypeScript and JSON Schema artifacts. This is ideal for discovering and supervising the exact app-server bundled with an installed desktop build.[R18]

The Windows desktop documentation currently identifies worktrees, scheduled tasks, Git operations, an in-app browser, file previews, plugins, skills, PowerShell/native Windows sandboxing, and WSL2 as supported workflows. The adapter must preserve those desktop behaviors.[R19][R20][R21][R22]

---

# 7. Product and engineering goals

## 7.1 Primary goals

1. Launch supported installed Electron desktop packages without the vendor’s full Electron desktop process tree.
2. Preserve package behavior through application-specific adapters.
3. Share browser infrastructure where the chosen renderer permits it.
4. Use a smaller main-process runtime where compatible.
5. Preserve proprietary or ABI-bound functionality through narrow, supervised boundaries.
6. Make compatibility evidence reproducible.
7. Handle high-frequency vendor updates through contract verification and generated deltas.
8. Attribute and govern application resources correctly.
9. Provide a maintainable FOSS contribution model.
10. Make Codex capable of implementing and extending the project from this specification.

## 7.2 Secondary goals

- Support both x64 and ARM64 Windows.
- Preserve a cross-platform core boundary where doing so does not compromise Windows implementation quality.
- Allow future macOS/Linux shell and renderer backends.
- Make adapter creation highly automatable.
- Produce diagnostics suitable for upstream application bug reports.
- Allow adapters to choose QuickJS, Bun, or a hybrid.
- Allow shared and standalone shell identity.
- Preserve devtools and traceability for adapter authors.

## 7.3 Quality attributes

The runtime is expected to be:

- deterministic for a given package snapshot, adapter, runtime version, and renderer version;
- fail-closed for unknown privileged behavior;
- explicit about exceptions;
- reversible;
- observable;
- crash-isolated where practical;
- resistant to stale-handle and cross-app routing bugs;
- state-migration-aware;
- compatible with frequent updates;
- suitable for long-running desktop sessions.

---

# 8. Success metrics

## 8.1 Functional success

For a specific certified build and declared feature matrix:

- required launch scenarios pass;
- required windows render and receive input;
- preloads and IPC work;
- native integration tests pass;
- storage and migration tests pass;
- application-specific workflows pass;
- no undeclared feature deficit is known;
- no critical exception exists.

## 8.2 Resource success

Under a defined benchmark workload, compared with the vendor build:

- the vendor’s original Electron main/browser process tree is absent;
- aggregate private commit is lower or the adapter declares `efficiency = neutral/regressed`;
- background CPU is not higher without a declared reason;
- process count and helper count are bounded;
- stale child processes are cleaned up;
- startup and interaction latency remain within declared bounds;
- renderer crashes and worker crashes recover as declared.

## 8.3 Update success

For a vendor update that preserves family contracts:

- discovery completes without human version entry;
- a build descriptor is generated;
- semantic module matching rebinds transforms;
- the app-server or other protocol schema is generated where available;
- mandatory probes pass;
- promotion occurs without a hand-authored build adapter;
- rollback remains possible if state compatibility permits.

## 8.4 Security success

- renderers cannot access unrestricted host APIs;
- adapter capabilities are enforced;
- cross-application handles and IPC are rejected;
- named pipes have explicit per-user ACLs;
- helper process identity is verified;
- adapter signatures are verified outside local developer mode;
- raw traces and secrets are not persisted by default;
- a declared full-host-access adapter is visibly marked.

---

# 9. Compatibility and parity model

## 9.1 Compatibility dimensions

Compatibility is not one boolean. Every build has at least these dimensions:

```rust
struct CompatibilityStatus {
    package: DimensionStatus,
    main_runtime: DimensionStatus,
    renderer: DimensionStatus,
    preload: DimensionStatus,
    electron_api: DimensionStatus,
    node_api: DimensionStatus,
    native_modules: DimensionStatus,
    helpers: DimensionStatus,
    state: DimensionStatus,
    security: DimensionStatus,
    workflows: BTreeMap<FeatureId, FeatureStatus>,
}
```

## 9.2 Certification classes

```rust
enum CertificationClass {
    /// Exact package fingerprint ran the complete configured certification suite.
    ExactCertified,

    /// Unknown exact hash satisfied family contracts and mandatory automated tests.
    ContractVerified,

    /// Core launch and safety probes passed, but the configured full suite did not run.
    Provisional,

    /// A mandatory contract or test failed.
    Blocked,
}
```

## 9.3 Adapter stability

```rust
enum AdapterStatus {
    Experimental,
    Stable,
    Deprecated,
    Revoked,
}
```

`Stable` MAY contain declared exceptions. It MUST NOT contain an undisclosed critical exception.

## 9.4 Exception model

```rust
struct FeatureException {
    id: String,
    surface: String,
    feature: String,
    severity: ExceptionSeverity,
    behavior: String,
    workaround: Option<String>,
    introduced_in: Option<String>,
    tracking_issue: Option<String>,
}

enum ExceptionSeverity {
    Cosmetic,
    Minor,
    Major,
    Critical,
}
```

Critical exceptions block stable promotion when they involve:

- data loss or corruption;
- credentials or secret exposure;
- sandbox or approval-policy weakening;
- incorrect command execution;
- silent permission escalation;
- broken process ownership causing unbounded orphan processes;
- security-boundary misrepresentation;
- irreversible state migration without safeguards.

## 9.5 Efficiency status

Functional compatibility and efficiency are separate:

```rust
enum EfficiencyStatus {
    Improved,
    Neutral,
    Regressed,
    Unknown,
}
```

A stable adapter can be `Regressed`. It cannot claim to solve Electron overhead unless it is `Improved` under a published benchmark.

---

# 10. High-level architecture

```text
                                  ┌──────────────────────────┐
                                  │       weregopher          │
                                  │ CLI / developer commands │
                                  └────────────┬─────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              weregopherd                                        │
│ Per-user supervisor                                                        │
│                                                                             │
│  discovery  catalog  fingerprints  snapshots  adapters  updates             │
│  contracts  certification  jobs  resource accounting  trace coordination    │
└───────────────┬──────────────────────────────┬──────────────────────────────┘
                │                              │
                │                              │
                ▼                              ▼
┌─────────────────────────────┐    ┌──────────────────────────────────────────┐
│ weregopher-shell                │    │ runtime workers                          │
│                             │    │                                          │
│ Win32 windows               │    │ weregopher-worker --engine=quickjs          │
│ taskbar/tray/menu            │◄──►│ bun + Weregopher bootstrap                  │
│ WebView2 / CEF              │    │ optional future Boa worker               │
│ input/accessibility         │    │ application main-process logic           │
│ renderer bridge             │    │ Electron and Node proxy modules          │
└───────────────┬─────────────┘    └───────────────────┬──────────────────────┘
                │                                      │
                ▼                                      ▼
┌─────────────────────────────┐    ┌──────────────────────────────────────────┐
│ browser process groups      │    │ native/helper boundaries                 │
│                             │    │                                          │
│ shared WebView2 runtime     │    │ Rust replacement services                │
│ optional CEF subprocesses   │    │ vendor helper processes                  │
│ specialized vendor surface │    │ N-API hosts                              │
└─────────────────────────────┘    │ matching-ABI islands                     │
                                   │ app-server / MCP / sandbox helpers        │
                                   └──────────────────────────────────────────┘
```

## 10.1 Architectural principles

1. **Package logic is preserved where possible.** Frequent application changes should flow through the vendor’s own JavaScript rather than requiring handwritten host mappings.
2. **Native boundaries are explicit.** Every process, DLL, helper, and capability has an owner and declared purpose.
3. **Opaque application IPC is passed through.** Weregopher interprets only the channels that cross a replaced boundary.
4. **Backends are replaceable.** JavaScript and renderer backends implement stable internal traits.
5. **The shell does not execute application JavaScript.**
6. **The UI thread never synchronously waits on application JavaScript.**
7. **Workers may synchronously call the host through a broker, subject to deadlock rules.**
8. **Unknown builds are analyzed, not guessed.**
9. **State and package rollback are separate concerns.**
10. **Resource attribution distinguishes exclusive and shared infrastructure.**

---

# 11. Process topology and executables

## 11.1 `weregopher.exe`

Purpose:

- human and Codex-facing command line;
- discovery and inspection;
- snapshot management;
- adapter building;
- trace capture;
- certification;
- launch and benchmark commands;
- registry operations.

It MUST be a thin client to shared library code or `weregopherd`, not an independent implementation of core logic.

## 11.2 `weregopherd.exe`

A per-user, unelevated supervisor daemon.

Responsibilities:

- watch installed applications and package updates;
- maintain the local application/build catalog;
- maintain the content-addressed package store;
- resolve and verify adapters;
- spawn shells, workers, and helpers;
- assign Job Objects;
- own process and resource metadata;
- coordinate shared WebView2 UDF access;
- run candidate-build verification;
- retain last-known-good builds;
- collect redacted traces;
- manage adapter registry metadata;
- coordinate crash recovery.

`weregopherd` MUST NOT load third-party adapter DLLs.

## 11.3 `weregopher-shell.exe`

Responsibilities:

- Win32 window creation and lifetime;
- AppUserModelID and taskbar identity;
- tray icons and menus;
- native menus;
- WebView2/CEF/specialized renderer controls;
- DirectComposition where required;
- input, focus, IME, per-monitor DPI;
- accessibility and UI Automation boundaries;
- clipboard and drag/drop;
- file/folder dialogs;
- notifications;
- renderer-origin registration and request handling;
- renderer bridge transport;
- renderer crash detection;
- window-state persistence.

Modes:

```text
shared:
    one shell process owns windows for multiple applications

standalone:
    one shell process owns windows for one application instance
```

Both modes MUST implement the same shell protocol.

## 11.4 `weregopher-worker.exe`

Default QuickJS-NG worker.

Responsibilities:

- execute one application’s main-process JavaScript;
- supply CommonJS/ESM loading;
- supply `electron`, `electron/main`, `electron/common`;
- supply implemented Node built-ins;
- execute adapter modules and transforms;
- run event loop;
- enforce heap, stack, and turn limits;
- expose runtime diagnostics;
- communicate only through authenticated local transports.

Default isolation is one process per app instance.

## 11.5 Bun worker

A supervised `bun.exe` process or Weregopher-distributed Bun runtime with:

- preloaded Weregopher bootstrap;
- runtime plugin/import interception;
- `electron` virtual package;
- synchronous bridge support;
- named-pipe transport;
- capability environment;
- per-app working directory and environment;
- dedicated Job Object.

Bun MUST NOT be shared by unrelated application families in one process by default.

## 11.6 `weregopher-helper-host.exe`

A generic, purpose-scoped helper host.

Examples:

- load a compatible N-API module;
- host one proprietary DLL;
- wrap one ABI-bound `.node` module;
- expose ConPTY;
- expose a database binding;
- expose Windows Credential Manager;
- host a codec or media service.

Each invocation MUST load one declared helper manifest and MUST NOT expose arbitrary DLL loading to application JavaScript.

## 11.7 Optional privileged broker

`weregopher-privileged.exe` MAY be installed for narrowly defined elevated operations.

It MUST:

- expose an allowlisted protocol;
- validate caller SID and signed request intent;
- avoid generic command execution;
- be separately auditable;
- have no renderer connection;
- never accept raw shell command strings from an adapter.

Potential operations include:

- setting up a vendor-compatible sandbox prerequisite;
- applying specific ACL templates;
- registering a system integration requiring elevation;
- launching a documented elevated helper in a constrained mode.

---

# 12. Core domain model

```rust
type AppFamilyId = String;
type AppInstanceId = uuid::Uuid;
type RuntimeId = uuid::Uuid;
type RendererId = u64;
type WindowId = u64;
type ObjectId = u64;
type ProfileId = String;
type AdapterId = String;
type BuildId = String;
type ScenarioId = String;
```

## 12.1 Application family

```rust
struct ApplicationFamily {
    id: AppFamilyId,
    display_name: String,
    publisher_identities: Vec<PublisherIdentity>,
    discovery_rules: Vec<DiscoveryRule>,
    source_availability: SourceAvailability,
    default_adapter: Option<AdapterId>,
}
```

## 12.2 Installed application

```rust
struct InstalledApplication {
    family: AppFamilyId,
    installation_id: String,
    installation_kind: InstallationKind,
    root: PathBuf,
    architecture: Architecture,
    channel: Option<String>,
    package_identity: Option<PackageIdentity>,
    publisher: PublisherIdentity,
    current_build: BuildFingerprint,
}
```

## 12.3 Build descriptor

```rust
struct BuildDescriptor {
    fingerprint: BuildFingerprint,
    package_layout: PackageLayout,
    package_tree: PackageTreeManifest,
    runtimes: EmbeddedRuntimeVersions,

    main_entries: Vec<VirtualPath>,
    preload_entries: Vec<VirtualPath>,
    renderer_entries: Vec<VirtualPath>,

    module_graph: ModuleGraph,
    normalized_ast_index: AstIndex,

    electron_usage: ElectronUsage,
    node_usage: NodeUsage,
    context_bridge_exports: Vec<BridgeExport>,
    ipc_graph: IpcGraph,

    native_modules: Vec<NativeModuleDescriptor>,
    helper_binaries: Vec<HelperBinaryDescriptor>,
    spawn_signatures: Vec<SpawnSignature>,

    protocols: Vec<ExternalProtocolDescriptor>,
    state_contract: StateContract,
}
```

## 12.4 Resolved adapter

```rust
struct ResolvedAdapter {
    family_adapter: AdapterPackage,
    generated_overlay: GeneratedOverlay,
    build_descriptor: BuildDescriptor,
    effective_manifest: EffectiveManifest,
    certification: Option<CertificationRecord>,
}
```

## 12.5 Build lease

```rust
struct BuildLease {
    app: AppFamilyId,
    instance: AppInstanceId,
    fingerprint: BuildFingerprint,
    package_source: BuildSource,
    package_view: Arc<dyn PackageView>,
    adapter: Arc<ResolvedAdapter>,
    state_epoch: StateEpoch,
    created_at: SystemTime,
}
```

A running application MUST retain one immutable logical lease. An update MUST NOT mutate the lease.

---


# 13. Installed-application discovery

The user MUST NOT be required to provide current versions, source availability, package paths, Electron versions, helper names, or native-module inventories. Those are scanner outputs.

## 13.1 Discovery sources

### 13.1.1 MSIX/AppX

Use Windows package APIs to collect:

- package name;
- package family name;
- full package name;
- version;
- architecture;
- publisher/signing identity;
- installation path;
- application IDs;
- AUMIDs;
- protocol registrations;
- file associations;
- startup tasks;
- declared capabilities;
- dependencies and optional packages.

The scanner SHOULD use `PackageManager` and `PackageCatalog.OpenForCurrentUser()` rather than scraping only the WindowsApps directory. Package catalog events SHOULD be used to detect installation, staging, update, status, and removal events.[R23]

### 13.1.2 Squirrel and versioned desktop installations

Inspect:

- `%LOCALAPPDATA%\Programs`;
- `%LOCALAPPDATA%\<VendorOrApp>`;
- `app-*` version directories;
- `Update.exe`;
- `.nupkg` files;
- `packages\RELEASES`;
- uninstall registry entries;
- Start Menu shortcuts;
- pinned taskbar shortcut targets;
- protocol handlers;
- running process image paths.

### 13.1.3 MSI/EXE installers and portable layouts

Inspect:

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`;
- `HKLM` 32-bit and 64-bit uninstall views;
- Windows Installer product records where applicable;
- winget package records as advisory metadata;
- portable directories selected by the user;
- executable version resources;
- Authenticode signer information.

### 13.1.4 Running process discovery

When the application is already running, record:

- image paths;
- parent/child process tree;
- command lines;
- loaded modules where accessible;
- Electron/Chromium process type switches;
- application window ownership;
- AUMID and package identity;
- file handles to `app.asar`, resources, helpers, profiles, and logs.

Running-process discovery is supplemental. The scanner MUST be able to inspect a closed installation.

## 13.2 Electron package classification

Classification SHOULD be scored from multiple signals:

- `resources/app.asar`;
- `resources/app.asar.unpacked`;
- `resources/default_app.asar`;
- Electron/Chromium DLL and resource layout;
- `chrome_100_percent.pak`, `resources.pak`, locale packs, snapshot data;
- executable version metadata;
- package `devDependencies` or build metadata;
- child command lines such as `--type=renderer`, `--type=gpu-process`, or utility-process switches;
- known Electron fuses/integrity metadata;
- imported `electron` modules;
- Electron-specific JavaScript APIs;
- known application-family signatures.

Do not classify solely by executable name.

## 13.3 Source availability catalog

Source availability is maintained metadata, not a launch requirement:

```rust
enum SourceAvailability {
    Full {
        repositories: Vec<RepositoryRef>,
        license: String,
    },
    CoreOnly {
        repositories: Vec<RepositoryRef>,
        proprietary_components: Vec<String>,
    },
    PackageOnly,
    Unknown,
}
```

The catalog is useful for:

- selecting source-port versus package-emulation strategies;
- license compliance;
- oracle instrumentation;
- debugging source maps;
- generating adapter patches;
- tracking upstream changes.

It MUST NOT block package analysis when source is unavailable.

## 13.4 Discovery output

Example:

```json
{
  "family": "openai.chatgpt.windows",
  "installationKind": "msix",
  "packageFamily": "discovered-at-runtime",
  "packageVersion": "discovered-at-runtime",
  "architecture": "x64",
  "publisher": {
    "subject": "discovered-at-runtime",
    "thumbprint": "sha256:..."
  },
  "electron": {
    "detected": true,
    "version": "derived-from-package"
  },
  "package": {
    "appAsar": "resources/app.asar",
    "unpacked": "resources/app.asar.unpacked",
    "main": "derived-from-package-json",
    "preloads": ["derived"],
    "nativeModules": ["derived"],
    "helpers": ["derived"]
  }
}
```

The specification intentionally does not hard-code package-family IDs or helper filenames for proprietary applications. Those are volatile discoveries.

---

# 14. Build fingerprinting

## 14.1 Purpose

Fingerprints provide:

- immutable identity;
- auditability;
- certification lookup;
- cache keys;
- snapshot deduplication;
- update-delta comparison;
- rollback selection;
- protection from applying an incompatible generated overlay.

Fingerprints do **not** require a hand-authored adapter leaf.

## 14.2 Compound fingerprint

```rust
struct BuildFingerprint {
    family: AppFamilyId,
    installation_kind: InstallationKind,
    architecture: Architecture,
    channel: Option<String>,

    package_identity: Option<PackageIdentity>,
    package_version: Option<Version>,
    product_version: Option<Version>,
    internal_version: Option<String>,

    package_tree_merkle: Sha256,
    app_asar_sha256: Option<Sha256>,
    app_asar_unpacked_merkle: Option<Sha256>,
    main_entry_sha256: Option<Sha256>,
    preload_merkle: Option<Sha256>,
    renderer_merkle: Option<Sha256>,
    native_module_merkle: Option<Sha256>,
    helper_binary_merkle: Option<Sha256>,

    signer_thumbprint: Option<Sha256>,
    electron_version: Option<Version>,
    chromium_version: Option<Version>,
    node_version: Option<Version>,
    v8_version: Option<Version>,
}
```

## 14.3 Package-tree Merkle manifest

For each file:

```rust
struct PackageFileRecord {
    normalized_path: String,
    size: u64,
    sha256: Sha256,
    executable: bool,
    kind: PackageFileKind,
    signer: Option<PublisherIdentity>,
}
```

Canonicalization rules:

- use `/` in normalized paths;
- preserve case in records;
- compare paths using Windows case-insensitive semantics where necessary;
- exclude mutable vendor logs and caches from package identity;
- include executable and native resources;
- include symlink/reparse-point semantics;
- reject traversal outside the package root;
- hash metadata and ordered child records into directory nodes.

## 14.4 Runtime version discovery

Possible sources, in descending confidence:

1. executable version metadata or embedded Electron version;
2. package metadata;
3. `process.versions` captured under the vendor oracle;
4. known Electron resource version structures;
5. runtime launch with a harmless version probe in a temporary copy.

The scanner MUST record confidence and provenance:

```rust
struct DerivedValue<T> {
    value: T,
    confidence: Confidence,
    source: EvidenceRef,
}
```

---

# 15. Package views, live mode, and immutable snapshots

```toml
[package]
mode = "auto" # auto | live | snapshot
```

## 15.1 Live mode

Live mode reads vendor package files directly through a read-only package view.

Live mode MAY be used when:

- the exact current fingerprint has been computed;
- the package root is immutable or versioned;
- all transforms are overlay-only;
- the updater installs a new package/version rather than mutating active files;
- the adapter declares live mode safe;
- a build lease can keep the logical package stable for the session.

MSIX and versioned Squirrel directories are likely candidates, subject to actual behavior.

Live mode MUST NOT:

- write into the package root;
- replace ASAR files;
- patch signed binaries;
- depend on a path that the updater can delete mid-session without a fallback;
- apply an adapter after the package fingerprint changes.

## 15.2 Snapshot mode

Snapshot mode creates a content-addressed package representation with an exact manifest-scoped
identity:

```text
store/
├── sha256/
│   └── <fanout>/<content-digest-tail>
└── package-views/
    └── sha256-<package-tree-merkle>/
        ├── tree/
        │   ├── app.asar
        │   ├── app.asar.unpacked/
        │   ├── resources/
        │   ├── helpers/
        │   └── native/
        └── evidence/              # future metadata/evidence namespace
```

Snapshot implementation SHOULD:

- use block/file deduplication where safe;
- avoid hard links to vendor-controlled mutable files;
- verify content after copy;
- preserve executable signatures;
- preserve timestamps only as evidence, not identity;
- store source metadata separately from package bytes;
- support garbage collection based on leases, pins, and retention policy.

The physical `tree/` directory is not itself a same-user sandbox. A snapshot lease MUST retain and
reverify exact listed file bytes and identities and MAY provide diagnostic point-in-time complete
membership checks. Membership success does not establish a closed namespace at method return: a
same-user process can inject a child after enumeration and before the check returns. The runtime MUST
NOT infer execution authority from a digest-named directory, a successful membership check, or an
unrestricted physical-root path. Execution-qualified consumers MUST use manifest-scoped VFS operations
or exact allowlisted retained handles and MUST keep the relevant lease alive for the complete operation.
Unrestricted same-user processes remain outside the initial snapshot threat boundary unless an
independently tested OS sandbox says otherwise.

## 15.3 Auto mode

Selection algorithm:

```text
if adapter forbids live:
    snapshot
else if adapter forbids snapshot:
    live or reject
else if package is immutable/versioned
     and overlay-only
     and live lease is safe
     and exact fingerprint remains available:
    live
else:
    snapshot
```

User overrides MAY be provided, but an adapter MAY reject an unsafe override.

## 15.4 Build leases

A running process MUST never “float” to a new build.

```text
session starts on build N
vendor installs N+1
session remains logically attached to N
candidate N+1 is scanned separately
new session chooses N+1 only after policy permits
```

When a live package can be deleted by an updater, `weregopherd` SHOULD proactively create a snapshot before or during candidate staging.

## 15.5 Retention

Default:

```toml
[store.retention]
last_known_good = 3
last_exact_certified = 2
failed_candidates = 2
pinned_never_delete = true
max_total_gib = 50
```

Deletion MUST be lease-aware and state-rollback-aware.

---

# 16. ASAR-aware virtual filesystem

## 16.1 Layer model

```text
highest priority
    adapter generated overlay
    adapter static overlay
    app.asar.unpacked
    app.asar
    vendor loose package files
lowest priority
```

Writable state is not part of this lookup unless explicitly addressed through a state path.

## 16.2 `PackageView` interface

```rust
trait PackageView: Send + Sync {
    fn metadata(&self) -> &PackageMetadata;
    fn stat(&self, path: &VirtualPath) -> Result<VirtualStat>;
    fn read_dir(&self, path: &VirtualPath) -> Result<Vec<VirtualDirEntry>>;
    fn read(&self, path: &VirtualPath) -> Result<Bytes>;
    fn open(&self, path: &VirtualPath) -> Result<Box<dyn VirtualFile>>;
    fn resolve(&self, from: &VirtualPath, request: &str) -> Result<VirtualPath>;
    fn materialize(
        &self,
        path: &VirtualPath,
        policy: MaterializationPolicy,
    ) -> Result<MaterializedPath>;
}
```

## 16.3 Required semantics

The VFS MUST support enough semantics for:

- `fs.readFile` and promises variants;
- `fs.readdir`;
- `fs.stat` and `lstat`;
- `fs.access`;
- `fs.open` for readable virtual files;
- CommonJS and ESM resolution;
- JSON loading;
- source maps;
- WebAssembly loading;
- package metadata;
- renderer resource requests;
- preload loading;
- helper/native materialization;
- `original-fs` behavior where the adapter requires raw ASAR access;
- `process.noAsar`.

The VFS MUST model read-only ASAR behavior and MUST NOT pretend writes into an archive succeeded.

## 16.4 Materialization

Materialization is required when a real OS path is needed:

- `LoadLibrary`;
- native `.node` loading;
- `CreateProcess`;
- APIs receiving a file path rather than bytes;
- memory-mapped databases;
- vendor libraries that call Win32 file APIs directly;
- external tools.

Materialization cache:

```text
materialized/
└── <package-tree-merkle>/
    └── <file-sha256>/
        └── original-filename
```

The cache MUST verify content hashes and SHOULD use restrictive ACLs.

## 16.5 Path virtualization

The runtime MUST virtualize:

- `__filename`;
- `__dirname`;
- `process.cwd()`;
- `process.execPath`;
- `process.resourcesPath`;
- `app.getAppPath()`;
- `app.getPath(...)`;
- package root;
- preload paths;
- helper paths.

The application should see stable virtual paths even when the backing data is in ASAR or a content-addressed store.

## 16.6 Renderer origin

Package renderer assets SHOULD be exposed through a private secure-context origin such as:

```text
https://<app-instance>.<family>.weregopher.invalid/
```

The backend maps requests to the VFS. The origin MUST:

- be unique enough to avoid cross-app storage collisions;
- use an origin policy compatible with the application;
- reject traversal;
- set deterministic MIME types;
- preserve range requests where needed;
- support source maps;
- define cache policy;
- apply CSP/header transforms only when declared by the adapter.

Adapters that require `file:` behavior MAY select it, but secure private origins are preferred.

---

# 17. Adapter architecture

## 17.1 Hierarchy

```text
family adapter
    ├── shared contracts and code
    ├── channel/platform overlays
    └── generated build overlay
```

A family adapter is durable. A generated overlay is replaceable evidence for one build.

## 17.2 Family adapter contents

A family adapter MAY include:

- discovery rules;
- accepted publishers/signers;
- package-layout matchers;
- renderer/runtime preferences;
- API contracts;
- module aliases;
- semantic AST transforms;
- native module strategies;
- helper process definitions;
- capability declarations;
- state classifications and migrations;
- trace normalizers;
- feature probes;
- parity scenarios;
- declared exceptions;
- update policy defaults.

## 17.3 Execution modes

```rust
enum MainExecutionMode {
    /// Execute the packaged main process under QuickJS or Bun.
    Emulate,

    /// Replace main orchestration in Rust while preserving package components.
    Replace,

    /// Mix preserved main logic and replaced native/protocol boundaries.
    Hybrid,

    /// Build a source-available app against the compatibility SDK.
    SourcePort,
}
```

The OpenAI adapter defaults to `Hybrid`.

## 17.4 Semantic transforms

Transforms MUST target syntax/semantics rather than byte offsets.

Preferred transform forms:

```typescript
replaceImport({
  specifier: "node-pty",
  with: "compat:openai/conpty",
});
```

```typescript
matchModule({
  imports: ["electron", "node:child_process"],
  strings: ["some-stable-marker"],
  exports: ["bootstrap"],
});
```

```typescript
replaceCall({
  callee: "autoUpdater.checkForUpdates",
  with: "compatUpdater.checkForUpdates",
});
```

Forbidden as the only matching mechanism:

```text
generated filename + byte offset
```

A generated filename or source-map module ID MAY be one signal.

## 17.5 Transform engine

The transform subsystem MUST be behind an internal interface:

```rust
trait SourceTransform {
    fn analyze(&self, source: SourceUnit, context: TransformContext)
        -> Result<Analysis>;
    fn transform(&self, source: SourceUnit, context: TransformContext)
        -> Result<TransformedSource>;
}
```

An implementation MAY use SWC, Oxc, or another parser, but dependency choice is not part of the compatibility contract. Source maps and an audit log are REQUIRED.

## 17.6 Adapter hooks

Hooks MAY run as WebAssembly components with capability-limited host calls.

Hook points include:

- package discovered;
- build descriptor generated;
- delta overlay generated;
- pre-launch;
- application lifecycle;
- window creation;
- renderer navigation;
- permission request;
- process launch;
- IPC observation;
- trace normalization;
- candidate verification;
- state migration.

A hook MUST NOT receive unrestricted Win32 access.

## 17.7 Module aliases

```toml
[module_loader.aliases]
"electron" = "compat:electron"
"electron/main" = "compat:electron-main"
"electron/renderer" = "compat:electron-renderer"
"node-pty" = "compat:openai/conpty"
"keytar" = "compat:windows-credentials"
```

Aliases MAY be conditional by runtime, architecture, build contract, or feature probe.

---

# 18. Adapter package format and trust

## 18.1 Archive

Extension: `.wga` (Weregopher Adapter Archive).

```text
adapter.wga
├── manifest.toml
├── manifest.cbor
├── fingerprints.cbor
├── contracts/
├── overlay/
├── modules/
│   ├── main/
│   ├── preload/
│   └── renderer/
├── transforms/
├── hooks/
├── native-manifests/
├── schemas/
├── tests/
├── oracle/
├── licenses/
└── signature.ed25519
```

The canonical signed representation is `manifest.cbor` plus a content Merkle root.

## 18.2 Trust modes

```rust
enum AdapterTrustMode {
    RegistrySigned,
    LocallyTrusted,
    DeveloperUnsigned,
    Revoked,
}
```

### Registry-signed mode

- verify registry signing key;
- verify adapter signature;
- verify content Merkle root;
- check revocation metadata;
- enforce declared capabilities;
- prohibit undeclared native binaries.

### Local developer mode

- allow unsigned adapters;
- display persistent “developer adapter” state;
- keep full traceability;
- do not auto-publish;
- do not relax process/IPC security automatically.

## 18.3 Native content

A third-party adapter MUST NOT load arbitrary native code into `weregopherd` or `weregopher-shell`.

Native content must execute as:

- a signed Weregopher-supplied helper;
- a separately spawned adapter helper with declared hash;
- a vendor helper already present in the package;
- an ABI island;
- a specialized renderer component.

## 18.4 Revocation

Registry metadata MAY revoke:

- an adapter version;
- a build certification;
- a signing key;
- a native helper hash;
- a generated overlay.

Revocation reasons MUST be visible. Security revocation SHOULD block launch unless the user explicitly uses local developer mode.

---

# 19. High-frequency vendor update compatibility

This section is critical for Codex.

## 19.1 Four-artifact model

```text
1. Family adapter
   manually maintained, durable

2. Build descriptor
   generated from every discovered build

3. Delta overlay
   generated by comparing the build with prior compatible builds

4. Certification record
   generated evidence for an exact fingerprint
```

Exact hash identity and human adapter maintenance are deliberately decoupled.

## 19.2 Update policies

```rust
enum UpdatePolicy {
    FollowVerified,
    FollowCurrent,
    Pinned,
}
```

### `FollowVerified`

Default.

Use the newest candidate that meets the configured minimum certification class.

```text
vendor update event
→ discover candidate
→ verify publisher/package identity
→ lease or snapshot candidate
→ generate build descriptor
→ generate protocol schemas
→ semantic delta analysis
→ rebind transforms
→ runtime/renderer/native probes
→ state-clone smoke tests
→ configured parity tests
→ promote or retain last-known-good
```

### `FollowCurrent`

Use the currently installed vendor package after mandatory safety probes.

Required before launch:

- package identity/signature checks;
- package layout resolution;
- main/preload/renderer entry resolution;
- unsupported Electron/Node API inventory;
- native dependency classification;
- helper classification;
- runtime bootstrap probe;
- renderer/preload bridge probe;
- state-safety probe where mutation is possible.

A failure before state mutation MAY fall back automatically.

### `Pinned`

Use a selected package snapshot and adapter resolution.

Warnings:

- remote services may stop accepting old clients;
- credentials may expire;
- state may migrate externally;
- security updates are not inherited.

## 19.3 Build descriptor generation

The analyzer MUST extract:

- module graph;
- normalized AST signatures;
- Electron imports and method calls;
- Node built-ins and call sites;
- native module loads;
- helper spawn sites;
- IPC registration and send sites;
- context bridge exports;
- protocol registrations;
- state path usage;
- updater behavior;
- renderer entry points;
- preload assignments;
- feature flags where discoverable.

### 19.3.1 Authority-nonexpanding execution-artifact rebinding

The signed family adapter owns the finite set of execution targets that one adapter may nominate.
A generated build overlay MUST NOT become a second authority source. Static execution authority MUST
bind the exact adapter artifact and a bounded map of durable target identifiers to closed process
roles, closed managed artifact-source classes, and complete target-contract digests. A generated
overlay MAY select a subset of those targets, but it MUST NOT add a target, change its role or source
class, or substitute its target contract.

Generated execution evidence MUST bind the exact source fingerprint, package-tree Merkle identity,
build descriptor, execution-environment descriptor, adapter identity, adapter content, and static
execution-authority document. Each selected target MUST bind the containing package-tree or managed
manifest, exact executable bytes, and exact external resolution evidence. For a package-snapshot
target, the containing-artifact identity MUST equal the overlay's package-tree identity.

Parsing or structurally validating these documents does not authenticate them and MUST NOT authorize
execution or process launch. Before launch, a separate live authorization capability MUST retrieve,
hash, authenticate, and revocation-check the adapter authority and target contracts; validate the
resolution evidence; verify exact retained package or managed-artifact capabilities; and resolve
command-line, environment, capability, compatibility, state, and user-policy requirements. Physical
package-view roots are not closed namespaces: execution-qualified package access MUST use
manifest-scoped, identity-verified file capabilities rather than unrestricted traversal.

Format-version-2 execution target contracts make the static artifact locator, fixed arguments,
empty-environment/no-inherited-handle/no-console launch semantics, working-directory rule, required
security posture, loader dependency policy, state mode, Job/process resource ceilings, and exact
static capability/state-policy requirements explicit and bounded. Current compatibility analysis
and user policy/consent remain
separate generation-tracked live-policy inputs; changing either MUST NOT require a new static target
signature. Separate generated resolution evidence binds the chosen locator to target-contract,
artifact-source, executable, artifact-trust, and provenance identities. A managed locator digest MUST
equal the role-named executable digest. Hostile readers MUST enforce the contract's outer document
byte ceiling before Serde allocation, and package locators MUST reject Windows-ambiguous names.
Parsing and content-addressing either document remains non-authorizing. See
[ADR-0023](../adr/0023-bounded-execution-target-and-resolution-contracts.md).

The initial Windows capability bridge binds a locked executable path back to the full-width file
identity already retained by its package-snapshot or managed-manifest lease. Package resolution
performs the manifest allowlist lookup before joining the physical root, and each executable
capability borrows the complete source lease. These capabilities are integrity prerequisites only:
they do not authenticate authority, authorize execution or launch, freeze later DLL resolution, or
close an ordinary directory namespace. See
[ADR-0022](../adr/0022-identity-bound-retained-executable-capabilities.md).

The initial Windows live authorizer uses an explicitly trusted local policy store for one exact
target. Its role-named pins cover authority, source/build/environment context, target and resolution
documents, trust and provenance evidence, resolved compatibility/capability/state/user policy,
security posture, state mode, and policy revision. Evidence bytes MUST be hashed under nonzero
per-document and aggregate limits. Callers MAY tighten those limits but MUST NOT raise them above
the implementation ceilings of 1 MiB per evidence document and 4 MiB per authorization decision.
Compatibility MUST be complete even when an incomplete analysis is itself exactly pinned. Package
and managed executables MUST match both the declared locator and the retained source/executable
identities. The initial primitive MUST accept only
`vendor_default_ambient` loader dependencies and `vendor_default` state. It MUST reject
`manifest_closed`, `disposable`, and `production` requirements until it retains independently
enforced dependency and state namespace capabilities. Before issuance, authorization MUST reject
unsupported posture or launch semantics, validate exact Job-limit representability, run the sole
Windows quoting implementation over the exact path and arguments, enforce the complete
`CreateProcessW` ceiling, bind the prepared plan to the retained path and full-width file identity,
and revalidate the retained view.
Policy replacement or revocation MUST monotonically invalidate outstanding values.

The resulting authorization capability MUST be opaque, non-cloneable, non-serializable, retain the
exact executable, its complete launch policy, and its opaque prevalidated launch plan, and bind the
issuing policy generation. Local and developer trust are the only recognized initial local-policy
modes; developer policy MUST require disposable state and therefore cannot produce an authorization
through the initial vendor-default-state primitive.
Registry and forensic modes MUST fail closed until their independent authentication and approval
engines exist. Issuance is still not launch. The Windows one-shot consumer MUST hold the issuing
policy read lock, repeat retained-view validation, create the kill-on-close Job, recheck the prepared
plan's retained path and file identity, create the exact retained executable suspended, assign and
verify Job membership, and only then resume the primary thread. It MUST consume the authorization by
value, retain the complete containing-artifact lease in the returned process-tree owner, and fail
before resume on every policy, posture, view, containment, creation, assignment, or verification
error. The initial consumer MUST reject broker-mediated and OS-contained targets because its Job
Object is not an enforcing security boundary. Exact executable identity under
`vendor_default_ambient` MUST NOT be described as exact dependency-closure identity. See
[ADR-0024](../adr/0024-revocation-current-local-live-execution-authorization.md).

The format-version-2 correction and prepared-plan boundary are specified by
[ADR-0026](../adr/0026-execution-contract-v2-and-pre-authorized-launch-plans.md).

The returned low-level Job owner MUST preserve the role-distinct authorization-context digest,
target identity, exact Job limits, and issuing policy generation. A bounded blocking supervisor MAY
consume that owner. Such a supervisor MUST use a policy interval from one millisecond through 60 seconds,
MUST use a nonzero runtime no greater than 24 hours, MUST wait for no longer than the smaller of the
poll interval and remaining runtime, and MUST terminate the complete Job after policy invalidation
or runtime expiry. Forced termination MUST be followed by bounded primary-process exit
confirmation. A terminal report MUST preserve the exact target and authorization-context identities
and MUST NOT become serialized authority or certification evidence.

This bounded lifecycle owner is not yet an `AppInstanceId`, `RuntimeId`, workflow, user-activation,
or state-lease owner and MUST NOT be represented as a complete production application supervisor.
Higher-level orchestration MUST bind those identities and state capability before permitting
corresponding privileged effects. Retained Windows directory handles still do not seal child
namespaces, and launch/supervision ordering MUST NOT be described as an OS sandbox or persistent
package-tree immutability. See
[ADR-0025](../adr/0025-atomic-authorization-consumption-and-job-owned-launch.md) and
[ADR-0027](../adr/0027-bounded-blocking-execution-supervision.md).

Execution authorization, Job Object ownership, suspended process creation, process resume, runtime
supervision, security posture, efficiency, and certification remain distinct decisions and evidence
boundaries. The authority-nonexpansion base is specified by
[ADR-0021](../adr/0021-authority-nonexpanding-execution-artifact-rebinding.md), and the canonical
format-v2 correction by
[ADR-0026](../adr/0026-execution-contract-v2-and-pre-authorized-launch-plans.md).

## 19.4 Semantic module matching

Raw filenames are weak signals because bundlers rename chunks.

For each module, compute a signature from:

- normalized AST shape;
- import/export edges;
- string-literal multiset;
- API call multiset;
- stable property names;
- control-flow sketch;
- source-map original path when available;
- dependency neighborhood;
- function arity/signatures;
- constant hashes;
- IPC channel strings;
- helper executable strings.

Candidate match score:

```text
score =
    0.30 * AST similarity
  + 0.15 * dependency-neighborhood similarity
  + 0.15 * import/export similarity
  + 0.15 * string-literal similarity
  + 0.10 * API-call similarity
  + 0.10 * source-map identity
  + 0.05 * size/control-flow similarity
```

Weights are implementation defaults, not compatibility guarantees.

The matcher SHOULD emit:

- best match;
- alternative matches;
- confidence;
- changed regions;
- transform rebind status;
- unresolved ambiguity.

## 19.5 Delta classification

```rust
enum DeltaClass {
    Identical,
    RenamedOrMoved,
    SemanticallyCompatibleChange,
    NewCapability,
    RemovedCapability,
    BreakingContract,
    Unknown,
}
```

Example report:

```text
Modules:
  unchanged:              1842
  moved/renamed:           119
  changed-compatible:       37
  new:                      12
  removed:                   4

New Electron usage:
  webContents.setWindowOpenHandler

New Node usage:
  fs.promises.cp

New native modules:
  none

Transforms rebound:
  18 / 18

Runtime probe:
  QuickJS failed on node:module behavior
  Bun passed

Candidate class:
  ContractVerified
```

## 19.6 Unknown APIs

Unknown Electron or Node calls MUST be trapped with:

- module;
- property;
- argument shape;
- call stack;
- source location;
- runtime and build identity;
- whether the call is sync/async;
- whether a safe no-op exists.

The default is fail with an explicit compatibility error. An adapter MAY declare a safe passthrough, no-op, or fallback.

## 19.7 Promotion

A candidate MUST be promoted atomically with:

- resolved adapter hash;
- build descriptor hash;
- generated overlay hash;
- certification class;
- state epoch;
- renderer/runtime selection;
- declared exceptions.

## 19.8 State-aware rollback

Package rollback is allowed only if state remains compatible or a state checkpoint exists. See Section 31.

---


---

# 20. JavaScript runtime abstraction

The runtime abstraction exists to separate application semantics from a particular JavaScript engine or process model. It is not intended to force QuickJS-NG and Bun into a false lowest-common-denominator API. The abstraction defines the lifecycle, module-loading, host-call, event-loop, interruption, diagnostics, and value-transfer contracts that every backend must satisfy. Backend-specific features remain discoverable through capability flags.

## 20.1 Runtime roles

A JavaScript backend MAY serve one or more roles:

```rust
enum RuntimeRole {
    MainProcess,
    UtilityProcess,
    AdapterService,
    BuildTransform,
    PreloadCompile,
    TestOracle,
}
```

The most important role is `MainProcess`: execute the package’s original or transformed Electron main-process JavaScript while substituting Weregopher’s `electron` module and selected Node implementations.

A renderer page does not normally use this abstraction. Renderer JavaScript executes inside the selected renderer backend. Preload source may be transformed or compiled through the runtime toolchain, but its final execution environment is the renderer’s isolated world unless an adapter explicitly delegates part of the preload to a worker.

## 20.2 Runtime backend interface

```rust
pub trait JsRuntimeBackend: Send {
    fn backend_id(&self) -> RuntimeBackendId;
    fn capabilities(&self) -> RuntimeCapabilities;

    fn initialize(
        &mut self,
        config: RuntimeConfig,
        package: Arc<dyn PackageView>,
        host: Arc<dyn RuntimeHost>,
    ) -> Result<(), RuntimeError>;

    fn load_main(
        &mut self,
        entry: &VirtualPath,
        argv: &[OsString],
    ) -> Result<MainModuleId, RuntimeError>;

    fn resolve_module(
        &mut self,
        request: ModuleRequest,
    ) -> Result<ResolvedModule, RuntimeError>;

    fn dispatch_host_event(
        &mut self,
        event: HostEvent,
    ) -> Result<(), RuntimeError>;

    fn invoke_export(
        &mut self,
        module: ModuleId,
        export: &str,
        arguments: Vec<WireValue>,
    ) -> Result<PendingCall, RuntimeError>;

    fn pump(
        &mut self,
        budget: RuntimeBudget,
    ) -> Result<PumpOutcome, RuntimeError>;

    fn request_interrupt(&self, reason: InterruptReason);
    fn request_gc(&mut self) -> Result<(), RuntimeError>;
    fn diagnostics(&self) -> RuntimeDiagnostics;
    fn snapshot_debug_state(&mut self) -> Result<RuntimeDebugSnapshot, RuntimeError>;
    fn shutdown(&mut self, mode: ShutdownMode) -> Result<(), RuntimeError>;
}
```

The backend MUST support cancellation and interruption without relying on application cooperation. A runtime that is stuck in JavaScript must be interruptible or killable by the supervisor. The process-isolated default permits termination as the final boundary.

## 20.3 Capability negotiation

```rust
pub struct RuntimeCapabilities {
    pub commonjs: SupportLevel,
    pub esm: SupportLevel,
    pub dynamic_import: SupportLevel,
    pub top_level_await: SupportLevel,
    pub import_maps: SupportLevel,
    pub source_maps: SupportLevel,
    pub wasm: SupportLevel,
    pub node_api: SupportLevel,
    pub native_addons: SupportLevel,
    pub worker_threads: SupportLevel,
    pub inspector: SupportLevel,
    pub synchronous_host_calls: bool,
    pub heap_limit: bool,
    pub instruction_interrupt: bool,
    pub custom_allocator: bool,
    pub structured_clone: SupportLevel,
}

pub enum SupportLevel {
    Native,
    Emulated,
    AdapterProvided,
    Partial,
    Unsupported,
}
```

The adapter compiler uses these capabilities during candidate-build evaluation. A build requiring an unsupported capability may:

1. receive a transform that removes the requirement;
2. receive an adapter module implementing it;
3. be routed to Bun;
4. route one dependency to a Bun helper;
5. route a native dependency to a helper or ABI island;
6. select another runtime backend;
7. fail the build contract.

## 20.4 Runtime configuration

```rust
pub struct RuntimeConfig {
    pub app_id: AppId,
    pub build: BuildFingerprint,
    pub role: RuntimeRole,
    pub isolation: RuntimeIsolation,
    pub module_policy: ModulePolicy,
    pub capability_token: CapabilityToken,
    pub environment: EnvironmentPolicy,
    pub limits: RuntimeLimits,
    pub diagnostics: DiagnosticsPolicy,
    pub compatibility_identity: CompatibilityIdentity,
}

pub struct RuntimeLimits {
    pub max_heap_bytes: Option<u64>,
    pub max_stack_bytes: Option<u64>,
    pub max_single_turn: Duration,
    pub max_pending_async_ops: u32,
    pub max_open_handles: u32,
    pub max_module_count: u32,
    pub max_source_bytes: u64,
    pub max_wire_message_bytes: u32,
}
```

Limits are adapter defaults and user policy inputs. They are not hard-coded globally. A code editor, chat client, and media application have materially different requirements.

## 20.5 Runtime host interface

The backend talks to the rest of Weregopher through a capability-filtered host interface:

```rust
pub trait RuntimeHost: Send + Sync {
    fn electron_call(&self, call: ElectronCall) -> HostCallFuture;
    fn node_call(&self, call: NodeHostCall) -> HostCallFuture;
    fn open_stream(&self, request: StreamRequest) -> Result<StreamHandle, HostError>;
    fn spawn(&self, request: SpawnRequest) -> Result<SpawnHandle, HostError>;
    fn resolve_package_path(&self, path: &VirtualPath) -> Result<ResolvedPath, HostError>;
    fn emit_trace(&self, event: TraceEvent);
    fn request_capability(&self, request: CapabilityRequest) -> CapabilityDecisionFuture;
}
```

The runtime never receives a raw reference to the shell, daemon, Win32 API, or unrestricted filesystem. All operations cross a typed boundary that can be audited, denied, traced, and attributed to an application.

## 20.6 Backend selection

Backend selection is performed per build and MAY be performed per subsystem:

```toml
[runtime]
selection = "probe"
preference = ["quickjs", "bun"]

[[runtime.services]]
id = "extension-host"
engine = "bun"
entry = "compat-services/extension-host.ts"

[[runtime.services]]
id = "simple-policy-engine"
engine = "quickjs"
entry = "compat-services/policy.mjs"
```

The selector evaluates:

- syntax compatibility;
- module-resolution requirements;
- Node built-ins used;
- native module requirements;
- use of process-global state;
- worker-thread behavior;
- inspector/debugging requirements;
- startup and smoke-test results;
- resource measurements;
- adapter-declared preference.

The selection result is stored in the build certification record. It is not rediscovered on every launch unless the environment changes.

## 20.7 Isolation modes

```rust
pub enum RuntimeIsolation {
    Process,
    InProcessThread,
}
```

### Process isolation

Default. Each application receives a `weregopher-worker.exe` or Bun worker process.

Benefits:

- crash containment;
- independent address-space and heap limits;
- reliable cleanup;
- simple Job Object ownership;
- application-specific mitigations;
- easier diagnostics and dumps;
- no cross-app native global state.

Costs:

- per-process baseline;
- IPC overhead;
- more process orchestration.

### In-process thread isolation

Optional, intended for controlled adapters whose code and dependency graph are well understood.

Benefits:

- lower process baseline;
- cheaper calls into the broker;
- potentially lower startup cost.

Costs:

- engine or native crash can terminate the shell/host;
- harder watchdog semantics;
- shared allocator pressure;
- more difficult unload correctness;
- greater cross-app denial-of-service risk.

In-process isolation MUST NOT be enabled for untrusted third-party adapters by default.

## 20.8 Runtime lifecycle

```text
Discovered
  → Prepared
  → Starting
  → MainLoaded
  → ApplicationReady
  → Running
  → Quiescing
  → Stopped
```

Failure states:

```text
StartFailed
ContractViolation
Hung
Crashed
KilledByPolicy
StateMigrationFailed
```

Each transition is emitted as a trace event and recorded in the application session log. The host must distinguish an application-requested exit from a crash, an adapter-requested restart, and policy termination.

## 20.9 Error model

```rust
pub enum RuntimeErrorKind {
    Syntax,
    ModuleResolution,
    UnsupportedNodeApi,
    UnsupportedElectronApi,
    CapabilityDenied,
    NativeModule,
    HostProtocol,
    Serialization,
    Timeout,
    HeapLimit,
    StackLimit,
    Interrupted,
    ProcessExited,
    Internal,
}

pub struct RuntimeError {
    pub kind: RuntimeErrorKind,
    pub message: String,
    pub stack: Option<String>,
    pub module: Option<String>,
    pub operation: Option<String>,
    pub source_location: Option<SourceLocation>,
    pub causal_chain: Vec<ErrorCause>,
    pub adapter_hint: Option<AdapterHint>,
}
```

Errors surfaced to application JavaScript SHOULD mimic Node/Electron error shape when compatibility requires it. Internal errors MUST retain machine-readable categories for diagnosis.

---

# 21. QuickJS-NG runtime

QuickJS-NG is the preferred optimized main-process engine. It is embedded in `weregopher-worker.exe` through a Rust binding layer. `rquickjs` is the initial binding candidate because it exposes runtime/context management, custom module resolvers/loaders, async integration, conversion traits, and allocator hooks. QuickJS-NG remains replaceable behind the runtime abstraction.[R10][R11]

QuickJS does not supply Node APIs, Chromium APIs, or Electron semantics. Weregopher supplies those explicitly.

## 21.1 Worker structure

```text
weregopher-worker.exe
├── bootstrap and authenticated pipe client
├── QuickJS-NG runtime
├── main application context
├── optional adapter contexts
├── module resolver and loader
├── Node compatibility modules
├── Electron proxy module
├── event-loop scheduler
├── async operation registry
├── handle table
├── source-map registry
├── trace client
└── watchdog/interruption endpoint
```

One worker MAY host multiple JavaScript contexts for one application, but MUST NOT host unrelated applications by default.

## 21.2 Memory ownership

QuickJS uses reference counting plus cycle removal. Weregopher MUST expose and record:

- runtime heap bytes;
- atom table size;
- object count where available;
- module count;
- pending Promise job count;
- native wrapper count;
- remote handle count;
- peak heap;
- explicit GC duration;
- allocation failures.

A custom allocator SHOULD tag allocations to an application and integrate with the runtime’s heap limit. The allocator MUST fail predictably rather than allowing integer overflow or unbounded growth.

The resource governor MAY request collection when:

- the runtime becomes idle after a large operation;
- private commit crosses an adapter threshold;
- a benchmark asks for a normalized post-GC measurement;
- an application-specific adapter hook declares a safe collection point.

It MUST NOT continuously force GC merely to make memory graphs look lower.

## 21.3 Interrupt handler

The supervisor sets an atomic interruption flag. QuickJS’s interrupt hook checks it at engine-defined safe points.

```rust
pub enum InterruptReason {
    TurnTimeout,
    ApplicationShutdown,
    UserCancel,
    HeapPressure,
    ContractProbeTimeout,
    SupervisorTermination,
}
```

A timeout first produces a JavaScript-visible interruption where safe. If the worker does not return to the event loop within the termination grace window, the supervisor terminates the process.

## 21.4 Context topology

Recommended contexts:

```text
Runtime
├── main realm
│   ├── global process
│   ├── CommonJS loader
│   ├── ESM loader
│   └── electron main shim
├── adapter realm (optional)
│   └── trusted adapter hooks
└── diagnostic realm (optional, development mode)
```

Adapter code SHOULD run in a separate context when it can be given a narrower host interface. App transforms and replacement modules loaded as application dependencies run in the main realm unless isolation would break object identity or Node semantics.

## 21.5 Module loader

The loader MUST implement the package-used subset of Node resolution with explicit compatibility modes.

Required behavior includes:

- CommonJS `require`;
- CommonJS wrapper variables;
- ESM static imports;
- `dynamic import()`;
- `package.json` `main`;
- `package.json` `exports` and condition selection;
- `package.json` `imports` where used;
- `.js`, `.cjs`, `.mjs`, `.json`, and `.wasm`;
- extension probing under the selected compatibility policy;
- `node_modules` traversal over the virtual package tree;
- symlink and realpath policy;
- cyclic dependency behavior;
- `require.cache`;
- adapter module aliases;
- virtual built-in modules;
- source maps;
- ASAR paths;
- materialized native/helper paths where permitted.

```rust
pub trait ModuleResolver {
    fn resolve(
        &self,
        specifier: &str,
        referrer: &ModuleIdentity,
        kind: ImportKind,
        conditions: &[String],
    ) -> Result<ModuleResolution, ModuleError>;
}
```

Resolution order:

```text
1. adapter exact alias
2. Weregopher virtual built-in (`compat:*`, `node:*`, `electron*`)
3. adapter overlay package
4. package ASAR/unpacked tree
5. explicitly allowed external package roots
6. rejection
```

The loader MUST NOT search arbitrary user or system directories unless the adapter grants that behavior.

## 21.6 CommonJS implementation

A CommonJS module is compiled as the semantic equivalent of:

```javascript
(function (exports, require, module, __filename, __dirname) {
  // transformed module source
});
```

The implementation must preserve:

- partially initialized exports during cycles;
- `module.exports` reassignment;
- `exports` alias behavior;
- parent/children metadata if the application observes it;
- cache insertion before evaluation;
- exception removal policy consistent with the configured Node compatibility target;
- JSON module caching;
- adapter-provided `require.resolve` behavior.

`require.extensions` MAY initially be adapter-provided rather than globally implemented. Dynamic hooks must be treated as privileged because they can intercept every module load.

## 21.7 ESM implementation

ESM loading must support:

- URL-like canonical module identities;
- import assertions/attributes used by target packages;
- top-level await where the engine supports it;
- CommonJS-to-ESM interop policy;
- ESM-to-CommonJS loading restrictions;
- live bindings;
- cyclic module graphs;
- dynamic import Promise behavior;
- package type detection.

The adapter compiler MAY bundle difficult module graphs into a simpler target, but source maps and module identities must remain traceable.

## 21.8 Syntax lowering

QuickJS-NG may lag current V8 syntax or semantics used by a newly bundled desktop app. The build system therefore supports deterministic syntax lowering:

```toml
[build.javascript]
source = "vendor"
target = "quickjs-ng-current"
transpiler = "bun"
minify = false
preserve_names = true
source_maps = "external"
```

The transform pipeline must not blindly rebundle code whose behavior depends on dynamic `require`, exact chunk paths, `import.meta.url`, source-relative assets, or runtime code generation. The build descriptor flags such hazards.

## 21.9 Event loop

QuickJS supplies a Promise job queue, not Node’s event loop. Weregopher implements the scheduling contract.

Queues:

```rust
struct RuntimeQueues {
    next_tick: VecDeque<Callback>,
    promise_jobs: EngineJobQueue,
    native_completions: VecDeque<NativeCompletion>,
    electron_events: VecDeque<ElectronEventDelivery>,
    timers: TimerWheel,
    immediates: VecDeque<Callback>,
    close_callbacks: VecDeque<Callback>,
}
```

A scheduler iteration:

```text
1. Receive at most one host/native event if one is ready.
2. Drain `process.nextTick` subject to a starvation limit.
3. Drain QuickJS Promise jobs subject to a job/time limit.
4. Run ready timer callbacks for the current timer phase.
5. Dispatch completed I/O callbacks.
6. Dispatch queued Electron events.
7. Drain `process.nextTick` again.
8. Drain Promise jobs again.
9. Run `setImmediate` callbacks.
10. Run close/finalizer callbacks.
11. Compute the next wake deadline and yield.
```

The precise ordering must be tested against the Node/Electron versions used by each application family. Weregopher should not claim universal Node event-loop equivalence.

Starvation guards are mandatory. An unbounded `nextTick` chain or Promise loop must not prevent shutdown, host events, or watchdog observation indefinitely.

## 21.10 Async operation registry

Every Rust-backed asynchronous operation receives an ID and lifecycle:

```rust
pub struct AsyncOperation {
    pub id: AsyncOpId,
    pub owner: RuntimeId,
    pub kind: AsyncOpKind,
    pub started_at: Instant,
    pub cancel: CancellationToken,
    pub completion: CompletionTarget,
    pub trace_context: TraceContext,
}
```

On worker shutdown:

- cancellable operations are cancelled;
- child processes follow their declared shutdown policy;
- stream handles are closed;
- pending JavaScript promises reject with a shutdown-compatible error where possible;
- unresolved host handles are released;
- the supervisor enforces a final deadline.

## 21.11 Synchronous host calls

Applications may expect synchronous APIs such as parts of `fs`, clipboard operations, or Electron getters. In process-isolated mode, synchronous calls use a dedicated pipe lane or shared-memory request slot.

Rules:

1. the worker thread MAY block waiting for the host;
2. the shell UI thread MUST NOT block waiting for JavaScript while servicing that call;
3. a broker thread marshals UI work through `PostMessage`/dispatcher mechanisms;
4. host-to-JavaScript events remain queued;
5. recursive synchronous host calls are depth-limited and traced;
6. every synchronous call has a timeout and cancellation path;
7. synchronous calls that would cause a modal nested-loop hazard SHOULD be transformed to async or implemented with a carefully modeled nested loop.

## 21.12 Debugging

Development mode SHOULD expose:

- JavaScript exception stacks with source maps;
- module resolution traces;
- loaded module graph;
- host-call timeline;
- heap statistics;
- pending async operations;
- remote handle table;
- inspector-like evaluation if a safe implementation is available;
- deterministic runtime log export.

A production adapter must not automatically expose an unauthenticated debug port.

---

# 22. Bun runtime and hybrid roles

Bun serves as a compatibility-oriented backend and build tool. It is not assumed to be perfectly Node-compatible. Every use is contract-tested for the target application.[R13][R14]

## 22.1 Full runtime mode

```toml
[runtime]
engine = "bun"
isolation = "process"
entry = "package:dist/main.js"
```

The supervisor launches a pinned or approved Bun binary with a Weregopher bootstrap. The bootstrap:

1. authenticates to the supervisor pipe;
2. installs module-resolution hooks;
3. maps `electron`, `electron/main`, and compatible subpaths to Weregopher shims;
4. loads adapter aliases;
5. establishes synchronous and asynchronous host-call transports;
6. applies environment and process virtualization;
7. loads the application main entry;
8. reports runtime capability probes and errors.

Bun is especially appropriate when a package uses a broad ordinary Node surface, npm package behavior, or Node-API modules that function under the selected Bun build.

## 22.2 Build/transpile mode

Bun MAY be used to:

- lower syntax for QuickJS;
- bundle adapter modules;
- analyze imports;
- transform ESM/CommonJS boundaries;
- emit source maps;
- compile test fixtures;
- produce dependency metadata.

Build-tool use does not imply runtime use.

```toml
[build]
engine = "bun"
output_target = "quickjs"
external = ["electron", "node:*", "compat:*"]
```

The build output must be reproducible. The adapter compiler records Bun version, command line, environment, input hashes, and output hashes.

## 22.3 Helper runtime mode

A QuickJS-hosted application may route one subsystem to a Bun service:

```text
QuickJS main runtime
    │ typed adapter RPC
    ▼
Bun helper runtime
    └── Node-heavy dependency graph
```

Examples:

- extension host;
- plugin loader;
- a package that depends heavily on Node streams;
- a library whose module resolution is difficult to reproduce immediately;
- a pure-JavaScript database migration tool;
- a test-only compatibility oracle.

The helper does not receive unrestricted application capabilities automatically. Its manifest declares the operations it may perform.

## 22.4 Bun worker protocol

The Bun worker uses the same backend-neutral runtime protocol as QuickJS where possible. A small native bridge MAY provide:

- authenticated named-pipe connection;
- synchronous RPC without spinning a JavaScript polling loop;
- shared-memory buffer transfer;
- process identity and inherited handle access;
- cancellation signal;
- crash annotations.

The bridge must be small enough to audit and must not expose a generic Win32 FFI to application JavaScript unless the adapter explicitly permits Bun FFI under full-host access.

## 22.5 Module interception

The bootstrap may use Bun plugins or a generated virtual package tree. The implementation must handle both ESM and CommonJS resolution. A conceptual plugin:

```typescript
plugin({
  name: "weregopher-electron",
  setup(builder) {
    builder.onResolve({ filter: /^electron(?:\/.*)?$/ }, args => ({
      path: args.path,
      namespace: "weregopher-electron",
    }));

    builder.onLoad(
      { filter: /.*/, namespace: "weregopher-electron" },
      args => ({
        loader: "js",
        contents: generateElectronShim(args.path),
      }),
    );
  },
});
```

The final implementation must prove that CommonJS `require("electron")` is intercepted in the target Bun version. If plugin hooks do not cover a path, the package overlay supplies a physical virtual module.

## 22.6 Process virtualization

Application code may inspect:

```javascript
process.execPath
process.argv
process.cwd()
process.resourcesPath
process.versions.node
process.versions.electron
process.versions.chrome
process.type
process.env
```

The Bun bootstrap and adapter must provide the expected values without lying in ways that break native ABI decisions. Compatibility identity and actual runtime identity should be separately accessible to diagnostics:

```javascript
process.versions.electron // compatibility target expected by app
process.weregopher.actualRuntime // development-only Weregopher metadata
```

`process.exit`, signal handlers, uncaught exceptions, and rejection behavior are intercepted so that the supervisor receives a semantic exit reason.

## 22.7 Native modules under Bun

A native module is classified, tested, and pinned by hash. Possible outcomes:

- loads directly and passes its adapter tests;
- requires an environment/path transform;
- requires rebuilding from available source;
- is routed to a helper/ABI island;
- is replaced in Rust;
- blocks the build contract.

No adapter may claim support merely because the package uses Node-API. ABI stability reduces risk but does not guarantee behavioral compatibility, external DLL availability, or Bun implementation completeness.

## 22.8 Bun version policy

Bun is treated as a runtime dependency with its own compatibility matrix:

```rust
struct BunCertification {
    bun_version: Version,
    binary_hash: Sha256,
    app_build: BuildFingerprint,
    adapter_version: Version,
    passed_probes: Vec<ProbeId>,
}
```

Adapters MAY pin a Bun range. The public registry SHOULD test current and previous supported Bun versions. Runtime auto-update must not silently move an application to an untested Bun build.

---

# 23. Node compatibility subsystem

The Node compatibility subsystem is the largest generic body of work in the QuickJS path. It is designed as a set of composable modules and host services, not one all-or-nothing claim of Node compatibility.

## 23.1 Compatibility identity

Each application build declares or discovers a Node compatibility target:

```rust
pub struct NodeCompatibilityIdentity {
    pub declared_node_version: Option<Version>,
    pub electron_node_version: Option<Version>,
    pub compatibility_profile: String,
    pub enabled_quirks: BTreeSet<NodeQuirk>,
}
```

The profile controls error codes, path behavior, module-resolution conditions, event ordering, deprecated aliases, and other observable behavior.

## 23.2 Module categories

### Category A: JavaScript modules

Implemented predominantly in JavaScript and backed by QuickJS primitives:

- `assert`;
- `events`;
- `querystring`;
- `string_decoder`;
- portions of `util`;
- portions of `buffer`;
- portions of `stream`;
- portions of `timers`;
- `url` where standards-compatible behavior is sufficient.

### Category B: Rust-backed modules

Require native operations or performance:

- `fs` and `fs/promises`;
- `path` integration with virtual/Windows paths;
- `os`;
- `crypto`;
- `zlib`;
- `net`;
- `dns`;
- `http` and `https`;
- `tls`;
- `child_process`;
- `process`;
- `perf_hooks`;
- selected `worker_threads` behavior;
- filesystem watchers;
- terminal/PTY adapters;
- `dgram` if required.

### Category C: adapter modules

Application-specific replacements:

- `compat:openai/conpty`;
- `compat:obsidian/vault-watcher`;
- `compat:discord/native-voice`;
- `compat:tidal/media`;
- `compat:vscode/extension-host`;
- `compat:github/credential-manager`.

### Category D: delegated modules

Executed in Bun or a helper:

- very large Node package graphs;
- native Node-API bindings;
- ABI-bound modules;
- modules relying on V8 internals;
- proprietary vendor components.

## 23.3 Coverage manifest

The runtime publishes machine-readable support:

```json
{
  "profile": "node-22-weregopher-1",
  "modules": {
    "fs": {
      "status": "partial",
      "exports": {
        "readFile": "supported",
        "readFileSync": "supported",
        "watch": "adapter-sensitive",
        "openAsBlob": "unsupported"
      }
    }
  }
}
```

The build analyzer compares actual call sites with this manifest. “Module present” is not sufficient; used exports and observed option combinations matter.

## 23.4 `process`

The `process` object is application-scoped even when the underlying host is not a Node process.

Required properties and behavior include, as needed:

- `argv`, `execArgv`, `execPath`;
- `cwd()` and `chdir()`;
- `env` with capability-aware mutation;
- platform/architecture values;
- `versions` compatibility identity;
- `pid`, `ppid`, title;
- uptime and memory usage;
- exit codes and exit events;
- signals;
- `nextTick`;
- standard streams;
- warnings;
- uncaught exception and rejection handling;
- resource usage where available.

`process.chdir()` is problematic in a shared process. Under process-per-app isolation it MAY change the worker’s actual current directory. Under in-process isolation it MUST be virtualized per runtime. Code that passes relative paths to native DLLs or vendor helpers may require explicit resolution transforms.

`process.kill()` and signals are translated to Windows process controls and adapter policy. Unsupported Unix signal semantics must return compatible errors rather than silently doing something else.

## 23.5 Buffers and typed arrays

`Buffer` must preserve:

- shared backing with typed arrays where Node does;
- encoding behavior;
- slicing/subarray semantics;
- integer reads/writes;
- endianness;
- pool behavior where observable;
- zero-fill and unsafe allocation policy;
- serialization through Weregopher’s wire codec.

Large buffers SHOULD transfer through shared memory or stream handles rather than repeated MessagePack copies. The protocol distinguishes copied bytes from transferable/shared buffers.

## 23.6 Streams

Streams are a compatibility hotspot. Implement:

- `Readable`, `Writable`, `Duplex`, `Transform`, `PassThrough`;
- backpressure and `highWaterMark`;
- object mode;
- piping and unpiping;
- destruction and error propagation;
- async iteration;
- `pipeline` and `finished`;
- Web Stream adapters where required;
- standard stream integration;
- host I/O stream wrappers.

A stream backed by a host pipe/socket should have a native flow-control window. The JavaScript `highWaterMark` is not a substitute for bounding native queues.

## 23.7 Filesystem

`fs` operates over a composed namespace:

```text
Virtual read-only package roots
Adapter overlay
Materialization cache
Application data roots
User-granted filesystem roots
Ordinary host paths allowed by capability policy
```

Every path operation:

1. parses according to Windows/Node path rules;
2. resolves virtual roots;
3. canonicalizes without following forbidden reparse points;
4. enforces capability policy;
5. resolves ASAR semantics;
6. executes asynchronously or synchronously;
7. returns Node-compatible result/error shape;
8. emits an attributed trace event.

Security-sensitive details:

- prevent `..` escape after path normalization;
- guard junction/symlink/reparse-point traversal;
- re-check the opened handle path where TOCTOU matters;
- distinguish package virtual paths from writable paths;
- reject device namespaces unless explicitly allowed;
- handle long paths and Unicode correctly;
- preserve case-insensitive Windows behavior while retaining original spelling where needed.

## 23.8 Filesystem watching

Windows directory watching does not map exactly to Node’s cross-platform behavior. The subsystem should use `ReadDirectoryChangesW` or a suitable completion-port wrapper and normalize events.

The adapter may declare:

```toml
[node.fs_watch]
mode = "native"
recursive = true
coalesce_ms = 20
rename_pairing = "best-effort"
```

Applications such as VS Code and Obsidian need dedicated stress tests for:

- large trees;
- rename storms;
- atomic-save patterns;
- junctions/symlinks;
- network shares;
- WSL paths;
- editor temp files;
- rapid create/delete cycles;
- watcher shutdown.

## 23.9 Networking

The network layer may be implemented through Rust libraries, Windows APIs, or delegated runtime facilities. Compatibility requirements include:

- sockets;
- DNS;
- TLS;
- HTTP/1.1;
- HTTP/2 where required;
- proxies;
- custom certificate handling;
- keepalive;
- abort/cancellation;
- streams and backpressure;
- WebSocket client behavior where used;
- local loopback servers.

Electron’s `net` and Chromium session networking are not identical to Node `http`. They belong to the Electron/session subsystem, not this module alone.

The capability model enforces destination policies where configured. It must not break normal application networking silently; denied requests produce explicit errors and trace entries.

## 23.10 Cryptography

The crypto implementation must be explicit about compatibility and provider behavior. It may use a vetted Rust crypto stack, Windows CNG, OpenSSL-compatible libraries, or delegate to Bun for a target app.

Required tests include:

- hashes/HMAC;
- random bytes;
- key generation;
- signing/verification;
- encryption/decryption;
- PEM/DER parsing;
- TLS-related interoperability;
- timing-safe comparison;
- WebCrypto interop where applicable.

Do not implement cryptographic primitives manually.

## 23.11 Child processes

`child_process` crosses a major security and lifecycle boundary.

```rust
pub struct SpawnRequest {
    pub executable: PathSpec,
    pub args: Vec<OsString>,
    pub cwd: Option<PathSpec>,
    pub environment: EnvironmentDelta,
    pub stdio: StdioSpec,
    pub windows: WindowsSpawnOptions,
    pub ownership: ProcessOwnership,
    pub capability_reason: String,
}
```

Before spawning:

- resolve package/virtual paths;
- classify executable and signer/hash;
- apply adapter allowlist or request user capability;
- create or select a Job Object;
- configure inherited handles explicitly;
- reject accidental handle inheritance;
- create pipes with explicit ACLs;
- apply mitigation policy where compatible;
- record owner app/thread/turn/subsystem;
- sanitize environment as declared.

The process tree remains owned even if the child spawns grandchildren. Job Objects are preferred where compatible. If a vendor child breaks away from jobs or requires nested-job behavior, the adapter declares and tests it.

## 23.12 Worker threads

QuickJS does not natively provide Node Worker threads. Supported strategies:

1. emulate each worker as another `weregopher-worker.exe` process;
2. create another QuickJS runtime on a thread or process;
3. route worker code to Bun;
4. transform the application to an adapter service;
5. mark unsupported.

MessagePort and structured clone semantics must use the common wire codec. Transferable buffers should move via shared-memory ownership transfer where possible.

## 23.13 Standard input/output/error

The main runtime receives virtual standard streams backed by the supervisor:

- stdout/stderr are logged and optionally forwarded;
- stdin may be closed, pipe-backed, or adapter-provided;
- TTY detection follows adapter policy;
- ANSI handling is preserved;
- blocking writes are bounded;
- secrets in logs are redacted according to trace policy.

## 23.14 Error compatibility

Node APIs often expose observable `code`, `errno`, `syscall`, and `path` fields. The subsystem defines mappings from Windows errors and Weregopher policy errors to Node-compatible errors.

```rust
struct NodeErrorShape {
    name: String,
    message: String,
    code: Option<String>,
    errno: Option<i32>,
    syscall: Option<String>,
    path: Option<String>,
    dest: Option<String>,
}
```

The mapping is profile-versioned and covered by fixtures.

## 23.15 LLRT reuse policy

LLRT is valuable prior art and potentially reusable source for QuickJS integration and Node-like modules, subject to source-level evaluation and license compliance. Weregopher must not assume LLRT’s serverless lifecycle, module policy, network policy, or compatibility target is suitable unchanged. LLRT explicitly does not promise drop-in Node compatibility.[R12]

Any reused component must be documented in `THIRD_PARTY_NOTICES`, pinned by source revision, and wrapped behind Weregopher’s own interfaces.


---

# 24. Electron compatibility object model

Electron compatibility is implemented as a versioned object broker plus JavaScript proxy modules. The broker owns native resources and authoritative object state. JavaScript receives proxies with Electron-shaped methods, properties, events, and identities.

The objective is not to mirror Electron’s C++ implementation. It is to reproduce the observable behavior required by supported application builds.

## 24.1 Compatibility namespace

The runtime resolves:

```javascript
require("electron")
require("electron/main")
require("electron/renderer")
```

and supported ESM equivalents to generated compatibility modules. The exports are selected by realm:

- main runtime receives main-process exports;
- preload receives renderer/preload-safe exports;
- page renderer receives only adapter-exposed APIs, never the raw Electron module unless the original package intentionally enabled renderer Node integration and the adapter models that dangerous configuration.

## 24.2 Object handles

```rust
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct ObjectHandle {
    pub app: AppInstanceId,
    pub id: u64,
    pub generation: u32,
    pub kind: ObjectKind,
}
```

The generation prevents a released handle from referring to a newly allocated object that reused the numeric ID.

Every incoming handle is validated for:

- authenticated runtime connection;
- matching application instance;
- expected object kind;
- current generation;
- required capability;
- object lifecycle state.

Cross-application handles are always invalid.

## 24.3 Broker object types

Initial object model:

```rust
enum BrokerObject {
    App(AppObject),
    BrowserWindow(BrowserWindowObject),
    WebContents(WebContentsObject),
    Session(SessionObject),
    WebRequest(WebRequestObject),
    Menu(MenuObject),
    MenuItem(MenuItemObject),
    Tray(TrayObject),
    NativeImage(NativeImageObject),
    DownloadItem(DownloadItemObject),
    Notification(NotificationObject),
    MessagePort(MessagePortObject),
    UtilityProcess(UtilityProcessObject),
    TouchBarPlaceholder(UnsupportedObject),
}
```

Windows-only implementation need not implement macOS-only behavior, but the compatibility module should fail with an appropriate unsupported-platform shape where the application probes it.

## 24.4 JavaScript proxies

Conceptual proxy:

```javascript
class BrowserWindow extends EventEmitter {
  constructor(options = {}) {
    super();
    const created = binding.callSync("BrowserWindow.create", [options]);
    this[kHandle] = created.window;
    this.webContents = WebContents.fromHandle(created.webContents);
    registerEventTarget(this[kHandle], this);
  }

  loadURL(url, options) {
    return binding.call("WebContents.loadURL", [
      this.webContents[kHandle],
      url,
      options,
    ]);
  }

  show() {
    binding.callSync("BrowserWindow.show", [this[kHandle]]);
  }

  destroy() {
    binding.callSync("BrowserWindow.destroy", [this[kHandle]]);
  }
}
```

Proxy requirements:

- stable identity for repeated lookup;
- prototype layout sufficient for application checks;
- event-emitter behavior;
- property getters/setters where observable;
- Promise versus synchronous return behavior;
- correct error timing;
- release/finalization;
- application-compatible `instanceof` behavior within the compatibility realm.

## 24.5 Electron API contracts

Electron API support is represented at method/event granularity:

```rust
struct ElectronApiContract {
    target_electron_range: VersionReq,
    modules: BTreeMap<ModuleName, ModuleContract>,
}

struct ModuleContract {
    exports: BTreeMap<ExportName, ExportContract>,
    events: BTreeMap<EventName, EventContract>,
}
```

A generated build descriptor records actual use:

```json
{
  "BrowserWindow": {
    "constructor": [{"callSites": 4}],
    "getAllWindows": [{"callSites": 2}],
    "events": ["closed", "focus", "ready-to-show"]
  }
}
```

This permits a build to pass even when Weregopher does not implement unrelated Electron APIs.

## 24.6 `app`

The `app` object must model:

- readiness;
- application paths;
- version/name/locale;
- command-line switches where meaningful;
- single-instance lock;
- protocol/file activation;
- lifecycle events;
- quit, exit, relaunch semantics;
- login-item/startup behavior;
- recent documents where used;
- accessibility support toggles;
- hardware acceleration policy before renderer creation;
- application user model ID;
- badges and notifications where exposed;
- sandbox helper setup callbacks for target apps.

Lifecycle state:

```rust
enum AppLifecycle {
    Bootstrapping,
    BeforeReady,
    Ready,
    QuittingRequested,
    BeforeQuit,
    WillQuit,
    Exiting,
    Exited,
}
```

Important events:

```text
will-finish-launching
ready
window-all-closed
before-quit
will-quit
quit
activate
second-instance
open-file
open-url
browser-window-created
web-contents-created
```

Event ordering and cancellation must be fixture-tested. `app.quit()` is not equivalent to killing the worker. It initiates the modeled close/quit flow. `app.exit(code)` bypasses some normal close behavior as Electron does.

## 24.7 Single-instance behavior

The daemon maintains an application-family/adapter-defined instance key. A second launch:

1. resolves the target running instance;
2. validates package and profile compatibility;
3. forwards command line, working directory, and activation data;
4. emits `second-instance` to the main runtime;
5. activates an appropriate window if application logic requests it.

Separate profiles MAY intentionally use separate instance keys.

## 24.8 `BrowserWindow`

`BrowserWindow` maps to a native top-level or child HWND plus a renderer controller.

Supported option categories:

- size, position, constraints;
- visibility and show timing;
- frame/titlebar style;
- transparency/background;
- parent/child/modal relationships;
- focusability;
- resizability/minimization/maximization/fullscreen;
- taskbar visibility;
- icon;
- always-on-top;
- workspace/virtual-desktop behavior where practical;
- web preferences;
- session/partition;
- preload;
- sandbox/context isolation/node integration;
- background throttling policy;
- web security policy;
- spellcheck;
- autoplay;
- native window open behavior.

Not every visual option maps exactly to Win32/WebView2. Adapter contracts identify options that are semantically required.

Window events include:

```text
ready-to-show
show/hide
focus/blur
maximize/unmaximize
minimize/restore
resize/move
enter-full-screen/leave-full-screen
close/closed
unresponsive/responsive
page-title-updated
app-command
session-end/query-session-end
```

Close cancellation must occur before destruction. The shell sends an event request to the main runtime and waits only through a bounded, deadlock-safe close protocol. If the runtime is hung, policy decides whether to wait, force close, or offer recovery.

## 24.9 `webContents`

`webContents` is the broadest compatibility surface. Weregopher divides methods into tiers:

### Tier 1: core navigation and execution

- `loadURL`, `loadFile`;
- reload/stop/goBack/goForward;
- URL/title/loading state;
- execute JavaScript;
- send IPC;
- open/close DevTools;
- zoom;
- focus;
- print/print-to-PDF if backend supports it;
- capture page;
- find-in-page;
- user-agent and audio state.

### Tier 2: lifecycle and interception

- navigation events;
- new-window/window-open handling;
- permission requests;
- certificate/auth handlers;
- download events;
- renderer crash/process-gone events;
- render-process responsiveness;
- frame creation/navigation;
- before-input-event;
- context-menu.

### Tier 3: backend-sensitive behavior

- debugger/CDP attachment;
- frame-specific execution;
- isolated worlds;
- custom protocol behavior;
- browser extensions;
- offscreen rendering;
- media/device control;
- desktop capture;
- WebRTC policies;
- service-worker controls;
- host-resolver rules.

Tier 3 often determines WebView2 versus CEF selection.

## 24.10 `session`

Electron sessions represent browser storage, cookies, cache, permissions, networking hooks, protocol handlers, downloads, and partitions.[R26]

Weregopher maps a session to a renderer-backend profile/environment plus broker state:

```rust
struct SessionObject {
    partition: SessionPartition,
    persistence: Persistence,
    renderer_profile: RendererProfileHandle,
    permission_store: PermissionStore,
    protocol_registry: ProtocolRegistry,
    web_request: WebRequestRegistry,
    download_policy: DownloadPolicy,
}
```

Partition mapping:

```text
persist:work      → persistent profile `<app>/work`
persist:personal  → persistent profile `<app>/personal`
empty/non-persist → ephemeral profile/environment or disposable storage root
```

Backend limitations must be explicit. If WebView2 cannot provide a required session behavior, the build contract may select CEF.

## 24.11 `webRequest`

The compatibility layer models request interception stages used by the application:

```text
onBeforeRequest
onBeforeSendHeaders
onSendHeaders
onHeadersReceived
onResponseStarted
onBeforeRedirect
onCompleted
onErrorOccurred
```

The renderer backend maps its available interception APIs to this contract. Ordering, blocking callbacks, redirect behavior, header mutation, and filter matching are tested. Applications that depend on exact Chromium extension-style semantics may require CEF.

## 24.12 `contextBridge`, `ipcMain`, and `ipcRenderer`

These are specified in Sections 26 and 27. The broker treats channel strings as opaque by default. There is no application-specific channel mapping unless an adapter intentionally replaces one endpoint.

## 24.13 Menus, tray, notifications, clipboard, dialogs, and shell

These modules map to native Windows services.

### `dialog`

- open/save dialogs;
- message boxes;
- error boxes;
- certificates where required;
- sync and async forms;
- parent-window modality;
- filters/default paths/options.

### `shell`

- open external URI;
- open path/show item in folder;
- trash item;
- shortcut-link operations where required;
- beep;
- recent documents.

External URI launches are capability-checked and protected against malformed schemes.

### `clipboard`

- text;
- HTML;
- RTF;
- images;
- bookmarks/custom formats where required;
- selection clipboard returns unsupported on Windows unless application expects platform branching.

### `nativeImage`

Represents encoded/decoded images, scale factors, icons, and clipboard/tray resources. Large image data should stay in the shell process where possible and be referenced by handles.

### `Menu` and `Tray`

Implemented through HMENU/notification-area APIs with event routing, accelerator handling, checked/radio state, icons, and context menus.

### `Notification`

Maps to Windows notifications where possible and adapter-specific fallback where package identity/AUMID requirements differ. Click/action events route back to the owning runtime.

## 24.14 Utility processes

Electron `utilityProcess` can be represented by:

- another QuickJS worker;
- a Bun worker;
- a native helper host;
- a direct vendor helper;
- an ABI island.

The compatibility object preserves message ports, process events, stdout/stderr, and termination semantics used by the package.

## 24.15 Remote object lifetime

JavaScript proxies retain broker objects. Release occurs when:

- application calls an explicit destroy/close method;
- broker lifecycle ends the object;
- runtime sends `ReleaseHandle` after finalization;
- connection closes;
- app session terminates.

The broker must not depend solely on JavaScript finalizers for resources such as windows, files, processes, or security-sensitive handles.

Leak diagnostics report:

- object count by kind;
- retained-by-runtime count;
- broker-only objects;
- stale subscriptions;
- long-lived remote function handles;
- creation stacks in development mode.

## 24.16 Unsupported API trap

An unsupported call produces a structured error and trace:

```json
{
  "kind": "UnsupportedElectronApi",
  "module": "desktopCapturer",
  "member": "getSources",
  "argumentsShape": ["object"],
  "applicationBuild": "sha256:...",
  "callSite": "app.asar/dist/main.js:18342:17",
  "suggestedBackend": "cef-or-specialized",
  "adapterAction": "implement-or-alias"
}
```

In `follow-current` mode, a newly observed API may trigger candidate quarantine or a safe fallback to the last-known-good build before persistent state mutation.

---

# 25. Renderer backends

The renderer subsystem hosts the package’s own desktop renderer content. It never substitutes a public web client.

Each backend implements a common interface plus backend-specific capabilities. Backend choice is per application build and may be per window when an adapter has a compelling reason.

## 25.1 Renderer interface

```rust
pub trait RendererBackend: Send {
    fn backend_id(&self) -> RendererBackendId;
    fn version(&self) -> RendererVersion;
    fn capabilities(&self) -> RendererCapabilities;

    fn create_environment(
        &mut self,
        spec: EnvironmentSpec,
    ) -> Result<EnvironmentHandle, RendererError>;

    fn create_profile(
        &mut self,
        environment: EnvironmentHandle,
        spec: ProfileSpec,
    ) -> Result<ProfileHandle, RendererError>;

    fn create_view(
        &mut self,
        window: NativeWindowHandle,
        profile: ProfileHandle,
        spec: ViewSpec,
    ) -> Result<RendererHandle, RendererError>;

    fn register_origin(
        &mut self,
        environment: EnvironmentHandle,
        origin: PrivateOrigin,
        package: Arc<dyn PackageView>,
    ) -> Result<(), RendererError>;

    fn add_document_start_script(
        &mut self,
        renderer: RendererHandle,
        world: ScriptWorld,
        source: &str,
    ) -> Result<ScriptHandle, RendererError>;

    fn navigate(
        &mut self,
        renderer: RendererHandle,
        target: NavigationTarget,
    ) -> Result<NavigationId, RendererError>;

    fn post_message(
        &mut self,
        renderer: RendererHandle,
        message: WireValue,
    ) -> Result<(), RendererError>;

    fn execute(
        &mut self,
        renderer: RendererHandle,
        world: ScriptWorld,
        source: &str,
    ) -> Result<PendingRendererCall, RendererError>;

    fn set_visibility(
        &mut self,
        renderer: RendererHandle,
        visibility: RendererVisibility,
    ) -> Result<(), RendererError>;

    fn suspend(
        &mut self,
        renderer: RendererHandle,
    ) -> Result<SuspendOutcome, RendererError>;

    fn close(&mut self, renderer: RendererHandle) -> Result<(), RendererError>;
}
```

## 25.2 Capability model

```rust
pub struct RendererCapabilities {
    pub chromium_family: bool,
    pub isolated_worlds: SupportLevel,
    pub document_start_scripts: bool,
    pub custom_schemes: SupportLevel,
    pub request_interception: SupportLevel,
    pub devtools_protocol: SupportLevel,
    pub browser_extensions: SupportLevel,
    pub protected_media: SupportLevel,
    pub screen_capture: SupportLevel,
    pub audio_capture: SupportLevel,
    pub video_capture: SupportLevel,
    pub offscreen_rendering: SupportLevel,
    pub service_worker_control: SupportLevel,
    pub web_authn: SupportLevel,
    pub multiple_profiles: bool,
    pub shared_browser_process: bool,
    pub fixed_version: bool,
}
```

The build descriptor records renderer requirements discovered from:

- Electron `webPreferences`;
- `webContents` calls;
- session/webRequest use;
- command-line switches;
- media permissions;
- custom protocols;
- browser extensions;
- renderer feature probes;
- oracle traces.

## 25.3 WebView2 backend

WebView2 is preferred on Windows. It uses installed Microsoft Edge WebView2 Runtime components rather than bundling another browser by default. A shared UDF can permit process sharing, while profiles under the UDF provide browser-data isolation.[R5][R6][R7]

### Environment policy

```rust
struct WebView2EnvironmentKey {
    browser_executable_folder: Option<PathBuf>,
    user_data_folder: PathBuf,
    additional_browser_arguments: NormalizedArguments,
    language: Option<String>,
    target_compatible_browser_version: Option<String>,
    exclusive_user_data_folder_access: bool,
    release_channel_preference: Option<ReleaseChannelPreference>,
}
```

Only environments with compatible keys can share a browser process.

The environment manager maintains:

- one or more shared UDF groups;
- dedicated UDFs where an adapter requires isolation;
- profile naming and ownership;
- environment option compatibility;
- browser-process exit handling;
- UDF migration/cleanup serialization;
- runtime-version certification.

### UDF/profile policy

Default:

```text
UDF: `%LOCALAPPDATA%/Weregopher/WebView2/shared-v1`
  Profile: `openai.chatgpt/default`
  Profile: `slack/work`
  Profile: `discord/stable`
```

An adapter MAY request:

- dedicated UDF;
- separate UDF per account;
- ephemeral UDF;
- shared profile group for intentional SSO;
- fixed-version environment.

Profiles must never share cookies by accident merely because the UDF is shared.

### Private package origin

The backend serves package content under an HTTPS-like private origin:

```text
https://<opaque-app-id>.weregopher.invalid/
```

Requests map to the ASAR VFS and overlay. The mapping must:

- reject path traversal;
- assign correct MIME types;
- support ranges where media/assets require them;
- provide cache validators based on content hashes;
- preserve source maps in development mode;
- enforce adapter origin policy;
- avoid exposing arbitrary host files.

Where the package requires `file:` semantics, the adapter either transforms those assumptions or uses a backend-specific virtual host/scheme implementation.

### Composition

The shell may use windowed WebView2 controllers or composition controllers. DirectComposition is appropriate for advanced composition, transparency, overlays, or nonstandard window structures. Standard windows should use the simplest reliable controller that meets the application contract.

### WebView2 limitations

Potential blockers include:

- browser switches unavailable to the embedding API;
- extension APIs;
- exact render-process hooks;
- proprietary codec/protected-media behavior;
- frame/world semantics differing from Electron;
- request interception differences;
- unsupported custom schemes;
- user-agent or runtime-version assumptions;
- vendor checks against WebView2;
- browser process sharing constraints.

A blocker routes the build to CEF or a specialized surface; it does not route to a public website.

## 25.4 Evergreen and fixed version

Normal use:

```toml
[renderer.webview2]
distribution = "evergreen"
```

Compatibility CI or adapter exception:

```toml
[renderer.webview2]
distribution = "fixed"
version = "<certified version>"
```

The certification record includes the runtime version. A WebView2 update can trigger a renderer contract recheck even when the application package did not change.[R8]

Fixed Version assets are optional backend components and are subject to Microsoft redistribution requirements. They must not be committed casually to the source repository.

## 25.5 CEF backend

CEF is the Chromium-compatibility fallback.[R9]

Use it when the application requires:

- Chromium command-line configuration unavailable in WebView2;
- direct renderer-process integration;
- V8 extension/binding behavior;
- browser-extension loading;
- custom schemes with exact semantics;
- more complete request handling;
- offscreen rendering;
- specialized media/codec configuration;
- exact Chromium version pinning;
- render-process crash/control behavior unavailable through WebView2.

### CEF process topology

```text
weregopher-shell.exe
├── CEF browser integration
├── CEF renderer subprocess(es)
├── GPU process
├── network/utility subprocesses
└── adapter native helpers
```

CEF remains multi-process. It may consume more resources than WebView2 and can weaken the sharing objective, but can still remove a separate vendor Electron main/runtime and permit Weregopher lifecycle/process control.

### CEF delivery

CEF is an optional installable backend component. The adapter declares an allowed version range and required features. The registry can distribute metadata but must comply with CEF/Chromium licenses and artifact-size realities.

```toml
[renderer.cef]
required = true
version_range = ">=150.0 <151.0"
component_id = "weregopher.cef.win-x64.150"
```

## 25.6 Specialized vendor surfaces

A specialized surface is a renderer or media/compositor component supplied by an adapter. Examples may include:

- proprietary protected-media renderer;
- game overlay surface;
- vendor browser helper;
- custom GPU compositor;
- a native editor surface;
- a media/video call engine.

Hard rules:

- it must have a narrow interface;
- it must be separately supervised;
- it must not launch the vendor’s full desktop application;
- it must not hide a complete Electron `BrowserWindow` tree behind the term “helper”;
- its process and memory cost must be reported;
- its licensing and redistribution status must be explicit;
- it must be selected only for application features requiring it.

## 25.7 Per-window backend selection

An adapter MAY use different backends for different windows:

```toml
[[renderer.window_rules]]
match = "main"
backend = "webview2"

[[renderer.window_rules]]
match = "protected-player"
backend = "specialized:tidal-media"

[[renderer.window_rules]]
match = "extension-hosted-browser"
backend = "cef"
```

Cross-backend `webContents` behavior and IPC are brokered through the same Electron model. This adds complexity and must be justified by the target application.

## 25.8 Renderer lifecycle and recovery

Renderer states:

```text
Creating
Initialized
Navigating
DOMContentLoaded
Loaded
Visible/Hidden
Suspending/Suspended
Crashed
Recovering
Closed
```

The backend emits normalized events. On crash:

- collect backend diagnostics;
- invalidate frame/world handles;
- preserve broker `webContents` identity if compatible;
- recreate the renderer/controller;
- restore session/profile;
- re-register package origin and scripts;
- navigate to the recovery target;
- notify application main logic through Electron-compatible process-gone events;
- apply adapter recovery policy.

## 25.9 Renderer suspension and unloading

Suspension is an optional resource policy, not a compatibility assumption. It is allowed only when:

- the renderer is not visible;
- no active audio/video/call exists;
- the adapter permits suspension;
- no required background task would be lost;
- the backend supports it;
- the application has passed resume tests.

Unloading destroys the renderer and releases its memory but loses in-memory page state. It is adapter-specific and must not be applied generically to active desktop clients.

---

# 26. Preload, context isolation, and renderer bridging

Preload compatibility is a central subsystem. Many Electron applications place their entire desktop privilege boundary in preload scripts and `contextBridge`. Weregopher must preserve both behavior and security characteristics closely enough for the package.

## 26.1 Execution models

Electron application configurations commonly include:

```text
contextIsolation=true, sandbox=true, nodeIntegration=false
contextIsolation=true, sandbox=false, nodeIntegration=false
contextIsolation=false, nodeIntegration=false
contextIsolation=false, nodeIntegration=true
```

Weregopher records the original configuration and selects a compatible implementation. Dangerous configurations are not silently “secured” if that breaks the package; they are exposed in adapter security metadata.

## 26.2 Preload pipeline

```text
Discover preload entry
→ resolve ASAR/package path
→ static analyze imports and exports
→ apply semantic adapter transforms
→ bundle/lower if required
→ inject Weregopher preload bootstrap
→ register at document start
→ execute in selected world
→ establish contextBridge exports
→ report readiness/failure
```

The compiled preload artifact is content-addressed by:

- original source graph hash;
- transform set hash;
- compiler version;
- target renderer/backend/version;
- compatibility identity.

## 26.3 Isolated worlds

For `contextIsolation=true`, preload code and page code must not share an ordinary global object.

The backend implementation MAY use:

- Chromium isolated worlds through CDP or backend-native APIs;
- CEF V8 contexts;
- another backend-provided isolated script context.

Required properties:

- page assignments do not mutate preload globals;
- page prototype pollution does not directly compromise preload objects;
- only explicitly exposed bridge values cross worlds;
- frame/world destruction invalidates handles;
- navigation recreates preload execution;
- origin/frame checks precede privileged operations.

A backend whose world semantics cannot satisfy the build contract is rejected for that build.

## 26.4 Bootstrap

The document-start bootstrap installs an internal object not directly exposed to page content:

```javascript
const internal = createInternalBridge({
  rendererId,
  frameId,
  worldId,
  nonce,
});
```

It provides the transformed preload with:

- `electron` renderer/preload module;
- permitted Node modules or proxies;
- contextBridge implementation;
- IPC transport;
- remote function/value handle registry;
- lifecycle notifications;
- source-map/error reporting.

The raw WebView2 host object or CEF native binding must not be exposed to the page’s main world.

## 26.5 `contextBridge.exposeInMainWorld`

When preload calls:

```javascript
contextBridge.exposeInMainWorld("desktop", apiObject);
```

Weregopher:

1. validates the key;
2. walks the object according to bridge rules;
3. copies allowed immutable values;
4. converts functions into remote function handles;
5. converts promises into promise handles/results;
6. rejects unsupported symbols/prototypes/cycles where Electron would reject them;
7. installs a frozen/proxied representation in the page main world;
8. associates every function with app, renderer, frame, origin, and world identity.

Conceptual bridge descriptor:

```rust
pub enum BridgeValue {
    Primitive(WireValue),
    FrozenArray(Vec<BridgeValue>),
    FrozenObject(Vec<(String, BridgeValue)>),
    Function(RemoteFunctionHandle),
    Promise(RemotePromiseHandle),
}
```

The exact supported value types are compatibility-profiled against the target Electron version.[R3]

## 26.6 Remote function calls

Page call:

```javascript
await window.desktop.openProject(path);
```

Route:

```text
page proxy
→ renderer internal bridge
→ shell renderer endpoint
→ preload/main runtime endpoint
→ application function
→ result/error
→ page Promise
```

Call metadata includes:

- app instance;
- window/webContents;
- frame and origin;
- world generation;
- function handle generation;
- request ID;
- user-activation state where relevant;
- capability context.

The call is rejected if navigation destroyed the originating world or the origin no longer matches.

## 26.7 `ipcRenderer`

The preload shim implements:

```javascript
ipcRenderer.send(channel, ...args)
ipcRenderer.sendSync(channel, ...args)
ipcRenderer.invoke(channel, ...args)
ipcRenderer.on(channel, listener)
ipcRenderer.once(channel, listener)
ipcRenderer.removeListener(channel, listener)
ipcRenderer.postMessage(channel, message, transfer)
```

`sendSync` requires a bounded synchronous bridge and is a deadlock risk. The trace analyzer identifies its call sites. Adapters SHOULD remove it where possible, but may preserve it when required.

Raw `ipcRenderer` should not be exposed to page content by default. If the package intentionally does so, the adapter records the exception and security implications.

## 26.8 Node access in preload

Preloads may import Node built-ins or packages. Strategies:

1. compile pure preload logic into the isolated world and proxy native operations to the main worker;
2. run privileged preload logic in a dedicated preload worker and expose only bridge descriptors to the renderer;
3. use CEF V8/native bindings;
4. route complex Node code to Bun;
5. transform the preload into an adapter module.

The first strategy is preferred for simple APIs. A preload that relies heavily on synchronous Node object identity may require CEF or a dedicated worker with synchronous RPC.

## 26.9 `contextIsolation=false`

For packages that expect shared globals, the bootstrap executes in the page world before application scripts. This is less secure but may be necessary for parity.

The adapter manifest must declare:

```toml
[security.renderer]
context_isolation = false
node_integration = true
risk_acknowledged = true
```

The renderer remains limited by application capabilities at the host boundary. However, remote content compromise may gain the same host capabilities the package itself grants; this must be visible in diagnostics.

## 26.10 Frame handling

Every frame receives an identity:

```rust
struct FrameIdentity {
    renderer: RendererId,
    frame: u64,
    generation: u32,
    parent: Option<u64>,
    origin: Origin,
    is_main: bool,
}
```

Preload rules declare whether scripts apply to:

- main frame only;
- all frames;
- selected origins;
- sandboxed frames;
- dynamically created frames.

Cross-origin iframes must not inherit privileged APIs unless the original Electron configuration and adapter explicitly require it.

## 26.11 Navigation and invalidation

On navigation:

1. mark old frame/world as closing;
2. reject new calls from the old world;
3. optionally wait for in-flight calls according to policy;
4. release remote functions and promises;
5. create new frame/world generation;
6. execute bootstrap/preload;
7. expose bridges;
8. emit normalized navigation events.

Late replies for an old generation are discarded and traced.

## 26.12 Bridge security invariants

- No raw native pointer or host object enters page JavaScript.
- Every remote handle is scoped to app, renderer, frame, world, and generation.
- Page-origin changes invalidate privileged function access unless explicitly retained.
- Host calls enforce capabilities independently of bridge possession.
- Serialization has size/depth/reference limits.
- Prototype keys such as `__proto__`, `prototype`, and `constructor` receive explicit handling.
- Error stacks are sanitized outside developer mode.
- Secret-bearing arguments are redacted in default traces.
- User activation is preserved for operations that require it.

## 26.13 Compatibility tests

Fixtures must cover:

- primitive exposure;
- nested objects/arrays;
- functions;
- promises;
- thrown errors;
- callback arguments;
- typed arrays;
- dates and regexes where supported;
- unsupported values;
- frame navigation;
- cross-origin frames;
- world destruction;
- prototype pollution attempts;
- concurrent calls;
- large payloads;
- renderer crash/recovery;
- sync IPC;
- event listener removal.

---

# 27. IPC and serialization

Weregopher uses a common protocol for host/worker/helper communication and a related bridge protocol for renderer messaging. The protocol is backend-neutral, authenticated, bounded, versioned, and observable.

## 27.1 Transports

Default Windows transport: named pipes.

Channels:

```text
control       lifecycle, calls, events, handles
sync          bounded synchronous worker-to-host calls
stream        bulk/streamed data control
trace         optional high-volume tracing
crash         minimal crash/last-gasp notification
```

Small deployments may multiplex channels over one pipe. High-throughput adapters may separate them.

Large byte buffers use:

- shared memory sections with duplicated handles;
- file-backed content-addressed blobs;
- bounded streams;
- direct renderer-backend transfer where available.

## 27.2 Pipe security

Named pipes MUST use an explicit security descriptor limited to the current user SID and required service identity. Windows default named-pipe security may grant broader read access than desired, so defaults are not acceptable.[R24]

Connection authentication:

1. daemon generates instance ID and one-time nonce;
2. worker receives the nonce through an inherited anonymous handle or protected inherited mapping, not command-line text;
3. pipe server validates client PID;
4. server validates process user SID and expected executable/signature/hash where configured;
5. server validates Job Object ownership;
6. client proves nonce possession in `Hello`;
7. server returns negotiated protocol and capabilities.

## 27.3 Frame envelope

```rust
#[repr(C)]
pub struct FrameHeader {
    pub frame_length: u32,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub message_kind: u8,
    pub flags: u8,
    pub reserved: u16,
    pub request_id: u64,
    pub sequence: u64,
}
```

Properties:

- little-endian;
- length includes payload but not transport framing metadata;
- maximum size negotiated and hard-capped;
- unknown flags rejected unless marked extension-safe;
- sequence numbers monotonically increase per direction;
- request ID zero means no request/response correlation;
- payload encoded in MessagePack with registered extension tags, or another binary codec selected by ADR before implementation.

MessagePack is an implementation choice, not a locked requirement. The semantic `WireValue` contract is locked.

## 27.4 Message kinds

```rust
pub enum MessageKind {
    Hello,
    Welcome,
    Reject,

    LoadApplication,
    ApplicationReady,
    ApplicationExit,

    Call,
    CallResult,
    CallError,
    Cancel,

    Event,
    Subscribe,
    Unsubscribe,

    IpcSend,
    IpcInvoke,
    IpcReply,
    IpcError,

    StreamOpen,
    StreamWindow,
    StreamData,
    StreamEnd,
    StreamError,

    RetainHandle,
    ReleaseHandle,

    SharedBufferOffer,
    SharedBufferAccept,
    SharedBufferRelease,

    Heartbeat,
    Diagnostics,
    Shutdown,
}
```

## 27.5 Handshake

```rust
struct Hello {
    runtime_id: RuntimeId,
    app_instance: AppInstanceId,
    backend: RuntimeBackendId,
    backend_version: String,
    protocol_range: VersionRange,
    nonce_proof: [u8; 32],
    capabilities: RuntimeCapabilities,
    limits_requested: ProtocolLimits,
}

struct Welcome {
    protocol_version: ProtocolVersion,
    session_id: ProtocolSessionId,
    limits: ProtocolLimits,
    compatibility_identity: CompatibilityIdentity,
    heartbeat: HeartbeatPolicy,
}
```

A protocol-major mismatch rejects the connection. Minor versions use negotiated feature bits.

## 27.6 Wire value model

```rust
pub enum WireValue {
    Undefined,
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    NegativeZero,
    NaN,
    PositiveInfinity,
    NegativeInfinity,
    BigInt { negative: bool, magnitude: Vec<u8> },
    String(String),
    Bytes(Vec<u8>),

    Array(Vec<WireValue>),
    Object(Vec<(String, WireValue)>),
    Reference(u32),

    Date(i64),
    RegExp { source: String, flags: String },

    Error(WireError),
    Handle(ObjectHandle),
    Function(RemoteFunctionHandle),
    Promise(RemotePromiseHandle),
    MessagePort(MessagePortHandle),

    TypedArray {
        kind: TypedArrayKind,
        byte_offset: u64,
        length: u64,
        storage: BufferStorage,
    },
}
```

`Reference` permits cycles and repeated identity within one serialized graph. Reference IDs are message-local unless represented by a remote handle.

## 27.7 Limits

```rust
pub struct ProtocolLimits {
    pub max_frame_bytes: u32,
    pub max_graph_nodes: u32,
    pub max_object_depth: u16,
    pub max_string_bytes: u32,
    pub max_inline_buffer_bytes: u32,
    pub max_pending_requests: u32,
    pub max_remote_handles: u32,
    pub max_open_streams: u16,
    pub max_listener_count: u32,
}
```

Limit violation terminates the offending request and may quarantine a runtime if it indicates corruption or abuse. It must not allocate according to an untrusted length before checking the cap.

## 27.8 Calls and errors

```rust
struct CallMessage {
    target: CallTarget,
    method: String,
    args: Vec<WireValue>,
    context: CallContext,
}

struct CallContext {
    app: AppInstanceId,
    renderer: Option<RendererId>,
    frame: Option<FrameIdentity>,
    user_activation: bool,
    capability_token: CapabilityTokenId,
    trace_parent: Option<TraceId>,
    deadline_ms: Option<u32>,
}
```

Errors preserve JavaScript-visible shape and internal category:

```rust
struct WireError {
    name: String,
    message: String,
    stack: Option<String>,
    code: Option<String>,
    kind: Option<String>,
    cause: Option<Box<WireValue>>,
    data: BTreeMap<String, WireValue>,
}
```

## 27.9 Ordering and concurrency

- Frames are ordered per transport direction by sequence.
- Independent requests may execute concurrently unless the target object requires serialization.
- UI object calls execute on the shell UI thread in issue order for that object.
- Events generated during a call are queued and delivered after the call boundary unless Electron behavior requires earlier delivery and the implementation has a safe reentrancy model.
- Cancellation is idempotent.
- Late results after cancellation are discarded but traced.
- A connection close releases all connection-owned remote handles.

## 27.10 Synchronous lane

The synchronous lane exists only for APIs that require it. It has stricter limits:

- one outstanding sync call per runtime thread by default;
- recursion depth cap;
- deadline required;
- no unbounded payloads;
- no host-to-worker sync callback;
- no UI-thread wait on runtime;
- deadlock detector records wait graph.

A detected wait cycle produces a diagnostic and aborts the inner operation rather than hanging the desktop indefinitely.

## 27.11 Streams

Stream protocol uses credit-based flow control:

```text
STREAM_OPEN
STREAM_WINDOW(credit=N)
STREAM_DATA(up to credit)
STREAM_WINDOW(additional credit)
STREAM_END
```

The receiver controls memory by granting credit. This is used for:

- child-process stdio;
- large file reads/writes;
- network bodies;
- app-server logs/traces;
- media-independent large data;
- archive extraction.

## 27.12 Shared buffers

Large `ArrayBuffer`/typed-array transfer:

1. sender creates a file mapping or approved shared-memory object;
2. sender duplicates a handle into receiver process;
3. sends descriptor and immutable/mutable ownership mode;
4. receiver validates size and maps it;
5. ownership transfer or reference counting is explicit;
6. release closes mappings in both processes.

Never accept a raw numeric handle from an untrusted message without verifying it came through the authenticated duplication path.

## 27.13 Renderer bridge protocol

Renderer messages carry additional fields:

```rust
struct RendererEnvelope {
    app: AppInstanceId,
    renderer: RendererId,
    frame: FrameIdentity,
    world: WorldIdentity,
    navigation: NavigationGeneration,
    nonce: [u8; 16],
    payload: WireValue,
}
```

The shell obtains authoritative frame/origin data from the renderer backend and does not trust page-supplied origin text.

## 27.14 Versioning

Protocol evolution rules:

- major version: incompatible envelope or semantic change;
- minor version: additive message kind/field with negotiated feature bit;
- unknown optional fields preserved or ignored according to schema;
- unknown required message kinds reject;
- test fixtures retain at least the previous supported major version during migration;
- adapters declare minimum runtime protocol only when necessary.

## 27.15 Fuzzing

The protocol parser and wire codec require:

- property-based round-trip tests;
- malformed length tests;
- deep nesting tests;
- cyclic graph tests;
- duplicate reference tests;
- integer boundary tests;
- invalid UTF-8 policy tests;
- handle forgery tests;
- sequence/replay tests;
- cancellation races;
- shared-buffer lifetime races;
- libFuzzer/AFL-compatible fuzz targets where practical.


---

# 28. Native modules, vendor helpers, and ABI islands

Native dependencies are handled through explicit strategies. The existence of a native dependency does not automatically force the original full Electron runtime, but neither may Weregopher pretend that an arbitrary `.node` binary can run under QuickJS.

Electron documents that native modules commonly require rebuilding for Electron because Electron’s Node/V8/crypto ABI can differ from ordinary Node.[R4]

## 28.1 Dependency inventory

The scanner identifies:

- `.node` files;
- DLL imports and delay imports;
- package metadata for native modules;
- prebuild directories and ABI tags;
- `node-gyp-build`, `bindings`, `prebuild-install`, and similar loaders;
- native helper EXEs;
- COM registrations;
- codecs;
- services/drivers referenced by the package;
- architecture-specific resources;
- child-process spawn sites;
- FFI package use;
- WebAssembly modules.

```rust
struct NativeDependency {
    package_name: Option<String>,
    package_version: Option<String>,
    path: VirtualPath,
    hash: Sha256,
    architecture: Architecture,
    abi: NativeAbi,
    imports: Vec<DllImport>,
    loader_sites: Vec<SourceLocation>,
    signer: Option<SignerIdentity>,
}
```

## 28.2 Strategy enum

```rust
enum NativeStrategy {
    RustReplacement,
    BunNapi,
    RebuiltNodeAddon,
    VendorHelper,
    AbiIsland,
    SpecializedSurface,
    WasmDirect,
    Reject,
}
```

Every native dependency used by a certified build has one strategy. Unknown native dependencies block `contract-verified` promotion until classified.

## 28.3 Rust replacement

A Rust replacement exposes only the application-used API, not necessarily the complete upstream package.

Examples:

| Original dependency | Replacement direction |
|---|---|
| `node-pty` | Windows ConPTY broker |
| `keytar` | Windows Credential Manager broker |
| registry packages | Win32 registry service |
| filesystem watcher binding | IOCP/`ReadDirectoryChangesW` service |
| SQLite binding | Rust SQLite service with compatible calls |
| global shortcut package | shell hotkey service |
| native notification package | shell notification service |
| clipboard module | shell clipboard service |

A replacement includes:

- JavaScript compatibility module;
- typed host RPC schema;
- Rust service;
- error mappings;
- application fixture tests;
- resource/lifetime ownership;
- capability declaration;
- differential trace evidence where possible.

## 28.4 Bun Node-API

A Node-API module MAY run in Bun when:

- the binary architecture matches;
- required dependent DLLs resolve;
- Bun’s implementation supports the used N-API version and behaviors;
- module initialization passes;
- application-specific tests pass;
- crash and unload behavior is acceptable;
- the exact module hash/Bun version combination is certified.

The module runs in the Bun worker process, not the central shell or daemon.

## 28.5 Rebuilt add-on

For source-available native modules, Weregopher MAY produce a build for a supported runtime ABI. The adapter build record includes:

- source repository and commit;
- patch set;
- compiler/toolchain;
- target ABI;
- build flags;
- dependency hashes;
- resulting binary hash;
- license notices.

Rebuilt add-ons are optional adapter components and should not silently replace vendor-signed binaries without clear provenance.

## 28.6 Vendor helper

A vendor helper is an existing EXE/service intended to run outside Electron. It may be retained unchanged when the application contract requires it.

Helper manifest:

```toml
[[helpers]]
id = "codex-app-server"
path = "package:resources/codex.exe"
hash_policy = "build-descriptor"
signer_policy = "same-vendor"
transport = "stdio-jsonl"
job = "app-server"
network = "inherit-adapter-policy"
shutdown = "protocol-then-kill-tree"
```

The supervisor:

- resolves the exact package path;
- verifies fingerprint/signer policy;
- applies Job Object and resource ownership;
- sets explicit environment and working directory;
- controls inherited handles;
- captures stdout/stderr;
- monitors exit/crash;
- performs graceful then forced shutdown;
- records resource use.

## 28.7 ABI island

An ABI island is a minimal helper process containing a matching runtime sufficient to load one native module or bounded module group.

```text
Application QuickJS/Bun runtime
        │ narrow typed RPC
        ▼
weregopher-abi-island.exe
├── matching Node or minimal Electron ABI
├── target native module(s)
├── adapter bridge
├── no application main entry
├── no BrowserWindow
├── no general renderer
└── dedicated Job Object
```

Hard constraints:

- no vendor desktop entry executable;
- no loading the entire app package as main;
- no normal Electron browser/window tree;
- allowlisted module hashes;
- allowlisted exported operations;
- explicit process/network/filesystem capabilities;
- crash does not crash the shell;
- resource cost appears in benchmarks.

An ABI island is a concession to parity, not a loophole to retain Electron wholesale.

## 28.8 Specialized media/overlay helpers

Discord overlay, TIDAL media/DRM, Slack/Discord call engines, and similar components may require specialized processes. The adapter specifies:

- launch conditions;
- package resources;
- surfaces/windows produced;
- message protocol;
- device permissions;
- capture permissions;
- GPU usage;
- shutdown semantics;
- feature exceptions;
- benchmark attribution.

The project must respect licensing and anti-circumvention boundaries. Weregopher does not bypass DRM or alter entitlement checks; it only hosts legitimately installed application components when technically and legally permitted.

## 28.9 DLL search and load policy

Never rely on the process-wide current directory for DLL resolution.

Use:

- absolute module paths;
- `SetDefaultDllDirectories`/safe load flags where compatible;
- explicit dependent DLL directories;
- package-local materialization directory;
- architecture validation;
- signer/hash verification;
- loader diagnostics.

Reject architecture mismatch before attempting load. A helper should not add broad writable directories to DLL search paths.

## 28.10 Native helper protocol

Native helpers use the common runtime protocol or an adapter-defined protocol wrapped by a supervised proxy. The public interface is typed and versioned.

Example ConPTY service:

```rust
trait PtyService {
    fn create(&self, options: PtyOptions) -> Result<PtyHandle>;
    fn write(&self, pty: PtyHandle, bytes: Bytes) -> Result<()>;
    fn resize(&self, pty: PtyHandle, cols: u16, rows: u16) -> Result<()>;
    fn kill(&self, pty: PtyHandle, signal: PtySignal) -> Result<()>;
}
```

## 28.11 Crash and hang policy

A native helper crash produces:

- helper-specific crash artifact;
- owner application/workflow attribution;
- last protocol operations;
- adapter recovery action;
- user-visible failure only if required.

Recovery options:

- restart helper and reconnect;
- restart affected subsystem;
- recreate renderer/window;
- restart application;
- block feature;
- fall back to last-known-good build.

## 28.12 Native component acceptance tests

Each strategy must test:

- clean startup;
- expected API behavior;
- bad input handling;
- process crash;
- process hang;
- abrupt parent exit;
- repeated load/unload;
- architecture variants;
- missing dependent DLL;
- incompatible version;
- capability denial;
- resource cleanup;
- state corruption risk;
- update replacement.

---

# 29. Windows shell implementation

The core shell is Rust using raw Win32/COM APIs, `windows-rs` generated bindings, and DirectComposition where needed. WPF/.NET is not part of the application-host process.

A separate adapter-development GUI or trace viewer MAY use C#/WPF because rapid data-oriented tooling can benefit from it without placing another managed runtime in every hosted application.

## 29.1 Responsibilities

`weregopher-shell.exe` owns:

- process DPI awareness;
- COM/WinRT apartment initialization;
- message loop;
- native windows;
- taskbar identity;
- renderer controllers;
- DirectComposition trees;
- focus/input/IME;
- drag and drop;
- clipboard;
- menus and tray;
- native dialogs;
- notifications;
- accessibility host integration;
- display and theme events;
- renderer event normalization;
- shell-side Electron broker objects.

It does not execute arbitrary adapter-native DLLs in-process.

## 29.2 Threading model

Recommended:

```text
UI thread
  HWND creation, message pump, COM UI objects, renderer controllers

Broker thread pool
  runtime RPC, capability checks, non-UI broker work

I/O completion runtime
  named pipes, streams, file/network/helper supervision

Composition/render helper thread(s)
  only where backend/API requires them
```

UI-thread-affine objects remain on the UI thread. Calls from workers are posted to the UI dispatcher and completed asynchronously or through the bounded synchronous-call lane.

## 29.3 Message loop

The message loop integrates:

- Win32 `GetMessage`/`PeekMessage` dispatch;
- COM message pumping requirements;
- renderer backend callbacks;
- shell task queue;
- modal dialog nested loops;
- graceful shutdown;
- high-resolution timers only when necessary.

The implementation must trace nested loops because they can alter event ordering and deadlock behavior.

## 29.4 Window class and state

```rust
struct NativeWindow {
    hwnd: HWND,
    app: AppInstanceId,
    browser_window: ObjectHandle,
    app_user_model_id: String,
    renderer: Option<RendererHandle>,
    state: WindowState,
    style: WindowStyleState,
    dpi: u32,
    close_protocol: CloseProtocolState,
}
```

Window state transitions are authoritative in the shell. The main runtime receives normalized events.

## 29.5 AppUserModelID and taskbar identity

Standalone mode assigns an application-specific explicit AppUserModelID so windows group under the intended Weregopher application identity rather than one generic shell.

Shared-shell mode can assign per-window AppUserModelIDs where Windows behavior permits; adapter tests must verify taskbar grouping, jump lists, notifications, and activation routing.

The shell manages:

- taskbar progress;
- overlay icons;
- thumbnail toolbar where required;
- badges through supported mechanisms;
- recent items/jump lists;
- activation from notifications and protocols.

## 29.6 DPI and display handling

The process should use Per-Monitor V2 DPI awareness unless a backend constraint requires otherwise.

Required behavior:

- correct initial size in device-independent units;
- `WM_DPICHANGED` handling;
- monitor move/rescale;
- minimum/maximum constraints;
- renderer scale synchronization;
- cursor and hit-test scaling;
- mixed-DPI multiple windows;
- display add/remove/orientation events;
- fractional scaling tests;
- remote desktop and dynamic session changes.

Electron reports bounds in device-independent pixels on Windows; the broker must normalize accordingly.

## 29.7 Frame and titlebar

Window styles include:

- standard framed window;
- frameless window;
- hidden inset/titlebar overlay equivalents where feasible;
- custom draggable regions;
- rounded corners and backdrop policy;
- transparent windows where backend permits;
- always-on-top levels;
- modal child windows.

Draggable regions from renderer CSS (`-webkit-app-region`) need a backend-specific hit-test map. The renderer bridge reports regions after layout; the shell applies `WM_NCHITTEST` behavior.

## 29.8 DirectComposition

DirectComposition is used when required for:

- composition WebView2 controllers;
- transparent/custom surfaces;
- multiple renderer surfaces in one window;
- overlays;
- offscreen or animated native composition;
- specialized vendor surfaces.

The composition tree has explicit ownership and device-loss recovery. GPU/device failures trigger renderer/surface recovery rather than permanent black windows.

## 29.9 Focus and keyboard input

The shell must correctly coordinate:

- top-level window activation;
- renderer focus;
- tab traversal;
- accelerator keys;
- menu shortcuts;
- global shortcuts;
- system commands;
- Alt key/menu behavior;
- dead keys and layouts;
- raw input only where an adapter requires it;
- game/app command buttons;
- accessibility focus.

`before-input-event` requires normalized key data and ordering relative to renderer dispatch.

## 29.10 IME and text services

Test:

- TSF/IME composition;
- CJK input;
- candidate windows;
- emoji panel;
- touch keyboard;
- RTL text;
- high-DPI caret positioning;
- focus changes during composition.

WebView2/CEF provide much of the editing implementation, but custom titlebars, composition controllers, and focus transitions can break IME placement.

## 29.11 Drag and drop

Support:

- files from Explorer into renderer;
- text/URLs;
- virtual files where required;
- drag out from application;
- custom formats;
- security/capability checks before granting filesystem paths;
- correct lifetime of `IDataObject` data;
- cancellation and renderer navigation during drag.

Dropped paths do not automatically bypass filesystem capability policy; the user gesture can produce a scoped grant.

## 29.12 Clipboard

Clipboard operations run on a suitable apartment/thread and handle contention. The shell supports delayed rendering where useful and clears sensitive transient formats according to adapter policy.

## 29.13 Menus and accelerators

Menu models are broker objects. The shell maps them to HMENU or custom UI as required.

Required:

- nested submenus;
- role mappings;
- checked/radio items;
- enabled/visible state updates;
- icons;
- keyboard accelerators;
- context menu coordinates;
- dynamic rebuilds;
- event routing;
- application menu semantics on Windows.

## 29.14 Tray

Tray integration handles:

- icon lifecycle and taskbar recreation;
- tooltip;
- click/double-click/right-click/balloon events;
- context menu;
- DPI-scaled icons;
- Windows Explorer restart;
- multiple app tray icons in shared shell mode.

## 29.15 Dialogs

Use IFileDialog family and TaskDialog/message APIs where appropriate. Preserve:

- sync/async API shape;
- parent modality;
- filters;
- multi-select;
- folders;
- default name/path;
- hidden files;
- overwrite confirmation;
- cancellation result;
- security-scoped grants for selected paths.

A synchronous JavaScript dialog call must not create a host/runtime deadlock. The broker may run a modal UI loop while the worker remains blocked, but must prevent host-to-JavaScript synchronous reentry.

## 29.16 Notifications

Notifications need stable AUMID/application identity and activation routing. The shell stores minimal activation metadata and forwards events to the correct app instance or launches it through the daemon.

Do not place secrets or full arbitrary payloads in activation arguments.

## 29.17 Protocols and file associations

Weregopher MAY register opt-in protocol/file handlers for a supported app. Registration is reversible and preserves original vendor registrations for fallback.

Activation record:

```rust
struct ActivationRequest {
    app_family: ApplicationFamilyId,
    kind: ActivationKind,
    payload: ActivationPayload,
    source_process: Option<u32>,
    received_at: SystemTime,
}
```

Unknown/untrusted URI payloads are parsed and validated before delivery.

## 29.18 Accessibility

The target is parity with the renderer/backend and native controls. Test:

- UI Automation tree;
- accessible names/roles/states;
- focus events;
- screen readers;
- high contrast;
- keyboard-only operation;
- zoom/text scaling;
- native dialog accessibility;
- custom titlebar controls.

A renderer hosted through composition must remain accessible through the backend’s provider chain.

## 29.19 Session and power events

The shell normalizes:

- lock/unlock;
- suspend/resume;
- shutdown/logoff query;
- display changes;
- battery/power mode;
- remote session changes;
- theme/accent changes.

Applications receive compatible `powerMonitor`, `nativeTheme`, and window events where implemented.

## 29.20 Crash handling

The shell installs crash reporting that:

- writes local dumps according to privacy policy;
- records adapter/build/backend identities;
- excludes secrets where possible;
- allows daemon restart;
- restores standalone/shared shell state;
- correlates renderer and worker crashes.

Crash uploads are never automatic unless the user explicitly configures a destination.

---

# 30. Capability and security model

Weregopher executes application package code that was originally granted Electron/Node desktop privileges. The compatibility layer must preserve required behavior without turning every renderer or third-party adapter into an unrestricted host plugin.

## 30.1 Threat model summary

Threat actors and failure sources:

- compromised remote content rendered by an application;
- malicious or compromised application package;
- malicious third-party adapter;
- vulnerable native module/helper;
- cross-application IPC confusion;
- forged handles or pipe clients;
- path traversal and reparse-point attacks;
- stale build/adapter mismatch;
- unsafe state rollback;
- trace leakage;
- denial of service through memory, CPU, handles, messages, or process spawning;
- update supply-chain compromise;
- local same-user process attempting to connect to Weregopher pipes.

The model does not claim to sandbox an application more strongly than its declared capabilities. It does require that one app cannot automatically obtain another app’s capabilities or data.

## 30.2 Trust boundaries

```text
Vendor package code
    ↕ runtime protocol
QuickJS/Bun worker
    ↕ capability broker
Daemon/shell
    ↕ renderer bridge
Packaged renderer content

Third-party adapter WASM
    ↕ constrained WIT interfaces
Adapter host

Native helper / ABI island
    ↕ narrow typed protocol
Helper supervisor

Public adapter registry
    ↕ signature verification
Local adapter store
```

## 30.3 Capability document

```rust
pub struct CapabilitySet {
    pub filesystem: FilesystemCapabilities,
    pub process: ProcessCapabilities,
    pub network: NetworkCapabilities,
    pub registry: RegistryCapabilities,
    pub shell: ShellCapabilities,
    pub devices: DeviceCapabilities,
    pub renderer: RendererCapabilitiesGranted,
    pub secrets: SecretCapabilities,
    pub tracing: TraceCapabilities,
    pub privileged: PrivilegedCapabilities,
}
```

Manifest example:

```toml
[capabilities.filesystem]
read = [
  "${PACKAGE_ROOT}/**",
  "${APP_DATA}/**",
  "${USER_HOME}/Documents/**"
]
write = ["${APP_DATA}/**"]

[capabilities.process]
spawn = [
  "package:resources/codex.exe",
  "package:resources/rg.exe"
]
allow_shell = false

[capabilities.network]
mode = "application-default"

[capabilities.devices]
microphone = "prompt"
camera = "prompt"
screen_capture = "prompt"
```

## 30.4 Capability enforcement

Capabilities are enforced at every broker boundary, not only during adapter installation.

A request includes:

- app/build/adapter identity;
- runtime identity;
- renderer/frame/origin where applicable;
- operation;
- resource target;
- user-activation state;
- declared reason;
- current capability token.

The decision can be:

```rust
enum CapabilityDecision {
    Allow,
    AllowScoped(ScopedGrant),
    Prompt(PromptSpec),
    Deny(DenyReason),
}
```

User-granted scoped paths or devices produce expiring or persisted grants according to policy.

## 30.5 Full-host escape hatch

Some desktop applications effectively require ordinary user-level Node access. The adapter may declare:

```toml
[capabilities]
unsafe_full_user_access = true
reason = "Application requires arbitrary project command execution"
```

Requirements:

- visible warning in adapter metadata and UI;
- signed adapter or explicit local developer mode;
- no implication of sandboxing;
- still isolated from other app profiles/handles;
- process ownership and resource accounting remain active;
- privileged/elevated operations remain separate.

Codex may require broad user-level process/filesystem capabilities depending on approval/sandbox mode, but those must remain aligned with its own user-visible security settings rather than silently bypassed.

## 30.6 Adapter sandbox

Declarative manifests and generated transforms are preferred. General adapter hooks run as WebAssembly components with constrained interfaces.

Adapter WASM does not receive:

- arbitrary filesystem access;
- raw network access;
- Win32 API access;
- process spawning;
- direct shell pointers;
- unrestricted package-state mutation.

Native adapter code runs only in helper processes.

## 30.7 Registry signatures

Public registry adapter bundle:

- content hash;
- publisher key;
- registry inclusion signature;
- manifest and capability digest;
- build provenance;
- license/provenance metadata;
- revocation status.

Verification chain:

```text
trusted registry root
→ publisher key authorization
→ adapter bundle signature
→ content hashes
```

Local developer mode bypasses registry trust only for explicitly selected local adapter paths. It must not silently mark them trusted for other users.

## 30.8 Update security

For vendor package candidates:

- validate expected package family and signer;
- compare signer changes explicitly;
- hash every consumed artifact;
- do not reuse certification across differing native/helper hashes;
- run package parsing in a constrained process where practical;
- reject malformed ASAR/path structures;
- retain last-known-good before promotion.

For Weregopher components:

- signed releases;
- reproducible build metadata where possible;
- dependency lockfiles;
- SBOM;
- advisory monitoring;
- optional component signatures for CEF/Bun/fixed WebView2 artifacts.

## 30.9 Renderer security

- package origins are private and app-specific;
- remote navigation policies are adapter-defined;
- privileged bridge exposure is origin/frame-scoped;
- raw host objects are hidden;
- context isolation is preserved where expected;
- permission requests route through broker policy;
- downloads are capability-checked;
- custom protocols validate paths and MIME types;
- CSP is not weakened unless an adapter explicitly requires it;
- devtools are controlled by policy;
- page content cannot forge authoritative frame identity.

## 30.10 Process security

Worker/helper processes SHOULD receive compatible mitigations:

- DEP/ASLR inherited from modern toolchains;
- restricted handle inheritance;
- child-process Job Objects;
- extension-point disable policy where compatible;
- dynamic-code restrictions only where runtimes permit them;
- CFG where binaries support it;
- low-integrity/AppContainer only for components whose functionality survives it;
- no elevation by default.

Do not apply a mitigation blindly if it breaks WebView2, CEF, Bun, JITs, media codecs, or vendor helpers. Mitigation sets are adapter/component-tested.

## 30.11 Privileged broker

The optional privileged broker exposes a fixed operation enum, not command strings:

```rust
enum PrivilegedOperation {
    InstallWindowsSandboxPrerequisite(InstallSpec),
    ApplyDeclaredAcl(AclSpec),
    RegisterSystemIntegration(RegistrationSpec),
    RemoveSystemIntegration(RegistrationId),
}
```

Requests include signed adapter identity, user consent, exact parameters, and audit record. The broker revalidates all paths and does not trust the unelevated caller’s canonicalization.

## 30.12 Secret handling

Secrets include:

- authentication tokens/cookies;
- API keys;
- MCP credentials;
- environment variables;
- credential-manager values;
- raw trace payloads;
- command output containing secrets.

Policies:

- no raw trace persistence by default;
- structured redaction before writing;
- memory buffers zeroed where practical;
- credential access through narrow broker APIs;
- adapter logs cannot read unrelated app secrets;
- crash dumps are opt-in or locally protected;
- user-visible export lists included sensitive categories before creation.

## 30.13 Audit log

Security-relevant actions:

- adapter install/update/revocation;
- full-host access grant;
- privileged operation;
- unknown package signer;
- capability prompt/decision;
- helper launch;
- ABI island use;
- renderer backend fallback;
- state migration;
- rollback;
- raw trace enablement.

The log is local, bounded, and user-readable.

## 30.14 Security tests

Required test classes:

- cross-app handle forgery;
- pipe impersonation;
- nonce replay;
- malicious frame/origin message;
- navigation race;
- path traversal;
- junction/symlink escape;
- malicious ASAR paths;
- oversized/deep wire values;
- shared-buffer handle forgery;
- adapter WASM escape attempts;
- helper binary replacement;
- signer mismatch;
- capability TOCTOU;
- privileged broker parameter confusion;
- trace-redaction regression;
- state rollback against migrated schema;
- renderer prototype pollution.

---

# 31. State, authentication, migration, and rollback

Package rollback is safe only when persistent state remains compatible. Weregopher models state explicitly and treats state migration as part of build promotion.

## 31.1 State classes

```rust
enum StateClass {
    Authentication,
    BrowserProfile,
    ApplicationSettings,
    WindowState,
    ProjectMetadata,
    UserDocuments,
    ApplicationDatabase,
    ExtensionState,
    PluginState,
    CodexConfiguration,
    ConversationIndex,
    Cache,
    Downloads,
    Logs,
    Ephemeral,
}
```

Each state root has:

- owner;
- source path/store;
- destination path/store;
- schema/version evidence;
- secret classification;
- migration policy;
- backup/checkpoint policy;
- rollback compatibility;
- retention policy.

## 31.2 Profile separation

Weregopher profiles must not silently use the vendor Electron profile directory directly unless an adapter explicitly declares live shared-state safety.

Default:

```text
Vendor install/profile    read-only or migration source
Weregopher app profile        dedicated persistent state
Weregopher browser profile    dedicated WebView2/CEF profile
Snapshots                 immutable package only, not active user state
```

This avoids two runtimes concurrently mutating one Chromium/Electron profile.

## 31.3 Authentication

The locked policy permits one explicit reauthentication. Weregopher therefore does not attempt generic cookie-database copying, DPAPI circumvention, or protected credential extraction.

Adapter options:

```toml
[authentication]
strategy = "reauthenticate"
copy_vendor_cookies = false
copy_protected_tokens = false
preserve_nonsecret_account_hints = true
```

The packaged desktop login flow executes in the selected renderer/backend. Authentication success is stored in Weregopher’s application profile using the application’s own mechanisms where possible.

If a package uses OS credential APIs, the adapter may call Credential Manager under the package’s expected target names only when compatible and permitted.

## 31.4 State manifest

```toml
[[state.roots]]
id = "desktop-settings"
class = "ApplicationSettings"
source = "vendor:${LOCAL_APP_DATA}/OpenAI/..."
destination = "weregopher:${APP_DATA}/settings"
strategy = "transform"
secret = false

[[state.roots]]
id = "authentication"
class = "Authentication"
strategy = "reauthenticate"
secret = true

[[state.roots]]
id = "codex-home"
class = "CodexConfiguration"
source = "host:${USER_HOME}/.codex"
destination = "same"
strategy = "shared-authoritative"
```

`shared-authoritative` means both the vendor and Weregopher intentionally use an external canonical state root. It requires concurrency and locking tests.

## 31.5 State epoch

```rust
struct StateEpoch {
    id: StateEpochId,
    app_family: ApplicationFamilyId,
    schema_fingerprint: Sha256,
    browser_profile_epoch: u64,
    application_state_epoch: u64,
    compatible_readers: BTreeSet<BuildContractId>,
    created_by: BuildFingerprint,
    checkpoint: Option<StateCheckpointId>,
}
```

Every application session binds to a state epoch in its build lease.

## 31.6 Candidate update testing

Before promoting a candidate build:

1. discover state roots touched during oracle/candidate startup;
2. clone or create disposable state where feasible;
3. run migration/startup probes;
4. record schema/filesystem/database changes;
5. run rollback-reader probe using last-known-good build when allowed;
6. classify migration as reversible, checkpoint-restorable, or irreversible;
7. promote package and state policy together.

## 31.7 Checkpoints

Checkpoints may use:

- database-native backup;
- file copy with content deduplication;
- VSS where justified and permitted;
- application export;
- adapter-specific transactional migration;
- browser-profile copy while processes are closed.

A checkpoint is not assumed cheap. Large caches SHOULD be excluded if reproducible; secrets require protected storage.

## 31.8 Rollback matrix

```rust
enum RollbackStatus {
    SafeWithoutStateChange,
    SafeWithCheckpointRestore,
    PackageOnlyUnsafe,
    IrreversibleMigration,
    Unknown,
}
```

The UI/CLI must not offer automatic package rollback when state is known incompatible unless it also restores the correct checkpoint.

## 31.9 Concurrent vendor and Weregopher use

A user may run the original vendor app and Weregopher. Policies:

- separate browser/application profiles by default;
- shared external project/document state only where normal concurrent use is safe;
- detect exclusive database/profile locks;
- warn or refuse concurrent use for unsafe state roots;
- preserve vendor fallback without corrupting state;
- serialize migrations.

## 31.10 Window/session restoration

The shell stores:

- window bounds/display identity;
- maximized/fullscreen state;
- surface/navigation identity;
- application-provided restoration token;
- profile/account;
- package build and state epoch.

Restoration never blindly reloads an old internal URL into an incompatible package build. The adapter validates restoration tokens.

## 31.11 Cache handling

Caches are categorized:

- safe to recreate;
- version-scoped;
- profile-scoped;
- sensitive;
- shared with helper/app-server;
- never snapshot.

Cache deletion is a troubleshooting operation, not routine memory management.

## 31.12 Uninstall and cleanup

Weregopher uninstall must not delete vendor data. App removal offers separate options for:

- Weregopher profile;
- package snapshots;
- adapter overlays;
- trace data;
- checkpoints;
- registry/file/protocol registrations;
- shared UDF profile only;
- shared UDF entirely when no owners remain.

All destructive operations show exact paths/categories and support dry run.


---

# 32. Resource accounting and governance

Resource accounting is part of the runtime architecture. Weregopher owns enough of the process tree to attribute resources more accurately than a generic process monitor and to apply lifecycle controls at meaningful subsystem boundaries.

The design must distinguish private committed memory from resident working set. Windows exposes private commit through `PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`; this is the primary process-memory measure for growth/leak analysis. Working set remains useful for residency and pressure analysis but is not equivalent to live/private allocation.[R25]

## 32.1 Accounting domains

```rust
enum ResourceDomain {
    DaemonShared,
    ShellShared,
    ShellApplication(AppInstanceId),
    Runtime(AppInstanceId),
    Renderer(AppInstanceId, RendererId),
    BrowserShared(RendererEnvironmentId),
    GpuShared(RendererEnvironmentId),
    NetworkShared(RendererEnvironmentId),
    NativeHelper(AppInstanceId, HelperId),
    AbiIsland(AppInstanceId, HelperId),
    ChildProcess(AppInstanceId, ProcessOwner),
}
```

The UI and reports present:

- app-exclusive resources;
- shared Weregopher resources;
- shared renderer infrastructure;
- proportional estimates where useful;
- total machine impact without double counting.

## 32.2 Process ownership

Every spawned process is registered before or immediately after creation:

```rust
struct ProcessRecord {
    pid: u32,
    creation_time: u64,
    image: PathBuf,
    image_hash: Option<Sha256>,
    signer: Option<SignerIdentity>,
    owner_app: Option<AppInstanceId>,
    owner_component: ComponentKind,
    owner_thread: Option<String>,
    owner_turn: Option<String>,
    job: Option<JobId>,
    parent: Option<ProcessIdentity>,
    launch_reason: String,
    started_at: SystemTime,
}
```

PID alone is insufficient because PIDs are reused. Use PID plus creation time/unique process identity.

## 32.3 Metrics

Per process/component:

- private commit/current and peak;
- working set/current and peak;
- private/shared working-set estimates where obtainable;
- CPU time and recent CPU rate;
- handle count;
- thread count;
- GDI/USER objects where applicable;
- I/O bytes/operations;
- network bytes where attribution is available;
- page faults;
- job accounting;
- runtime heap and GC statistics;
- renderer process count;
- child/helper count;
- queue depth;
- startup and shutdown duration;
- crash/hang count.

Per application:

```rust
struct ApplicationResourceSample {
    timestamp: Instant,
    exclusive_private_commit: u64,
    exclusive_working_set: u64,
    shared_browser_private_commit: u64,
    shared_gpu_private_commit: u64,
    estimated_shared_allocation: u64,
    cpu_time_delta: Duration,
    handles: u64,
    threads: u64,
    process_count: u32,
    renderer_count: u32,
    helper_count: u32,
    runtime_heap: Option<u64>,
}
```

## 32.4 Shared-process allocation

Shared browser/GPU/network process memory cannot be truthfully assigned in full to every app.

Report three values:

```text
Exclusive application footprint
Shared infrastructure total
Estimated application share
```

Estimation methods MAY include:

- equal share among active profiles/renderers;
- renderer-count weighted;
- CPU/activity weighted;
- backend-provided process association;
- working-set page analysis where reliable;
- no estimate, only shared total.

The report must identify the method. Product comparisons use machine-wide totals to avoid allocation ambiguity.

## 32.5 Sampling

Default sampling tiers:

```text
Fast:    1 second during startup, active benchmark, or anomaly
Normal:  5 seconds during active use
Idle:   30 seconds when stable/inactive
Event:   immediate on process/window/runtime transitions
```

Sampling overhead is measured and bounded. ETW MAY augment polling for process/thread/I/O events, but is not required for initial correctness.

## 32.6 Baselines

Each adapter/build/workload has a baseline model:

```rust
struct ResourceBaseline {
    build: BuildFingerprint,
    adapter: AdapterVersion,
    renderer: RendererVersion,
    runtime: RuntimeBackendVersion,
    scenario: ScenarioId,
    warmup: Duration,
    expected_plateau: Range<u64>,
    expected_process_range: Range<u32>,
    expected_handle_slope: Range<f64>,
    expected_cpu_idle: Range<f64>,
}
```

A global “Electron app should use under X MB” threshold is not credible.

## 32.7 Growth detection

Probable runaway/leak scoring considers:

- robust slope of private commit;
- repeated increasing high-water marks;
- lack of recovery after idle/GC-safe points;
- handle/thread/process slope;
- renderer churn;
- queue growth;
- helper accumulation;
- state (foreground, active call, build, indexing, download, agent turn);
- system memory pressure;
- adapter-known workload.

```rust
struct GrowthScore {
    memory_slope: f64,
    handle_slope: f64,
    process_slope: f64,
    plateau_breaks: u32,
    idle_persistence: Duration,
    confidence: f32,
    explanation: Vec<GrowthEvidence>,
}
```

The UI says “probable sustained private-memory growth,” not “definite JavaScript memory leak,” unless runtime heap evidence proves it.

## 32.8 Governance actions

Available actions:

- QuickJS heap limit/interruption;
- request QuickJS collection at adapter safe point;
- restart runtime worker;
- restart one renderer;
- unload/recreate a renderer where adapter-safe;
- suspend an inactive renderer where adapter-safe;
- lower process memory priority;
- enable EcoQoS/power throttling for inactive processes;
- cap Job Object CPU or memory in diagnostic/explicit policy mode;
- terminate orphan helpers;
- restart a subsystem;
- restart application when safe;
- notify only.

Hard Job Object memory limits are dangerous because allocations can fail inside arbitrary code. They are advanced opt-in controls, not defaults.

## 32.9 No automatic working-set cleaner

Weregopher does not periodically call `EmptyWorkingSet` or purge global standby lists as a primary optimization. Such operations can lower a displayed residency number while retaining private commit and causing page faults/latency when memory is touched again.

A manual diagnostic trim MAY exist and must be labeled as residency trimming, not leak repair.

## 32.10 Context-aware policy

Application activity model:

```rust
enum ActivityState {
    ForegroundInteractive,
    VisibleBackground,
    HiddenActive,
    AudioPlayback,
    VoiceVideoCall,
    ScreenCapture,
    Downloading,
    Indexing,
    Building,
    AgentRunning,
    Idle,
    Suspended,
}
```

Policies use activity state. Examples:

- do not suspend Slack/Discord during calls;
- do not throttle TIDAL playback;
- do not kill Codex MCP/helper processes while an owning turn is active;
- clean up Codex helpers whose owning thread/turn is definitively closed;
- do not restart VS Code with unsaved editors;
- allow aggressive renderer recreation only after adapter-safe state serialization.

## 32.11 Job Objects

Use Job Objects for owned process trees where compatible:

- aggregate accounting;
- kill-on-job-close;
- active process limits in tests;
- CPU rate controls;
- notifications;
- nested ownership where Windows supports it;
- deterministic child cleanup.

Not every vendor helper tolerates job assignment or lack of breakaway. Adapter tests decide exceptions.

## 32.12 System pressure

The daemon observes system-wide memory pressure and available commit. Policies react to actual pressure, not only fixed free-RAM percentages.

Pressure response MAY:

1. ask inactive QuickJS runtimes to collect;
2. lower memory priority for inactive components;
3. request backend low-memory mode;
4. suspend adapter-safe renderers;
5. unload adapter-safe transient windows;
6. notify about runaway applications;
7. restart an app/subsystem if configured.

## 32.13 Benchmark protocol

A valid vendor-versus-Weregopher benchmark records:

- hardware/firmware;
- Windows build;
- power plan;
- display configuration;
- WebView2/CEF/Electron versions;
- application package fingerprint;
- adapter/runtime versions;
- account/profile;
- open workspaces/documents;
- plugins/extensions;
- active windows;
- media/call state;
- warmup;
- sample interval;
- scenario steps;
- raw and normalized metrics.

Primary comparison:

```text
machine-wide aggregate private commit delta
+ application-owned CPU/process/handle behavior
+ startup/interaction latency
```

Do not compare one app’s sum against another app’s double-counted shared processes.

## 32.14 Efficiency labels

```rust
enum EfficiencyStatus {
    Improved,
    Neutral,
    Regressed,
    Unknown,
}
```

Certification stores evidence and confidence. A functionally stable adapter may be `Regressed`; it simply cannot claim a resource improvement.

---

# 33. Behavioral oracle and differential tracing

The behavioral oracle observes the original vendor application and compares it with Weregopher under equivalent scenarios. It is central to manually supporting proprietary applications whose internal behavior changes frequently.

## 33.1 Oracle principles

- instrument a temporary local copy or development build, never the vendor install in place;
- do not redistribute proprietary assets or traces containing proprietary code/secrets;
- record semantic operations, not just screenshots;
- correlate main, preload, renderer, native, process, filesystem, and UI behavior;
- normalize nondeterminism;
- retain enough causal order to diagnose event-order differences;
- support multiple instrumentation tiers because package integrity may block one approach.

## 33.2 Instrumentation tiers

### Tier 1: source-level

For source-available applications:

- wrap/import-substitute Electron;
- instrument Node module loads;
- build trace-enabled package;
- add source-level probes;
- run fixture scenarios.

### Tier 2: snapshot overlay

For proprietary packages where integrity permits:

- create immutable snapshot;
- add bootstrap through overlay/transformed entry;
- wrap Electron exports;
- wrap IPC registration and sends;
- wrap child-process/native module loading;
- run under matching vendor Electron;
- discard modified runtime package after trace extraction.

### Tier 3: inspector/CDP

When code modification is blocked:

- attach to main-process Node inspector if available;
- attach to renderer CDP;
- observe module/global behavior;
- instrument runtime functions through debugger evaluation where permitted;
- capture network-independent renderer events;
- inspect frames/worlds;
- correlate with external process tracing.

### Tier 4: external observation

- Windows UI Automation;
- ETW/process creation;
- Job/process snapshots;
- filesystem and registry observation;
- window/event hooks limited to the test process;
- accessibility tree snapshots;
- screenshot checkpoints;
- named-pipe/socket endpoint metadata without decrypting protected traffic;
- child-process command lines/environment with secret redaction.

## 33.3 Trace event schema

```rust
struct TraceEvent {
    id: TraceEventId,
    session: TraceSessionId,
    logical_time: LogicalTime,
    wall_time: Option<SystemTime>,
    process: ProcessIdentity,
    thread: Option<u32>,
    app: ApplicationIdentity,
    realm: RealmIdentity,
    category: TraceCategory,
    operation: String,
    phase: TracePhase,
    arguments: Option<WireValue>,
    result: Option<WireValue>,
    error: Option<WireError>,
    causal_parent: Option<TraceEventId>,
    correlation: Option<String>,
    source: Option<SourceLocation>,
    redactions: Vec<RedactionRecord>,
}
```

Categories:

```text
Electron API
Node API
Module resolution
IPC
Context bridge
Window
Renderer
Navigation
Session/network metadata
Filesystem
Registry
Process
Native module
Helper protocol
App-server
MCP
Sandbox
Git/worktree
UI Automation
Accessibility
Resource
State migration
```

## 33.4 Electron instrumentation

Wrap constructors, methods, properties, and event subscriptions:

```javascript
const realElectron = require("electron");
module.exports = traceModule(realElectron, {
  module: "electron",
  objectIdentity: true,
  events: true,
  promises: true,
});
```

Trace:

- call name;
- normalized arguments;
- sync return/Promise resolution;
- thrown/rejected error;
- object handles;
- event listener registration/removal;
- event emissions and ordering;
- callback invocations;
- source call site;
- duration.

Instrumentation must avoid changing object identity/prototype behavior more than necessary. Differential tests should account for instrumentation effects.

## 33.5 IPC graph extraction

Observe:

- `ipcMain.on/once/handle/handleOnce`;
- `ipcMain.remove*`;
- `ipcRenderer.send/sendSync/invoke/postMessage`;
- `webContents.send/postMessage`;
- contextBridge-exposed functions that invoke IPC;
- MessagePort transfer;
- channel payload shapes;
- origin/frame;
- request-response correlations.

Generated graph:

```rust
struct IpcGraph {
    channels: BTreeMap<String, IpcChannel>,
    edges: Vec<IpcEdge>,
}
```

Channel names are opaque unless an adapter maps them to replaced endpoints.

## 33.6 Module/native/process tracing

Trace:

- CommonJS/ESM resolution;
- package entry decisions;
- native `.node` loads;
- DLL loads where observable;
- helper spawns;
- arguments/cwd/environment keys;
- stdio mode;
- process tree;
- exit and orphan behavior.

Secret environment values are redacted; key names may remain if not sensitive.

## 33.7 UI and screenshot traces

Screenshots are supporting evidence, not the sole oracle. Store:

- screenshot at named checkpoint;
- window rectangle/DPI;
- accessibility tree;
- focus element;
- visible window list;
- renderer URL/origin identifier;
- semantic app state.

Visual diffs use masks/tolerances for dynamic content and compare layout regions where applicable.

## 33.8 Normalization

Normalizer replaces nondeterministic values with stable symbols:

```text
PID 21904                 → <PROCESS:main>
HWND 0x000A1234           → <WINDOW:1>
C:\Users\Zeid            → <USER_HOME>
random temp directory     → <TEMP:1>
request UUID              → <REQUEST:7>
timestamp                 → logical sequence/delta
port 53142                 → <PORT:1>
access token              → <REDACTED:token>
```

Normalization is application/build-aware. Over-normalization can hide real incompatibilities, so each rule is auditable.

## 33.9 Semantic diff

Diff levels:

1. exact event match;
2. equivalent event with normalized differences;
3. permitted reordering within a declared partial order;
4. declared exception;
5. incompatibility.

Example partial order:

```text
BrowserWindow.create
  before did-start-loading
  before dom-ready
  before did-finish-load

ready-to-show
  may occur after first paint
  must occur before adapter-triggered show in this build
```

The oracle can express happens-before constraints instead of requiring identical timestamps.

## 33.10 Trace storage

Default trace storage is local and redacted.

Layout:

```text
traces/<session-id>/
├── metadata.cbor
├── events.zst
├── resources.zst
├── ui/
├── screenshots/
├── normalization.toml
├── redaction-report.json
└── summary.md
```

Raw traces require explicit enablement and encryption. Encryption key management must not place the key beside the encrypted file in plaintext.

## 33.11 Oracle reproducibility

An oracle record includes:

- package fingerprint;
- vendor Electron/runtime versions;
- instrumentation revision;
- adapter/test revision;
- Windows build;
- scenario version;
- profile/state fixture;
- environment variables names and redaction status;
- renderer/backend settings;
- trace hash.

## 33.12 Legal/ethical guardrails

The tooling is for local interoperability, testing, and compatibility work. It must not:

- redistribute vendor package contents;
- bypass licensing/entitlement/DRM;
- extract credentials;
- publish proprietary source recovered from packages;
- upload raw proprietary traces automatically;
- disable integrity/security checks in the user’s live install.

---

# 34. Inference-assisted adapter development

Inference is used to accelerate deterministic adapter development. It is not required on the end user’s machine and must not make unreviewed runtime decisions that affect security or data integrity.

## 34.1 Inputs

The adapter synthesis system consumes:

- build descriptor;
- normalized module graph;
- Electron/Node API usage inventory;
- native dependency inventory;
- IPC graph;
- source maps when available;
- selected source/bundle slices;
- vendor oracle trace;
- Weregopher trace;
- semantic diff;
- runtime errors;
- renderer capability matrix;
- existing family adapter;
- prior generated overlays;
- generic compatibility API schemas;
- target application tests;
- license/source-availability metadata.

## 34.2 Outputs

It may propose:

- semantic AST transforms;
- module aliases;
- adapter manifest updates;
- QuickJS Node-module additions;
- Bun routing decisions;
- Electron broker methods/events;
- native replacement schemas;
- helper manifests;
- trace-normalization rules;
- state migrations;
- parity scenarios;
- regression tests;
- diagnosis of unresolved deltas.

All outputs are files in the adapter workspace and pass review/tests before registry publication.

## 34.3 Adapter synthesis loop

```text
Discover candidate
→ analyze package
→ compare to prior build
→ run automatic transforms
→ execute contract probes
→ run oracle/weregopher scenarios
→ compute semantic diff
→ inference proposes bounded patch/test
→ build and rerun
→ human or policy review
→ certify/publish
```

The model receives the smallest relevant context: module neighborhood, failing trace slice, API schema, and existing patterns. Dumping the entire proprietary package into a prompt is neither necessary nor acceptable by default.

## 34.4 Semantic module matching

Inference assists when deterministic matching has ambiguity. Features:

- normalized AST fingerprints;
- import/export graph;
- string constants;
- Electron/Node call signatures;
- IPC channel strings;
- source-map names;
- control-flow shape;
- adjacent module relationships;
- native/helper references.

Output includes confidence and evidence:

```json
{
  "oldModule": "chunk-a:42",
  "newModule": "chunk-f:17",
  "confidence": 0.97,
  "evidence": [
    "same 8 Electron call sites",
    "same 14 IPC channels",
    "normalized AST similarity 0.94",
    "same import neighborhood"
  ]
}
```

Low-confidence matches do not silently apply transforms under `follow-verified`.

## 34.5 Transform generation

Transforms target semantic constructs:

```typescript
export default defineTransform({
  id: "openai-replace-pty-loader",
  appliesTo(ctx) {
    return ctx.module.usesPackage("node-pty") &&
           ctx.module.containsCall("spawn", "codex");
  },
  transform(ast, ctx) {
    return replaceModuleSpecifier(
      ast,
      "node-pty",
      "compat:openai/conpty",
    );
  },
});
```

Generated transforms must:

- be deterministic;
- preserve source maps;
- declare assumptions;
- include a fixture showing the before/after shape;
- fail when the expected match count changes unexpectedly;
- avoid broad text replacement.

## 34.6 Runtime failure diagnosis

A model can classify:

- unsupported Electron method;
- Node error-shape mismatch;
- module resolution mismatch;
- event ordering mismatch;
- renderer world/bridge failure;
- native ABI mismatch;
- state migration issue;
- helper ownership leak;
- WebView2/CEF behavior difference.

It should produce evidence-backed hypotheses and a test that would distinguish them.

## 34.7 Test generation

For every proposed implementation, generate or extend:

- generic conformance fixture;
- application-specific scenario;
- negative/security test;
- update regression test;
- resource-cleanup assertion.

A patch without a reproducing test is not complete unless the limitation is documented.

## 34.8 Model execution environment

Adapter-generation tooling MAY call local or hosted inference providers through a provider abstraction. Requirements:

- explicit user configuration;
- no automatic upload of proprietary package content;
- content classification and redaction;
- local-only mode;
- prompt/artifact audit log;
- deterministic non-inference fallback;
- provider secrets stored securely;
- no inference requirement for application launch.

## 34.9 Confidence gates

```rust
enum SynthesisDisposition {
    AutoApplyInWorkspace,
    RequireReview,
    Reject,
}
```

Auto-application may occur only in a disposable development workspace and only for low-risk generated artifacts. Registry publication and privileged capability changes always require review/signature.

## 34.10 Codex integration for building Weregopher

Because this document is intended for Codex, the repository should include machine-readable work items and architecture constraints:

- `AGENTS.md` at repository root;
- per-crate `AGENTS.md` where constraints differ;
- JSON Schema for manifests/protocols;
- ADR templates;
- executable test commands;
- generated-code boundaries;
- no-network unit-test mode;
- fixture-generation scripts;
- issue templates for compatibility findings.

Section 43 supplies direct instructions.

---

# 35. Testing and certification

Testing operates at unit, property, fuzz, conformance, adapter, end-to-end, differential, security, state, resource, and soak levels.

## 35.1 Test taxonomy

### Unit tests

- parser and VFS behavior;
- path canonicalization;
- module resolution;
- wire codec;
- handle table;
- capability matching;
- fingerprinting;
- transform matching;
- state migration functions.

### Property tests

- serialize/deserialize round trip;
- virtual path normalization invariants;
- Merkle manifest stability;
- reference graph preservation;
- capability subset rules;
- update descriptor diff symmetry where appropriate.

### Fuzz tests

- ASAR parser;
- package manifest parser;
- protocol frame parser;
- wire value codec;
- URL/custom scheme parser;
- adapter archive parser;
- trace normalizer;
- AST transform matcher;
- app-server proxy framing.

### Electron conformance fixtures

Small applications run under reference Electron and Weregopher:

```text
electron-conformance/
  app/
  browser-window/
  web-contents/
  ipc/
  context-bridge/
  session/
  web-request/
  protocol/
  dialog/
  menu/
  tray/
  utility-process/
  native-modules/
```

### Node conformance fixtures

Application-used subsets for:

- event loop;
- CommonJS/ESM;
- buffers;
- streams;
- filesystem;
- watchers;
- child processes;
- HTTP/TLS;
- error shapes;
- process globals;
- worker/message ports.

### Adapter tests

- discovery;
- build matching;
- transforms;
- runtime selection;
- renderer selection;
- native dependency strategies;
- package update delta;
- feature workflows;
- declared exceptions.

### End-to-end tests

Drive the actual packaged renderer and native shell through UI Automation or adapter test hooks.

### Differential tests

Run equivalent scenario under vendor Electron and Weregopher and compare normalized traces.

### Security tests

Defined in Section 30.14.

### Resource/soak tests

Run long-duration workflows and assert bounded memory/handles/processes and correct cleanup.

## 35.2 Test matrix

Dimensions:

```text
Windows build
architecture: x64 / ARM64
runtime: QuickJS / Bun / hybrid
renderer: WebView2 Evergreen / selected fixed versions / CEF
shell: shared / standalone
package mode: live / snapshot
update policy: verified / current / pinned
profile: clean / migrated / populated
application build/channel
```

Not every Cartesian product runs for every commit. Adapters declare mandatory and extended matrices.

## 35.3 Reference Electron matrix

Generic API fixtures SHOULD run against the Electron major versions relevant to target applications. The result is a behavior corpus, not an assumption that one shim exactly matches every release.

```rust
struct ElectronBehaviorProfile {
    electron_version: Version,
    node_version: Version,
    chromium_version: Version,
    fixture_results: Vec<FixtureResult>,
}
```

## 35.4 Contract probes

Fast probes required before `follow-current` or `contract-verified` launch:

- package/signature identity;
- entry point resolution;
- transform match counts;
- module graph load;
- no unknown critical native dependency;
- runtime bootstrap;
- `electron` shim load;
- create/destroy hidden test window or equivalent package bootstrap;
- preload/bridge handshake;
- app-server schema/initialize where applicable;
- state read/migration dry run;
- helper launch/exit;
- no critical security contract regression.

Probes run in a disposable profile/snapshot where state mutation is possible.

## 35.5 Certification classes

### `ExactCertified`

- exact fingerprint;
- full mandatory suite;
- all critical workflows;
- security suite;
- state suite;
- resource scenario suite;
- declared exceptions verified;
- artifacts signed/published.

### `ContractVerified`

- build was previously unknown;
- structural/delta analysis succeeded;
- mandatory contract probes passed;
- no new critical API/native/state/security requirements;
- configured smoke workflows passed.

### `Provisional`

- core launch works;
- incomplete workflow/certification evidence;
- only allowed by user policy;
- visible status and exact gaps.

### `Blocked`

- critical contract/probe failed;
- unknown privileged behavior;
- incompatible state migration;
- unsupported native dependency;
- security/parity failure beyond policy.

## 35.6 Stable adapter gates

A stable family adapter may have exceptions, but must satisfy:

- deterministic package discovery;
- safe unknown-build handling;
- no undisclosed full Electron fallback;
- capability manifest;
- crash isolation policy;
- state/rollback policy;
- mandatory workflow suite;
- helper cleanup;
- trace redaction;
- update policy tests;
- documented source/license/proprietary component status.

## 35.7 Critical blockers

Regardless of declared exceptions, stability is blocked by:

- silent data loss/corruption;
- credential exposure;
- sandbox/approval behavior weaker than shown to user;
- arbitrary cross-app access;
- incorrect command execution target;
- unbounded orphan process accumulation;
- package/adapter mismatch that proceeds silently;
- unsafe irreversible migration without checkpoint/disclosure;
- vendor full Electron process tree hidden as a helper;
- bypass of licensing/DRM/security controls.

## 35.8 Scenario runner

Scenario DSL appears in Appendix C. Runner capabilities:

- launch/stop app;
- select surface/profile/build/runtime/renderer;
- interact through UI Automation;
- invoke adapter test hooks in development mode;
- create fixtures;
- wait on semantic events;
- approve/deny prompts;
- inspect filesystem/process/state;
- take screenshots/accessibility snapshots;
- measure resources;
- compare against oracle.

## 35.9 Flake policy

A test is not “fixed” by arbitrary retry counts. Flake reports include:

- event timeline;
- wait condition;
- process/resource state;
- screenshots/UI tree;
- backend/runtime versions;
- retry history.

Retries may distinguish nondeterminism but cannot convert an unexplained recurring failure into certification.

## 35.10 Soak tests

Minimum long-running classes:

- idle overnight;
- repeated open/close windows;
- repeated login/profile switching;
- repeated renderer crashes;
- repeated worker restarts;
- repeated update candidate evaluation;
- high-volume IPC;
- filesystem watcher storms;
- child-process/MCP lifecycle churn;
- media/call lifecycle where relevant;
- Codex repeated thread/turn/MCP/browser/worktree operations.

Assertions include bounded slopes, not just final absolute values.

## 35.11 Reproducibility bundle

A failed test can export a redacted bundle:

```text
repro/
├── environment.json
├── build-fingerprint.json
├── adapter-lock.json
├── scenario.yaml
├── normalized-trace.zst
├── resource-series.zst
├── screenshots/
├── logs/
├── redaction-report.json
└── replay.md
```

It must not include proprietary package files by default.

## 35.12 CI organization

CI tiers:

- fast portable unit/property tests;
- Windows unit/integration tests;
- WebView2 fixture tests;
- optional CEF tests;
- QuickJS/Bun matrix;
- signed adapter registry validation;
- private/local installed-package certification jobs for proprietary apps;
- source-available adapter jobs in public CI;
- scheduled soak/benchmark jobs.

Proprietary package tests should run on user-controlled or project-controlled machines with licensed installations, not upload packages to public CI.


---

# 36. Codex and unified ChatGPT desktop adapter

The OpenAI adapter targets the complete installed unified ChatGPT desktop package, with Codex as the highest-priority surface and acceptance workload. It must not replace Chat, Work, or Codex with public web pages. It consumes the installed desktop package and transforms and runs its packaged desktop renderer, main/preload logic, helpers, state, and integrations.

Codex’s rapid update cadence is a primary design condition. The adapter is a durable family contract with generated per-build artifacts. It is not a directory of manually authored adapters for every package version.

## 36.1 Scope

Target application family:

```text
openai.chatgpt.windows
├── shared desktop shell/package behavior
├── Chat surface
├── Work surface
└── Codex surface
    ├── app-server
    ├── agent threads/turns/items
    ├── approvals and permissions
    ├── native Windows sandbox
    ├── WSL environments
    ├── MCP servers
    ├── plugins and skills
    ├── worktrees and Git
    ├── scheduled tasks
    ├── built-in browser/computer-use surfaces
    ├── file previews and diffs
    ├── terminal/command execution
    └── helper process lifecycle
```

OpenAI’s Windows documentation identifies native/WSL execution, worktrees, scheduled tasks, Git functionality, an in-app browser, file previews, plugins, and skills as desktop capabilities. These are adapter acceptance surfaces, not optional website substitutions.[R19][R20][R21][R22]

## 36.2 Source and package model

Source availability is component-specific:

- Codex CLI/core and app-server implementation are available in OpenAI’s public Codex repository under Apache-2.0.[R29]
- The installed unified desktop shell/renderer must be treated as package-derived unless the exact component source is publicly released and matched.
- Bundled helper executables are identified and fingerprinted from the installed package.
- The adapter must not assume that a globally installed Codex CLI matches the desktop package.

The scanner is authoritative for:

- package family/version/channel/architecture;
- package signer;
- application resource paths;
- main and preload entry points;
- renderer bundles;
- bundled `codex` executable;
- helper executables and native modules;
- Electron/Chromium/Node versions;
- app-server protocol generation support;
- plugins/skills roots;
- state roots;
- feature flags discoverable without authentication bypass.

No human-entered “current version” is required.

## 36.3 Execution strategy

Default:

```toml
[execution]
mode = "hybrid-preserve-main"
main_runtime_selection = "probe"
main_runtime_preference = ["quickjs", "bun"]
package_logic = "preserve-by-default"
```

Meaning:

- preserve OpenAI’s packaged main-process JavaScript wherever possible;
- replace generic Electron window/session/IPC/native APIs through Weregopher;
- treat internal channel names and payloads as opaque by default;
- intercept only native boundaries Weregopher must own or supervise;
- run the exact bundled app-server/helper binaries;
- generate adapter deltas automatically for changed package structure;
- route newly used Node behavior to Bun before requiring a QuickJS implementation when policy permits.

A full handwritten Rust reimplementation of the desktop main process is explicitly rejected as the default because it would couple Weregopher to every OpenAI UI and protocol change.

## 36.4 Proposed topology

```text
Installed/snapshotted ChatGPT package
├── packaged main-process JS
├── packaged preload JS
├── packaged renderer assets
├── native modules
├── bundled codex executable
├── sandbox/setup helpers
├── command/browser/terminal helpers
├── bundled plugins/skills/resources
└── desktop state schema
             │
             ▼
OpenAI family adapter
├── Weregopher Win32 shell
│   ├── packaged Chat renderer window(s)
│   ├── packaged Work renderer window(s)
│   ├── packaged Codex renderer window(s)
│   └── native dialogs/tray/notifications/protocols
├── QuickJS or Bun main runtime
│   └── preserved/transformed packaged main JS
├── generic Electron IPC/object broker
├── OpenAI native-boundary shims
├── Codex app-server supervisor/proxy
├── MCP/helper process ownership service
├── Windows sandbox/WSL integration broker
├── worktree/Git/browser/preview integration
└── state/update/certification manager
```

## 36.5 Family adapter layout

```text
adapters/openai-chatgpt/
├── family.toml
├── contracts/
│   ├── package.contract.toml
│   ├── electron.contract.toml
│   ├── renderer.contract.toml
│   ├── state.contract.toml
│   ├── app-server.contract.toml
│   └── security.contract.toml
├── shared/
│   ├── transforms/
│   ├── modules/
│   ├── preload/
│   ├── state/
│   ├── shell/
│   └── tests/
├── surfaces/
│   ├── chat/
│   │   ├── tests/
│   │   └── exceptions.toml
│   ├── work/
│   │   ├── tests/
│   │   └── exceptions.toml
│   └── codex/
│       ├── app-server/
│       ├── mcp/
│       ├── sandbox/
│       ├── worktrees/
│       ├── git/
│       ├── terminal/
│       ├── browser/
│       ├── plugins/
│       ├── tests/
│       └── exceptions.toml
├── generated/
│   └── <build-fingerprint>/
│       ├── build-descriptor.cbor
│       ├── semantic-delta.json
│       ├── app-server-schema/
│       ├── transformed/
│       ├── probes/
│       └── certification.json
└── oracle/
    ├── scenarios/
    └── normalizers/
```

Generated build directories need not be committed to the main repository when they contain proprietary-derived metadata unsuitable for publication. The registry may distribute non-proprietary descriptors, transforms, and certification records while requiring users to generate package-specific indexes locally.

## 36.6 OpenAI package contract

The family package contract locates components through semantic rules, not fixed filenames alone.

```rust
struct OpenAiPackageContract {
    package_identity: PackageIdentityRule,
    desktop_entry: EntryPointLocator,
    preloads: Vec<PreloadLocator>,
    renderer_roots: Vec<RendererRootLocator>,
    codex_binary: BinaryLocator,
    helper_classifiers: Vec<HelperClassifier>,
    plugin_roots: Vec<PathLocator>,
    state_roots: Vec<StateRootLocator>,
}
```

Locator evidence can include:

- package manifest role;
- executable metadata;
- embedded strings/subcommands;
- source-map/module graph;
- spawn call sites;
- app-server `--help`/schema-generation probes;
- signer/relative path;
- normalized binary behavior;
- prior-build semantic match.

A changed filename does not automatically break the contract. A changed signer, missing app-server handshake, unknown privileged helper, or changed state root may.

## 36.7 Preserved main-process logic

The main-process package is loaded under QuickJS when the used Node/Electron surface passes probes; otherwise Bun is tried.

The adapter transforms only necessary boundaries:

```text
require("electron")             → Weregopher Electron shim
native module loader            → strategy-specific adapter module
spawn bundled codex/helper      → supervised spawn wrapper
package path assumptions        → ASAR/VFS-compatible paths
updater ownership               → Weregopher update bridge
crash reporter                  → local Weregopher diagnostics bridge
unsupported renderer switches   → backend policy/transform
```

Everything else remains vendor logic.

This is essential for high update tolerance. New internal channels, UI features, feature flags, and app-server calls continue to run through OpenAI’s own package code unless they cross a replaced boundary.

## 36.8 Opaque IPC preservation

The generic Electron broker supports arbitrary channel strings:

```text
ipcMain.on(channel, handler)
ipcMain.handle(channel, handler)
ipcRenderer.send(channel, payload)
ipcRenderer.invoke(channel, payload)
webContents.send(channel, payload)
```

Weregopher does not require an adapter entry for every OpenAI IPC channel.

Channel-specific mappings exist only when:

- native shell owns the operation;
- Weregopher replaces a native module;
- Weregopher supervises a helper;
- a security/capability boundary requires inspection;
- a build compatibility transform is necessary;
- tracing/testing needs semantic labeling.

```rust
enum OpenAiChannelBackend {
    OpaqueMainRuntime,
    ElectronBroker,
    AppServerProxy,
    NativeShell,
    NativeHelper,
    AdapterImplementation,
    Blocked,
}
```

Unknown channels route through `OpaqueMainRuntime` by default. Payloads use the generic wire codec and are not schema-rejected merely because a build is new.

## 36.9 App-server boundary

OpenAI documents app-server as a bidirectional JSON-RPC-like protocol. The default transport is newline-delimited JSON over stdio. A client sends `initialize`, receives an initialization response, then sends `initialized`; messages before initialization are rejected. The binary can generate exact-version TypeScript and JSON Schema definitions.[R18]

Weregopher uses the exact bundled binary:

```text
Packaged OpenAI main logic
       │ original app-server protocol
       ▼
Weregopher app-server supervisor/proxy
       │ transparent JSONL by default
       ▼
Bundled codex app-server
```

Do not substitute a globally installed CLI unless an adapter/user explicitly selects and certifies that mode.

## 36.10 App-server discovery and schema generation

Candidate ingestion:

```text
Locate bundled codex executable
→ fingerprint binary/signer/version
→ run non-mutating capability/help probe
→ generate TypeScript schema if supported
→ generate JSON Schema if supported
→ hash generated artifacts
→ run initialize/initialized handshake in disposable environment
→ record supported methods/notifications/features
```

Artifacts:

```text
generated/<fingerprint>/app-server-schema/
├── raw-typescript/
├── raw-json-schema/
├── normalized-schema.json
├── generated-rust/
├── capabilities.json
├── protocol-hash.txt
└── probe-transcript.redacted.jsonl
```

Generated Rust types must use forward-compatible field handling:

- preserve unknown fields in pass-through paths;
- use tagged known variants plus unknown variants;
- do not reject a new notification merely because the typed observer does not know it;
- validate only where Weregopher actively interprets or transforms semantics.

## 36.11 Transparent app-server proxy

Default behavior:

```text
unknown request method       pass through
unknown notification method  pass through
unknown object field         preserve
new result variant           preserve as generic JSON
```

The proxy owns:

- process lifetime;
- stdio/WebSocket framing;
- request correlation observation;
- backpressure;
- trace redaction;
- helper/MCP ownership correlation;
- selective interception;
- crash/restart state;
- protocol-version evidence.

The proxy does not become a brittle handwritten implementation of every app-server method.

## 36.12 Proxy interface

```rust
trait AppServerProxy {
    fn start(&mut self, spec: AppServerLaunchSpec) -> Result<AppServerSession>;
    fn send_client_message(&mut self, message: JsonValue) -> Result<()>;
    fn next_server_message(&mut self) -> Result<JsonValue>;
    fn register_observer(&mut self, observer: Arc<dyn AppServerObserver>);
    fn register_interceptor(&mut self, interceptor: Arc<dyn AppServerInterceptor>);
    fn diagnostics(&self) -> AppServerDiagnostics;
    fn shutdown(&mut self, mode: ShutdownMode) -> Result<()>;
}
```

Interceptor modes:

```rust
enum InterceptMode {
    Observe,
    Validate,
    Transform,
    Replace,
    Block,
}
```

Manifest:

```toml
[[codex.app_server.intercepts]]
method = "thread/start"
mode = "observe"

[[codex.app_server.intercepts]]
method_pattern = "*/command*"
mode = "observe-process-ownership"

[[codex.app_server.intercepts]]
method = "legacy/method"
mode = "transform"
transform = "transforms/legacy-method.wasm"
```

## 36.13 Backpressure

App-server documentation describes bounded queues for at least its experimental WebSocket transport and overload behavior.[R18] Weregopher applies bounded queues to all transports.

```rust
struct AppServerQueuePolicy {
    max_outbound_messages: usize,
    max_outbound_bytes: usize,
    max_inbound_messages: usize,
    max_inbound_bytes: usize,
    notification_drop_policy: NotificationDropPolicy,
    request_deadline: Duration,
}
```

Never drop requests/responses silently. Low-priority telemetry notifications may be coalesced only when semantics permit and the policy is explicit.

## 36.14 Threads, turns, and items

The proxy observer derives ownership without hard-coding the entire UI:

```rust
struct CodexExecutionIdentity {
    thread_id: Option<String>,
    turn_id: Option<String>,
    item_id: Option<String>,
}
```

This identity is attached to:

- helper launches;
- MCP processes;
- command processes;
- worktrees;
- browser sessions;
- resource samples;
- approval requests;
- trace events.

When a turn/thread completes or is cancelled, the ownership service can determine which transient processes should terminate and which app-scoped processes remain.

## 36.15 Approval and permission semantics

Approval requests are security-critical. Weregopher must preserve OpenAI’s exact user-visible decision semantics and never silently grant more access.

```rust
enum CodexApprovalKind {
    CommandExecution,
    FileChange,
    Permission,
    McpElicitation,
    ToolInput,
    Network,
    Other(String),
}

struct CodexApprovalRequest {
    identity: CodexExecutionIdentity,
    request_id: String,
    kind: CodexApprovalKind,
    payload: JsonValue,
    allowed_decisions: Vec<String>,
    expires: Option<Instant>,
}
```

Requirements:

- preserve request identity and causal turn;
- preserve exact allowed decisions;
- distinguish one-time/session/persistent decisions where protocol provides them;
- handle cancellation/automatic resolution;
- do not reorder concurrent approvals incorrectly;
- ensure the response goes to the correct app-server session;
- display sandbox/permission mode accurately;
- record redacted audit evidence;
- block stable certification if semantics differ materially.

## 36.16 Sandbox integration

OpenAI documents native Windows sandbox modes and WSL2 operation.[R19][R20]

Weregopher should preserve and supervise the package’s sandbox implementation rather than independently inventing weaker semantics.

Responsibilities:

- surface package-defined sandbox options;
- launch exact sandbox/setup helpers;
- route required privileged setup through Weregopher’s explicit privileged broker only where compatible;
- preserve workspace roots and access modes;
- preserve network policy;
- preserve approval policy;
- preserve trusted-project behavior;
- preserve native Windows versus WSL environment selection;
- record helper/process ownership;
- test actual denied/allowed operations.

Security rule:

> The Weregopher UI must never display a sandbox or approval mode stronger than the actual process isolation and access policy being applied.

A mismatch is a critical certification blocker.

## 36.17 WSL

WSL workflows require:

- distribution discovery;
- path mapping between Windows and Linux;
- working-directory semantics;
- environment variables;
- shell/command invocation;
- app-server/helper placement as required by package behavior;
- file watching and Git behavior;
- terminal transport;
- process ownership across `wsl.exe` and Linux process boundaries;
- cleanup;
- URI/editor/open-file routing back to Windows.

Resource accounting can attribute the Windows WSL launcher and, where available, relevant WSL VM/process activity separately. It must not pretend Linux child attribution is exact when the data source cannot prove it.

## 36.18 MCP servers

MCP support includes:

- stdio MCP servers, including Node-based servers;
- HTTP/remote MCP servers;
- bundled plugin MCP servers;
- app-scoped and thread/turn-scoped lifecycle;
- startup state and errors;
- environment/cwd;
- authentication;
- resources/tools/prompts/elicitation;
- reload/configuration changes;
- process cleanup.

Node-based MCP servers remain normal child processes or adapter-declared runtimes. They do not need to run inside QuickJS.

Ownership model:

```text
OpenAI app instance
└── app-server session
    ├── app-scoped MCP group
    ├── thread A MCP group
    │   └── turn A.1 transient tools
    ├── thread B MCP group
    └── remote MCP connections
```

Process cleanup tests must prove that repeated thread creation/cancellation does not accumulate stale MCP processes.

## 36.19 Plugins and skills

OpenAI’s plugin documentation describes plugins that may include skills, connectors/MCP, browser extensions, hooks, and scheduled templates.[R22]

The adapter must preserve package plugin discovery and loading. It should not hard-code known plugin names.

Plugin descriptor inventory:

```rust
struct OpenAiPluginDescriptor {
    id: String,
    root: PathBuf,
    manifest_hash: Sha256,
    capabilities: Vec<String>,
    mcp_servers: Vec<McpDescriptor>,
    skills: Vec<SkillDescriptor>,
    browser_extensions: Vec<BrowserExtensionDescriptor>,
    hooks: Vec<HookDescriptor>,
}
```

Renderer choice may be affected by browser-extension requirements. WebView2 limitations can route a build/plugin combination to CEF or specialized surfaces.

## 36.20 Worktrees and Git

OpenAI documents worktree workflows for parallel isolated changes.[R21]

Adapter requirements:

- use package/app-server-defined worktree behavior;
- preserve repository identity;
- preserve branch/base selection;
- correctly attribute worktree paths to threads;
- show Git status/diffs;
- support handoff/apply behavior;
- clean up only according to package policy;
- never delete a worktree with uncommitted work without explicit semantics;
- handle long paths and Windows filesystem rules;
- support WSL repositories where package does;
- supervise Git/helper processes.

Git credentials and signing should use the same mechanisms the package expects or an explicit adapter replacement.

## 36.21 Terminal and command execution

Terminal support likely requires ConPTY/native helpers. The adapter must preserve:

- shell selection;
- cwd/environment;
- interactive input;
- resize;
- ANSI/Unicode;
- cancellation;
- exit code;
- command approval association;
- sandbox/WSL routing;
- process tree ownership;
- terminal restoration where supported.

A command process is tagged with thread/turn/item and approval identity when available.

## 36.22 Built-in browser and computer-use surfaces

The Windows app documentation includes an in-app browser workflow.[R19] The adapter must preserve the packaged desktop browser/computer-use behavior.

This may involve:

- a dedicated WebView2/CEF renderer;
- CDP integration;
- screenshots;
- DOM snapshots;
- navigation and permissions;
- browser extension/plugin integration;
- sandboxed browser helper;
- download/upload/file chooser;
- process/session cleanup.

It is not replaced with an external browser unless the original desktop package explicitly requests that behavior.

## 36.23 File previews, diffs, and editors

Preserve:

- packaged preview renderer;
- syntax/diff components;
- binary/image preview;
- line comments/review metadata;
- apply/reject change operations;
- filesystem updates;
- conflict behavior;
- opening in external editor;
- large-file behavior;
- renderer crash recovery.

File changes must remain causally associated with agent turns and approvals where package semantics provide that information.

## 36.24 Scheduled tasks

Scheduled tasks are part of the target surface.[R19][R22]

Requirements:

- package-defined schedule semantics;
- task creation/update/delete behavior;
- credentials and environment;
- project/worktree roots;
- notification/result delivery;
- machine sleep/restart behavior;
- overlapping run policy;
- helper/MCP cleanup;
- resource accounting;
- update compatibility.

Do not implement Windows Task Scheduler integration unless the package actually uses or requires it; preserve the packaged mechanism first.

## 36.25 Authentication and profile

The adapter accepts one reauthentication. It creates a dedicated Weregopher browser/application profile and runs the packaged login flow.

Do not generic-copy:

- Electron cookie databases;
- encrypted tokens;
- DPAPI-protected blobs;
- vendor credential stores.

Migrate only understood non-secret state, such as:

- window layout;
- recent project hints;
- selected settings;
- UI preferences;
- package-compatible Codex configuration roots.

If the package shares `.codex` configuration/history with CLI/IDE, the adapter treats that path as an explicit external authoritative root only after verifying package behavior and concurrency.[R28]

## 36.26 Updater interception

The package’s updater must not overwrite the active build lease or launch the vendor Electron app unexpectedly.

Strategies:

- allow vendor update installation but route detection through `PackageCatalog`/scanner;
- intercept package main-process updater calls and report Weregopher-managed state;
- preserve update UI/status if it can reflect actual candidate state;
- disable only the launch/restart behavior that would invoke vendor Electron;
- keep original vendor update mechanism available outside Weregopher;
- never patch update binaries in place.

The user can select:

```text
FollowVerified
FollowCurrent
Pinned
```

## 36.27 Rapid-update algorithm

For every detected OpenAI package candidate:

```text
1. Verify package family, signer, architecture.
2. Create a build lease or immutable candidate snapshot.
3. Generate package/module/native/helper descriptor.
4. Locate and probe exact bundled Codex binary.
5. Generate app-server schema/types.
6. Compare package modules semantically with last known compatible build.
7. Rebind existing transforms and aliases.
8. Inventory new Electron/Node/native/helper use.
9. Probe QuickJS main bootstrap.
10. If QuickJS fails a compatibility requirement, probe Bun.
11. Probe renderer/preload bridge under preferred backend.
12. Probe app-server initialize/initialized.
13. Run state migration dry run.
14. Run OpenAI mandatory smoke scenarios.
15. Classify ExactCertified/ContractVerified/Provisional/Blocked.
16. Promote according to policy or retain last known good.
```

No human action is required when all contracts pass.

## 36.28 OpenAI build contracts

### Package contract

- expected signer/package family;
- main/preload/renderer roots found;
- bundled Codex binary found and executable;
- known helper classes or safely unprivileged unknowns;
- no malformed package paths;
- package origin serves required assets.

### Main runtime contract

- module graph resolves;
- Electron imports map;
- used Node APIs are supported/routed;
- no unknown native module without strategy;
- application reaches ready state;
- internal IPC registrations succeed.

### Renderer contract

- preload executes;
- context bridge exports appear;
- packaged renderer loads;
- main navigation and shell bootstrap complete;
- mandatory surface selectors/semantic test hooks are available;
- no critical renderer capability missing.

### App-server contract

- schema generation or compatible introspection succeeds;
- handshake succeeds;
- unknown methods can pass through;
- required smoke requests work;
- process ownership events can be correlated sufficiently;
- shutdown is clean.

### State contract

- profile opens;
- login flow works or existing Weregopher auth remains valid;
- project/config roots resolve;
- candidate does not irreversibly corrupt current state without checkpoint;
- last-known-good rollback status is known.

### Security contract

- approval/sandbox modes display accurately;
- capability requests route correctly;
- helper executables match expected identity;
- no cross-app profile access;
- no critical trace secret leakage;
- no unknown elevated operation.

## 36.29 Runtime selection for OpenAI builds

```rust
fn choose_openai_runtime(candidate: &BuildDescriptor) -> RuntimeChoice {
    if quickjs_contract(candidate).passes() {
        RuntimeChoice::QuickJs
    } else if bun_contract(candidate).passes() {
        RuntimeChoice::Bun
    } else if hybrid_contract(candidate).passes() {
        RuntimeChoice::QuickJsWithBunServices
    } else {
        RuntimeChoice::Blocked
    }
}
```

QuickJS remains the optimization target. Bun is the immediate compatibility shield for new ordinary Node usage. ABI islands are for bounded native dependencies only.

## 36.30 Renderer selection for OpenAI builds

Preferred:

```text
WebView2
```

Fallback:

```text
CEF
```

Specialized:

```text
package/browser/computer-use or other vendor-specific surface
```

The adapter runs feature probes for:

- context isolation/preload;
- request/session behavior;
- browser/computer-use integration;
- plugin browser extensions;
- file previews;
- media/capture if used;
- authentication flow;
- renderer command-line assumptions.

## 36.31 Process ownership model

```text
App instance Job
├── main runtime worker
├── shell-associated helpers
├── app-server Job
│   ├── app-scoped MCP Job
│   ├── thread A Job
│   │   ├── turn A.1 command Job
│   │   ├── turn A.1 MCP/tool helpers
│   │   └── browser/terminal helpers
│   ├── thread B Job
│   └── sandbox/setup helpers
├── plugin helpers
├── browser/computer-use helpers
└── ABI islands
```

Not every process can necessarily be nested exactly this way due to application behavior/Windows Job constraints. The logical ownership graph remains even when physical job hierarchy differs.

## 36.32 Orphan detection

A process is a probable orphan when:

- its owning app-server session ended;
- owning thread/turn/item is terminal;
- no live protocol stream references it;
- grace period elapsed;
- adapter declares it transient;
- it is not an intentionally app-scoped MCP/helper.

Cleanup:

1. protocol shutdown if available;
2. close stdin/control handle;
3. send termination request;
4. terminate process tree after grace;
5. record cleanup result;
6. flag repeated failure as adapter defect.

## 36.33 OpenAI adapter test suite

### Launch and authentication

- clean-profile launch;
- existing Weregopher profile launch;
- one-time reauthentication;
- logout/login;
- token expiration;
- multiple windows;
- notification/protocol activation;
- vendor update while running.

### Chat

- open Chat surface;
- create/resume conversation as package supports;
- attachments/file picker;
- rendering and navigation;
- desktop notifications;
- packaged desktop-only integrations discovered by oracle.

### Work

- open Work surface;
- create/open supported work artifacts;
- file/site/editor interactions present in package;
- navigation across surfaces;
- persistence/restoration;
- declared exceptions verified.

### Codex core

- open local project;
- start thread;
- resume/fork/archive where supported;
- start/stop/cancel turn;
- streaming output;
- model/reasoning settings;
- approval flows;
- apply/reject changes;
- diff/file preview;
- open in editor;
- crash recovery.

### MCP/plugins/skills

- stdio Node MCP;
- remote MCP;
- failed MCP startup;
- reload configuration;
- app-scoped/thread-scoped cleanup;
- plugin discovery;
- skill invocation;
- browser extension integration where present;
- no orphan process accumulation.

### Sandboxes/environments

- native Windows sandbox modes;
- setup/repair flow;
- WSL environment;
- workspace roots;
- denied path/network access;
- full-access mode with accurate warning;
- approval behavior per mode.

### Git/worktrees

- clean/dirty repo;
- create parallel worktrees;
- branch/status/diff;
- handoff/apply;
- conflict;
- cleanup refusal with uncommitted changes;
- WSL repo where supported.

### Terminal/browser/scheduled

- ConPTY lifecycle;
- resize/input/output/cancel;
- built-in browser navigation and screenshot/DOM flow where used;
- file upload/download;
- scheduled task create/run/overlap/restart;
- sleep/resume behavior.

### Resource/soak

- hundreds of thread/turn cycles;
- repeated MCP starts/stops;
- repeated browser surface create/destroy;
- repeated worktree create/cleanup;
- app-server restart;
- main runtime restart;
- renderer crash recovery;
- overnight idle;
- frequent candidate update ingestion;
- bounded private commit/handles/processes.

## 36.34 Mandatory smoke suite for `ContractVerified`

The fast suite should complete without relying on external destructive actions:

1. package/main/preload discovery;
2. hidden or disposable-profile shell bootstrap;
3. packaged renderer load to ready state;
4. app-server schema generation;
5. app-server initialize/initialized;
6. create/list a disposable thread or equivalent non-destructive protocol probe where supported;
7. start and terminate one benign helper/MCP fixture;
8. native sandbox capability/status probe without changing system configuration;
9. state open/close and rollback check;
10. clean process-tree shutdown;
11. no critical trace/security finding.

Authenticated network-dependent probes may be separated from offline structural probes. `FollowCurrent` policy can define what evidence is required before first interactive launch.

## 36.35 Declared exceptions

Because stable-with-exceptions is allowed, the OpenAI adapter can declare a specific missing feature:

```toml
[[compatibility.exceptions]]
id = "openai-work-example"
surface = "work"
feature = "specific packaged desktop feature"
severity = "major"
behavior = "Exact missing or changed behavior"
workaround = "None"
affects_build_contract = ">=..."
```

It may not use a generic statement such as “some features may not work.”

Critical exceptions that block stable status include:

- incorrect approvals;
- weaker sandbox than displayed;
- wrong working directory/repository;
- command execution under wrong environment;
- lost or corrupted changes;
- credential leakage;
- uncontrolled helper/MCP accumulation;
- incorrect state migration;
- inability to distinguish full access from sandboxed execution.

## 36.36 OpenAI efficiency criteria

For an optimized OpenAI adapter:

- vendor ChatGPT Electron entry executable is not running;
- vendor full Electron browser process tree is not running;
- packaged renderer is hosted by selected Weregopher renderer;
- packaged main logic runs under QuickJS/Bun rather than vendor Electron main;
- app-server and necessary helpers are allowed and counted;
- browser/computer-use helpers and MCPs are counted by owner;
- aggregate private commit is measured against the exact vendor package under equivalent workload;
- frequent-update verification overhead is excluded from steady-state app usage but reported separately.

A build that requires a large ABI island or CEF may still be functionally supported even when resource improvement is neutral. The evidence decides the label.

## 36.37 OpenAI adapter maintenance workflow

Normal update:

```text
Package detected
→ descriptor/schema generated
→ semantic delta mostly unchanged
→ transforms rebind
→ QuickJS/WebView2 probes pass
→ smoke suite passes
→ ContractVerified
→ user receives current build under policy
```

Compatibility delta:

```text
New Node API or renderer requirement
→ QuickJS probe fails
→ Bun or CEF probe passes
→ generated policy overlay selects fallback
→ smoke suite passes
→ ContractVerified with changed backend
```

Manual work:

```text
New native module/security/state boundary
→ candidate Blocked or Provisional
→ oracle trace + inference-assisted diagnosis
→ adapter/native implementation + tests
→ certification
```

This is how the design remains viable when the package updates multiple times per day.


---

# 37. Other target application profiles

These profiles define likely adapter boundaries and acceptance surfaces. They are not implementation order recommendations, and they do not use public web clients. Each profile begins with installed-package discovery and exact-build analysis.

## 37.1 Discord

### Source/package position

Treat the desktop package as proprietary/package-derived unless a specific component is published under a usable license. Discover stable/PTB/Canary independently; channel and installed package fingerprint are authoritative.

### Preferred execution

```toml
[execution]
main = "bun-or-hybrid"
renderer = "webview2-or-cef"
native = "vendor-helpers-and-specialized-surfaces"
```

Bun is the likely default main runtime because Discord’s module loader, updater, and native package ecosystem may rely on broad Node behavior.

### Required desktop behavior

- account/profile/authentication;
- voice and video;
- screen/game streaming;
- audio input/output selection;
- noise suppression/processing;
- global shortcuts and push-to-talk;
- game detection and rich presence;
- activities;
- notifications/tray;
- protocol activation;
- updater/module delivery behavior;
- in-game overlay where supported;
- native crash/recovery behavior;
- local settings/cache migration.

### Likely hard boundaries

- proprietary voice/media native modules;
- screen/game capture;
- overlay injection/composition;
- update-delivered native modules;
- Chromium media/WebRTC assumptions;
- game-process interaction.

### Strategy

- preserve main logic under Bun;
- host packaged renderer under WebView2 if all media/protocol probes pass, otherwise CEF;
- preserve voice/media engine as narrow vendor helper or ABI island;
- model overlay as specialized component with separate certification and resource label;
- treat downloaded native modules as build/runtime dependencies with hashes;
- use generic opaque IPC.

### Critical tests

- join/leave voice repeatedly;
- switch audio devices;
- stream screen/game;
- lose/recover device;
- suspend/resume/lock;
- overlay activation and cleanup;
- repeated channel/server switching;
- renderer/voice helper crash recovery;
- no stale capture/audio/helper processes;
- stable idle and call resource profiles.

## 37.2 GitHub Desktop

GitHub Desktop is source-available under MIT and is an excellent source-port/reference adapter candidate.[R31]

### Preferred execution

```toml
[execution]
mode = "source-port"
main = "quickjs-or-native-rust"
renderer = "webview2"
```

A source port may replace more Electron-specific code directly while preserving the React/desktop UI and application logic.

### Required behavior

- repository discovery and management;
- bundled/system Git behavior;
- credential manager and authentication;
- clone/fetch/pull/push;
- branch and worktree behavior;
- commit/diff/history;
- merge/rebase/conflict workflows;
- shell/editor integration;
- protocol/deep links;
- Git LFS/submodules where supported;
- Copilot/native components present in the installed build;
- update/migration behavior;
- file watching.

### Likely hard boundaries

- native credential integration;
- Git process lifecycle and askpass;
- bundled Git paths;
- Microsoft/GitHub authentication flows;
- any native Copilot runtime included by current builds;
- shell integration registration.

### Strategy

- compile source against a Weregopher compatibility SDK where practical;
- preserve installed-distribution overlays for package-specific assets/features;
- supervise Git/askpass/credential helpers;
- implement credential manager in Rust or preserve vendor helper;
- use exact behavior fixtures from public source and packaged build.

### Critical tests

- auth and credential prompts;
- clone/push/private repos;
- long paths and Unicode;
- submodules/LFS;
- conflict resolution;
- external editor/shell;
- abrupt Git child exit;
- repeated repository open/close;
- no credential leakage in traces.

## 37.3 Notion

### Source/package position

Treat the desktop shell as proprietary/package-derived. The installed MSIX/direct package and its renderer/preloads are authoritative.

### Preferred execution

```toml
[execution]
main = "bun"
renderer = "webview2"
package = "live-if-msix-contract-safe-else-snapshot"
```

### Required behavior

- packaged desktop UI;
- offline/local cache behavior;
- multiple windows/tabs;
- profile/account behavior;
- command search/global shortcuts;
- notifications;
- deep links;
- file uploads/downloads;
- audio/meeting features present in package;
- local database/cache migration;
- MSIX activation/update behavior;
- restore windows/tabs.

### Likely hard boundaries

- offline database/cache;
- background sync;
- authentication/profile migration;
- global shortcut/window activation;
- capture/audio features;
- package-specific native modules.

### Critical tests

- offline edit/reconnect;
- conflict/recovery behavior;
- multiple windows and profile restoration;
- large workspace navigation;
- login/reauth;
- update while running;
- cache/state rollback;
- repeated sleep/resume.

## 37.4 Obsidian

Obsidian’s desktop package is proprietary/package-derived; its plugin ecosystem makes compatibility broader than the core application.

### Preferred execution

```toml
[execution]
main = "bun"
renderer = "webview2-or-cef"
plugin_runtime = "bun"
```

### Required behavior

- vault filesystem semantics;
- atomic saves and file watching;
- community/core plugins;
- themes/snippets;
- multiple windows;
- Canvas;
- Markdown/PDF/media rendering;
- custom URI protocol;
- menus/shortcuts;
- CLI integration present in package;
- local storage and workspace restoration;
- Sync-facing local state without implementing/bypassing Sync.

### Likely hard boundaries

- arbitrary community plugin Node/Electron usage;
- plugin native modules;
- filesystem watcher volume;
- editor/renderer assumptions;
- custom protocols and multiple-window state.

### Strategy

- preserve Obsidian main/plugin logic under Bun;
- expose a declared Electron compatibility profile to plugins;
- scan installed plugins as a second-level compatibility set;
- allow per-plugin exceptions or helper routing;
- do not claim an adapter is full-parity for “all plugins”; certification records exact plugin corpus.

### Critical tests

- large vault watcher storms;
- atomic saves/renames;
- representative plugin corpus;
- plugin install/update/uninstall;
- multiple windows;
- URI activation;
- PDF/Canvas/media;
- no data loss under crash/restart;
- plugin process/resource bounds.

## 37.5 Slack

### Source/package position

Treat the desktop package as proprietary/package-derived.

### Preferred execution

```toml
[execution]
main = "bun"
renderer = "webview2-or-cef"
media = "vendor-helper-or-specialized"
```

### Required behavior

- multiple workspaces/accounts;
- authentication/enterprise SSO;
- messages/search/files;
- notifications/tray/badges;
- deep links;
- huddles/calls;
- screen sharing;
- camera/microphone/audio device selection;
- clips/recording features present in package;
- downloads/uploads;
- global shortcuts;
- updater/state migration.

### Likely hard boundaries

- media engine/WebRTC behavior;
- screen capture picker;
- enterprise auth;
- session partitions;
- background notification/call lifecycle;
- native crash modules.

### Critical tests

- multiple workspaces/profiles;
- SSO and reauth;
- join/leave huddle repeatedly;
- screen share and device switching;
- sleep/resume;
- incoming notification while backgrounded;
- renderer/media crash;
- no orphan call/capture processes;
- stable long-running memory.

## 37.6 TIDAL

### Source/package position

Treat the installed desktop package and proprietary media components as authoritative. Public browser playback is irrelevant and never used.

### Preferred execution

```toml
[execution]
main = "bun-or-replaced-boundaries"
renderer = "webview2-cef-or-specialized"
media = "vendor-specialized-surface"
```

### Required behavior

- packaged desktop UI;
- full supported playback quality;
- protected media/DRM without bypass;
- offline downloads/storage;
- audio output selection;
- exclusive-mode or device-specific behavior present in package;
- gapless playback/crossfade behavior present in package;
- media keys/session controls;
- TIDAL Connect/casting/device discovery;
- video;
- authentication;
- cache/database migration;
- notifications/deep links.

### Likely hard boundaries

- proprietary codecs/DRM;
- media pipeline tied to bundled Chromium/native components;
- offline encrypted downloads;
- audio device/exclusive mode;
- casting/device discovery;
- vendor entitlement checks.

### Strategy

- preserve media components unchanged through narrow helpers/specialized surfaces;
- do not alter DRM or entitlement logic;
- host packaged UI through the backend that passes media integration tests;
- allow CEF or specialized renderer only for windows/surfaces requiring it;
- report media helper cost separately.

### Critical tests

- each supported quality tier;
- offline download/play/delete;
- network loss/recovery;
- output-device changes;
- exclusive-mode contention;
- gapless/crossfade;
- media keys and lock screen;
- casting/connect;
- long playback soak;
- helper crash/recovery;
- no degradation concealed as parity.

## 37.7 Visual Studio Code

Code-OSS is source-available under MIT; Microsoft’s VS Code distribution includes product-specific configuration/assets/services governed separately.[R32]

### Preferred execution

```toml
[execution]
mode = "source-port-with-distribution-overlay"
main = "quickjs-native-or-bun-by-subsystem"
renderer = "webview2-or-cef"
extension_host = "bun-or-node-compatible-helper"
```

VS Code is not a simple application adapter. It is a platform adapter.

### Required behavior

- editor/workbench;
- multiple windows;
- extension host and extension API;
- native extension modules;
- terminal/PTY;
- filesystem watchers;
- language servers;
- debug adapters;
- webviews/custom editors;
- authentication/secret storage;
- Git/source control;
- Remote SSH;
- WSL;
- Dev Containers where package supports them;
- CLI/protocol/file associations;
- Marketplace/product configuration consistent with licensing;
- update behavior;
- accessibility/IME/performance.

### Likely hard boundaries

- extension host expects Node/Electron APIs;
- native extensions;
- terminal and file watchers;
- remote agent architecture;
- webview extension behavior;
- Microsoft product-specific services/licensing;
- browser extensions/CDP assumptions.

### Strategy

- keep generic workbench renderer;
- source-port Electron service layer to Weregopher SDK;
- run extension hosts as isolated Bun/Node-compatible workers;
- preserve native extension helpers/ABI islands by exact extension corpus;
- certify extension sets, not claim universal extension compatibility;
- use CEF if WebView2 cannot satisfy extension webview behavior;
- maintain Code-OSS core separately from Microsoft distribution overlays.

### Critical tests

- large workspace;
- extension install/update/disable;
- representative language/debug/native extensions;
- terminal and task execution;
- WSL/SSH/dev container;
- Git;
- multi-window;
- webviews/custom editors;
- crash recovery;
- watcher/extension host process cleanup;
- long editing soak.

## 37.8 Blockbench

Blockbench is source-available under GPL-3.0 and currently uses Electron, making it a strong source-port target subject to license separation between adapter/runtime and application-derived changes.[R30]

### Preferred execution

```toml
[execution]
mode = "source-port"
main = "quickjs-or-native-rust"
renderer = "webview2"
```

### Required behavior

- model/editor UI;
- WebGL/GPU behavior;
- file import/export;
- plugins;
- drag/drop/clipboard;
- native dialogs;
- file associations/protocols;
- texture/media handling;
- update behavior;
- platform integrations present in desktop build.

### Likely hard boundaries

- plugin APIs using Node/Electron;
- WebGL/backend differences;
- exporter/importer filesystem behavior;
- codecs/native helpers;
- license obligations for source-port changes.

### Critical tests

- representative model formats;
- large models/textures;
- plugin corpus;
- GPU/device loss;
- import/export round trips;
- drag/drop/clipboard;
- crash/state recovery;
- resource comparison.

## 37.9 Cross-application certification principle

For applications with extensions/plugins, certification identity includes the tested extension/plugin corpus:

```rust
struct ExtensionCorpusFingerprint {
    entries: Vec<ExtensionFingerprint>,
    merkle_root: Sha256,
}
```

Core adapter stability does not imply every third-party extension is compatible. The UI distinguishes:

- core application certification;
- tested extension corpus;
- unknown extensions with runtime probes;
- known incompatible extensions.

---

# 38. Repository architecture

```text
/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── LICENSE
├── NOTICE
├── README.md
├── AGENTS.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── deny.toml
├── justfile
├── xtask/
│   └── src/
│
├── crates/
│   ├── weregopher-cli/
│   ├── weregopher-daemon/
│   ├── weregopher-shell-win32/
│   ├── weregopher-shell-protocol/
│   ├── weregopher-discovery/
│   ├── weregopher-catalog/
│   ├── weregopher-fingerprint/
│   ├── weregopher-snapshot/
│   ├── weregopher-vfs/
│   ├── weregopher-asar/
│   ├── weregopher-adapter-schema/
│   ├── weregopher-adapter-loader/
│   ├── weregopher-adapter-compiler/
│   ├── weregopher-adapter-wasm/
│   ├── weregopher-runtime-protocol/
│   ├── weregopher-runtime-core/
│   ├── weregopher-runtime-quickjs/
│   ├── weregopher-runtime-bun/
│   ├── weregopher-node-compat/
│   ├── weregopher-node-fs/
│   ├── weregopher-node-process/
│   ├── weregopher-node-streams/
│   ├── weregopher-node-child-process/
│   ├── weregopher-electron-model/
│   ├── weregopher-electron-broker/
│   ├── weregopher-renderer-core/
│   ├── weregopher-renderer-webview2/
│   ├── weregopher-renderer-cef/
│   ├── weregopher-renderer-specialized/
│   ├── weregopher-preload/
│   ├── weregopher-ipc/
│   ├── weregopher-capabilities/
│   ├── weregopher-helper-supervisor/
│   ├── weregopher-resource-accounting/
│   ├── weregopher-state/
│   ├── weregopher-oracle/
│   ├── weregopher-trace/
│   ├── weregopher-trace-diff/
│   ├── weregopher-test-harness/
│   ├── weregopher-benchmark/
│   └── weregopher-privileged-protocol/
│
├── bins/
│   ├── weregopherctl/
│   ├── weregopherd/
│   ├── weregopher-shell/
│   ├── weregopher-worker/
│   ├── weregopher-helper-host/
│   └── weregopher-privileged/
│
├── js/
│   ├── electron-main-shim/
│   ├── electron-renderer-shim/
│   ├── preload-bootstrap/
│   ├── bun-bootstrap/
│   ├── node-polyfills/
│   ├── adapter-sdk/
│   └── test-fixtures/
│
├── wit/
│   ├── adapter-hooks.wit
│   ├── package-view.wit
│   ├── trace-normalizer.wit
│   └── state-migration.wit
│
├── schemas/
│   ├── adapter.schema.json
│   ├── build-descriptor.schema.json
│   ├── certification.schema.json
│   ├── capability.schema.json
│   ├── scenario.schema.json
│   └── trace.schema.json
│
├── adapters/
│   ├── openai-chatgpt/
│   ├── discord/
│   ├── github-desktop/
│   ├── notion/
│   ├── obsidian/
│   ├── slack/
│   ├── tidal/
│   ├── vscode/
│   └── blockbench/
│
├── conformance/
│   ├── electron/
│   ├── node/
│   ├── renderer/
│   └── protocol/
│
├── fixtures/
│   ├── packages/
│   ├── asar/
│   ├── state/
│   ├── repositories/
│   └── extensions/
│
├── tools/
│   ├── adapter-studio/
│   ├── trace-viewer/
│   ├── package-inspector/
│   └── registry-builder/
│
├── docs/
│   ├── architecture/
│   ├── adr/
│   ├── adapter-authoring/
│   ├── protocol/
│   ├── security/
│   ├── compatibility/
│   └── research/
│
└── third_party/
    ├── README.md
    └── licenses/
```

## 38.1 Crate boundaries

Rules:

- `weregopher-electron-model` contains platform-neutral semantic types, not Win32 handles.
- `weregopher-shell-win32` owns HWND/COM/DirectComposition types.
- `weregopher-renderer-core` contains backend-neutral traits.
- CEF/WebView2 implementation types do not leak into adapters.
- `weregopher-runtime-protocol` has no dependency on shell implementation.
- `weregopher-capabilities` is used by every host boundary.
- application-specific behavior does not enter generic crates without an ADR and reusable contract.
- generated code lives under explicit `generated` modules/directories and is reproducible.

## 38.2 Feature flags

Cargo feature flags should avoid accidental giant builds:

```toml
[features]
default = ["webview2", "quickjs"]
webview2 = []
cef = []
quickjs = []
bun = []
privileged-broker = []
etw = []
dev-inspector = []
```

CEF remains an optional component and should not be pulled into default artifacts.

## 38.3 Unsafe code policy

- forbid `unsafe` by default at workspace lint level;
- allow only in FFI/Win32/allocator modules with module-level justification;
- each unsafe block states invariants;
- add Miri where applicable for portable components;
- fuzz FFI input boundaries;
- wrap COM ownership in explicit RAII types;
- never share raw pointers across protocol boundaries.

## 38.4 Dependency policy

- locked dependencies;
- `cargo-deny` license/advisory/source checks;
- minimize duplicate async/runtime stacks;
- avoid unmaintained crates for security boundaries;
- pin QuickJS/CEF/Bun integration revisions;
- generate SBOM;
- document native redistribution licenses;
- vendor only when necessary and preserve provenance.

## 38.5 ADRs

Required early ADRs:

```text
ADR-0001 binary wire codec
ADR-0002 async runtime
ADR-0003 QuickJS binding/fork policy
ADR-0004 WebView2 controller/composition choice
ADR-0005 adapter WASM component runtime
ADR-0006 snapshot storage/deduplication
ADR-0007 trace format
ADR-0008 CEF component packaging
ADR-0009 state checkpoint mechanism
ADR-0010 OpenAI app-server proxy boundaries
```

---

# 39. CLI and developer workflows

`weregopher` is the authoritative scriptable interface. GUI tooling is optional.

## 39.1 Discovery

```powershell
weregopher discover
weregopher discover --application "Codex"
weregopher discover --path "C:\...\App.exe"
weregopher inspect openai.chatgpt --json
```

Output includes package identity, runtime versions, entry points, native modules, helpers, source catalog status, and adapter candidates.

## 39.2 Snapshot and package views

```powershell
weregopher snapshot openai.chatgpt
weregopher snapshots list openai.chatgpt
weregopher snapshots verify <id>
weregopher snapshots prune --dry-run
```

## 39.3 Analyze

```powershell
weregopher analyze openai.chatgpt --build current
weregopher analyze --snapshot <id> --emit build-descriptor.json
weregopher diff-builds <old> <new>
```

## 39.4 Oracle

```powershell
weregopher trace vendor openai.chatgpt --scenario codex-smoke
weregopher trace weregopher openai.chatgpt --scenario codex-smoke
weregopher trace diff <vendor-trace> <weregopher-trace>
```

Raw trace requires explicit flag and confirmation:

```powershell
weregopher trace vendor ... --raw-encrypted --key-provider windows-dpapi
```

## 39.5 Adapter development

```powershell
weregopher adapter init openai.chatgpt
weregopher adapter build adapters/openai-chatgpt
weregopher adapter validate adapters/openai-chatgpt
weregopher adapter probe openai.chatgpt --runtime quickjs --renderer webview2
weregopher adapter synthesize openai.chatgpt --from-diff <id>
weregopher adapter test openai.chatgpt --suite mandatory
weregopher adapter sign <bundle>
```

## 39.6 Launch

```powershell
weregopher launch openai.chatgpt
weregopher launch openai.chatgpt --surface codex
weregopher launch openai.chatgpt --runtime quickjs
weregopher launch openai.chatgpt --runtime bun
weregopher launch openai.chatgpt --renderer cef
weregopher launch openai.chatgpt --package-mode snapshot
weregopher launch openai.chatgpt --update-policy follow-current
weregopher launch openai.chatgpt --shell standalone
```

Overrides that violate adapter safety are rejected unless local developer mode explicitly permits them.

## 39.7 Certification

```powershell
weregopher certify openai.chatgpt --build current --suite full
weregopher certification show openai.chatgpt
weregopher certification explain openai.chatgpt --build current
```

## 39.8 Resource and diagnostics

```powershell
weregopher status
weregopher resources openai.chatgpt --watch
weregopher process-tree openai.chatgpt
weregopher leaks openai.chatgpt --explain
weregopher diagnostics export openai.chatgpt --redacted
```

## 39.9 Update policy

```powershell
weregopher update policy openai.chatgpt follow-verified
weregopher update policy openai.chatgpt follow-current
weregopher update pin openai.chatgpt <snapshot-or-build>
weregopher update candidates openai.chatgpt
weregopher update promote openai.chatgpt <candidate>
weregopher update rollback openai.chatgpt --with-state-checkpoint <id>
```

## 39.10 Machine-readable output

Every read-only command supports `--json`. Mutating commands support `--dry-run` where meaningful. Exit codes are stable and documented.

---

# 40. Engineering work packages and dependency graph

This section defines parallelizable bodies of engineering work and their dependencies. It is not an “ease into it” product roadmap. Codex may execute independent packages concurrently when interfaces are locked.

## 40.1 Dependency graph

```text
WP-A Core types/schema ─────────┬─────────────┬──────────────┐
                               │             │              │
WP-B Discovery/fingerprint ─────┤             │              │
WP-C ASAR/VFS/snapshot ─────────┤             │              │
                               ▼             ▼              ▼
WP-D Runtime protocol      WP-E Adapter SDK  WP-F Trace schema
       │                        │              │
       ├──────────┬─────────────┘              │
       ▼          ▼                            ▼
WP-G QuickJS   WP-H Bun                    WP-I Oracle/diff
       │          │                            │
       └────┬─────┘                            │
            ▼                                  │
WP-J Node compatibility                        │
            │                                  │
WP-K Electron model/broker ◄───────────────────┘
            │
       ┌────┴──────────────┐
       ▼                   ▼
WP-L Win32/WebView2    WP-M CEF backend
       │                   │
       └────────┬──────────┘
                ▼
WP-N Preload/bridge/IPC
                │
       ┌────────┼───────────┐
       ▼        ▼           ▼
WP-O Native   WP-P State  WP-Q Resources/security
helpers
       └────────┴─────┬─────┘
                      ▼
WP-R Test/certification harness
                      │
                      ▼
WP-S OpenAI family adapter
```

## 40.2 WP-A: core schemas and domain types

Deliverables:

- workspace skeleton;
- IDs/handles/domain types;
- JSON Schemas;
- manifest parser/validator;
- compatibility/certification types;
- ADR process;
- lint/CI baseline.

Acceptance:

- schemas round-trip;
- versioning policy documented;
- no platform-specific types in core model.

## 40.3 WP-B: discovery and fingerprinting

Deliverables:

- MSIX/AppX discovery;
- Squirrel/MSI/portable discovery;
- running-process resolution;
- Electron classification;
- package/runtime version extraction;
- Merkle manifest;
- source-availability catalog;
- package update event listener.[R23]

Acceptance:

- discovers target installations without version input;
- same package produces stable fingerprint;
- changed native/helper content changes fingerprint;
- malformed packages fail safely.

## 40.4 WP-C: ASAR/VFS/snapshot

Deliverables:

- ASAR parser/index;
- layered `PackageView`;
- overlay;
- materialization cache;
- live lease;
- immutable snapshot store;
- deduplication/retention;
- private renderer origin service.

Acceptance:

- Electron ASAR fixture behavior;
- path escape tests;
- executable/native materialization;
- concurrent readers;
- deterministic manifest.

## 40.5 WP-D: runtime protocol

Deliverables:

- named-pipe transport;
- authenticated handshake;
- wire codec;
- calls/events/handles;
- sync lane;
- streams/shared buffers;
- protocol fuzzing.

Acceptance:

- cross-process round trips;
- cancellation/deadline;
- forged client rejection;
- large-data flow control;
- no UI/runtime deadlock fixture.

## 40.6 WP-E: adapter SDK/compiler

Deliverables:

- manifest hierarchy;
- semantic transform API;
- SWC/internal AST backend;
- WASM hook host;
- adapter archive/signature;
- local developer mode;
- generated delta overlay format.

Acceptance:

- deterministic build;
- transform match-count failures;
- signed bundle verification;
- hostile WASM capability tests.

## 40.7 WP-F: trace/oracle model

Deliverables:

- trace schema;
- normalizer;
- redaction;
- storage;
- semantic diff;
- source-level Electron wrapper fixtures;
- external process/UI trace integration.

Acceptance:

- vendor/Weregopher fixture diff;
- stable normalization;
- secret redaction tests;
- causal ordering preserved.

## 40.8 WP-G: QuickJS runtime

Deliverables:

- `rquickjs`/QuickJS-NG integration;
- allocator/limits/interruption;
- CommonJS/ESM loader;
- scheduler;
- host bindings;
- diagnostics/source maps.

Acceptance:

- fixture main process loads;
- timeout/heap limit;
- module cycles;
- async host call;
- clean worker termination.

## 40.9 WP-H: Bun runtime

Deliverables:

- supervised Bun bootstrap;
- Electron/module interception;
- sync bridge;
- runtime protocol integration;
- Bun build-tool wrapper;
- helper-service mode;
- version certification.

Acceptance:

- CommonJS and ESM Electron fixture;
- host call sync/async;
- native-module classification fixture;
- crash isolation;
- reproducible build output.

## 40.10 WP-I: oracle instrumentation

Deliverables:

- source adapter;
- snapshot-overlay instrumentation;
- inspector/CDP tooling;
- process/filesystem/UI correlation;
- trace viewer.

Acceptance:

- reference Electron fixture trace;
- proprietary-safe local workflow;
- no package mutation in place;
- raw/redacted trace distinction.

## 40.11 WP-J: Node compatibility

Deliverables:

- process/events/buffer/streams;
- filesystem/path/watch;
- child process;
- timers/event loop;
- selected crypto/network modules;
- module coverage manifest;
- Bun delegation interface.

Acceptance:

- target fixture corpus;
- Node error shapes;
- watcher/child cleanup stress;
- backpressure;
- path security.

## 40.12 WP-K: Electron model/broker

Deliverables:

- handles/object registry;
- app lifecycle;
- BrowserWindow/webContents;
- sessions/protocols/webRequest;
- menu/tray/dialog/shell/clipboard;
- unsupported API trap;
- versioned contract manifest.

Acceptance:

- reference Electron fixtures;
- event ordering;
- close/quit semantics;
- stale/cross-app handle rejection.

## 40.13 WP-L: Win32/WebView2 shell

Deliverables:

- raw Win32 shell/message loop;
- AppUserModelID/taskbar;
- WebView2 environment/profile manager;
- renderer hosting;
- DirectComposition where required;
- input/IME/DPI/drag-drop/accessibility;
- package origin;
- notification/protocol activation.

Acceptance:

- multi-window/shared and standalone;
- shared UDF/separate profiles;
- crash recovery;
- DPI/IME/accessibility fixtures;
- no profile cross-leak.

## 40.14 WP-M: CEF backend

Deliverables:

- optional component loader;
- renderer backend implementation;
- subprocess packaging;
- scheme/request/interception;
- V8/world integration;
- version/component manager.

Acceptance:

- same renderer fixture under CEF;
- backend capability selection;
- optional install/removal;
- process/resource attribution.

## 40.15 WP-N: preload/context bridge/renderer IPC

Deliverables:

- preload compiler;
- document-start bootstrap;
- isolated-world implementation;
- contextBridge codec;
- ipcRenderer/main routing;
- frame/world generations;
- sync IPC.

Acceptance:

- full bridge fixture matrix;
- navigation invalidation;
- prototype-pollution tests;
- renderer crash recovery;
- deadlock tests.

## 40.16 WP-O: native helper system

Deliverables:

- helper manifests;
- Job/process supervisor;
- ABI island host;
- Bun N-API certification path;
- ConPTY reference replacement;
- DLL load policy.

Acceptance:

- helper crash/hang/cleanup;
- ABI isolation;
- no full Electron loophole;
- architecture/signature mismatch rejection.

## 40.17 WP-P: state/update system

Deliverables:

- state roots/epochs;
- migration hooks;
- checkpoints;
- live/snapshot update policies;
- candidate promotion;
- rollback matrix;
- reauthentication flow.

Acceptance:

- reversible/irreversible migration fixtures;
- vendor update during run;
- last-known-good retention;
- concurrent vendor/Weregopher safety.

## 40.18 WP-Q: resource/security system

Deliverables:

- process/resource attribution;
- private-commit sampling;
- growth detection;
- Job policies;
- capability broker;
- adapter signatures;
- audit log;
- privileged broker protocol.

Acceptance:

- shared resource reporting;
- orphan cleanup;
- capability/path attacks;
- pipe authentication;
- trace secret policy.

## 40.19 WP-R: certification harness

Deliverables:

- scenario DSL/runner;
- matrix execution;
- UI Automation;
- screenshot/accessibility/resource capture;
- certification records;
- reproducibility bundles.

Acceptance:

- generic Electron fixture certification;
- contract-verified candidate path;
- flake diagnostics;
- soak test runner.

## 40.20 WP-S: OpenAI family adapter

Deliverables:

- OpenAI package contract;
- preserved main logic transforms;
- exact app-server discovery/schema generation;
- transparent proxy;
- MCP/helper ownership;
- sandbox/WSL/worktree/Git/browser/preview integrations;
- Chat/Work/Codex surface tests;
- rapid-update contract path.

Acceptance is Section 36 and Section 41.

---

# 41. Definition of done

## 41.1 Core runtime done

The core runtime is done for an initial supported release when:

- installed packages are discovered without manual version input;
- live and snapshot package views work;
- ASAR VFS passes conformance/security tests;
- signed/local adapters load;
- QuickJS and Bun workers execute fixture main processes;
- WebView2 hosts packaged renderer assets;
- optional CEF backend can be installed and selected;
- `app`, `BrowserWindow`, `webContents`, preload, contextBridge, and IPC fixtures pass for the declared Electron profiles;
- native helpers/ABI islands are bounded and supervised;
- state/update/rollback contracts work;
- resource accounting reports exclusive/shared values;
- capability, pipe, path, and adapter security tests pass;
- certification bundles are reproducible.

## 41.2 OpenAI adapter done

The OpenAI family adapter is done for a declared build contract when:

- the exact installed unified desktop package is discovered and fingerprinted;
- packaged main/preload/renderer logic is loaded through Weregopher;
- vendor full Electron desktop executable/tree is absent;
- exact bundled app-server is located, schema-generated, initialized, and transparently proxied;
- Chat, Work, and Codex surface smoke tests pass, with any stable exceptions explicit;
- Codex project/thread/turn/approval/change workflows pass;
- MCP, plugins, skills, worktrees, Git, terminal, browser, previews, scheduled tasks, Windows sandbox, and WSL pass according to declared support;
- helper process ownership/cleanup passes soak tests;
- authentication works through one reauthentication;
- state and rollback status are known;
- a subsequent compatible high-frequency package update reaches `ContractVerified` without hand-authoring an exact-build adapter;
- resource benchmark truthfully records improved/neutral/regressed status.

## 41.3 No hidden fallback

Done requires proof that:

- original vendor desktop entry executable is not launched;
- original full Electron main/browser tree is not running under another name;
- any Electron-derived ABI island is bounded to declared native modules and creates no BrowserWindow/renderers;
- public web clients are not used.

## 41.4 Documentation done

- architecture and ADRs current;
- adapter authoring guide;
- security model;
- protocol docs;
- contributor build/test commands;
- third-party notices;
- compatibility registry metadata;
- known exceptions and benchmark methodology.

---

# 42. Known risks and unresolved questions

## 42.1 QuickJS compatibility ceiling

Risk: new packages may rely on modern V8/Node semantics costly to reproduce.

Mitigation:

- semantic transpilation;
- Bun fallback/helper;
- app-specific replacement modules;
- runtime capability probes;
- retain Boa interface without committing to it.

Open question: which Node modules dominate actual target call graphs after oracle instrumentation?

## 42.2 Preload isolated-world fidelity

Risk: WebView2 world and host-object behavior may not exactly reproduce Electron contextBridge semantics.

Mitigation:

- CDP isolated worlds;
- explicit bridge codec;
- CEF fallback;
- differential fixtures;
- adapter-specific preload workers.

Open question: which target applications depend on subtle proxy/prototype behavior?

## 42.3 WebView2 process sharing fragility

Risk: environment option differences, runtime changes, or app requirements prevent sharing.

Mitigation:

- environment-key manager;
- adapter-selectable UDF/backend;
- report actual rather than assumed sharing;
- benchmark machine-wide totals.

## 42.4 CEF weakens resource goal

Risk: CEF adds another Chromium distribution/process tree.

Mitigation:

- optional/per-window selection;
- use only when required;
- still replace vendor Electron main and gain lifecycle control;
- efficiency label may be neutral/regressed.

## 42.5 Proprietary native components

Risk: licensing, ABI, update, or integrity constraints prevent transformation.

Mitigation:

- run installed component in narrow helper;
- no redistribution;
- exact hash certification;
- source replacement where legal/available;
- explicit unsupported status.

## 42.6 DRM/protected media

Risk: renderer/backend change invalidates protected media path.

Mitigation:

- specialized installed vendor surface;
- no DRM bypass;
- TIDAL feature tests;
- accept unsupported build when legal/technical path absent.

## 42.7 Unified ChatGPT package opacity

Risk: proprietary shell changes, integrity checks, or opaque native modules block instrumentation or runtime substitution.

Mitigation:

- preserve package main logic;
- inspector/external oracle tiers;
- Bun fallback;
- app-server as documented durable boundary;
- generated contract probes;
- `follow-current` and pinned options.

## 42.8 Update frequency

Risk: package changes faster than full certification.

Mitigation:

- contract verification;
- opaque IPC/pass-through;
- generated app-server schemas;
- semantic transform rebinding;
- fast mandatory smoke suite;
- user-selectable follow-current;
- last-known-good snapshots.

## 42.9 State migrations

Risk: candidate build migrates state irreversibly before failure.

Mitigation:

- disposable/cloned state probes;
- checkpoints;
- state epochs;
- promotion gating;
- disable unsafe automatic rollback.

## 42.10 Renderer login/authentication

Risk: login flows detect or reject embedded renderer/backend differences.

Mitigation:

- packaged desktop flow under compatible Chromium backend;
- WebView2/CEF feature probes;
- dedicated profile and explicit reauth;
- no credential extraction.

## 42.11 Extension/plugin ecosystems

Risk: “full parity” is unbounded when users install arbitrary code.

Mitigation:

- core adapter certification plus extension-corpus fingerprint;
- runtime probes;
- per-extension routing/exceptions;
- no false universal claim.

## 42.12 Security regression through compatibility

Risk: preserving dangerous Electron configurations exposes host capabilities to compromised content.

Mitigation:

- capability broker independently enforces operations;
- origin/frame-scoped bridge;
- visible security profile;
- critical blockers for undisclosed weakening;
- do not silently change behavior that users rely on without explicit adapter contract.

## 42.13 ABI-island scope creep

Risk: adapter authors place too much Electron code in an ABI island.

Mitigation:

- structural rules and process inspection;
- no BrowserWindow/renderers;
- allowlisted modules/operations;
- resource accounting;
- registry review.

## 42.14 Cross-platform future

Risk: Windows-specific core assumptions leak into portable layers.

Mitigation:

- platform-neutral domain/runtime/adapter traits;
- Windows implementation prioritized over premature abstraction;
- only abstract proven boundaries.

Unresolved: macOS application identity/process sharing and Linux WebKitGTK distribution differences require separate specs.

## 42.15 Legal interoperability boundaries

Risk: package transforms or redistribution violate licenses/terms.

Mitigation:

- local package processing;
- no proprietary asset redistribution;
- component provenance/license catalog;
- adapters distribute transforms/metadata, not vendor code;
- legal review before public registry support for proprietary targets.

---

# 43. Instructions for Codex

This section is an operational instruction block for a Codex coding session working on the repository.

## 43.1 Primary directive

Build the system specified in this document. Do not replace the problem with a website wrapper, PWA, public web client, or generic resource monitor. The installed desktop package is the source application.

## 43.2 Repository behavior

Codex MUST:

1. read the root `AGENTS.md` and any nested `AGENTS.md` before modifying a path;
2. read relevant ADRs and schemas;
3. preserve locked decisions;
4. create an ADR before changing a major implementation choice;
5. keep application-specific logic in adapters;
6. write tests with every compatibility implementation;
7. avoid in-place modification of vendor installs;
8. avoid adding CEF/.NET/large runtimes to default builds without the specified feature/component boundary;
9. maintain license/provenance metadata;
10. run formatting, lint, unit, and affected integration tests before presenting changes.

## 43.3 No false completion

Codex MUST NOT claim:

- generic Electron compatibility based on one fixture;
- memory improvement based on working set alone;
- full parity when exceptions exist;
- support for a proprietary native module without executing its tests;
- update compatibility from version/hash similarity alone;
- security parity without sandbox/approval tests;
- process cleanup without soak/lifecycle evidence.

## 43.4 Work selection

When assigned a broad task, Codex should:

1. identify the work package and dependency contracts;
2. inspect existing interfaces/tests;
3. state assumptions in an issue/ADR or code comments where durable;
4. implement the smallest complete vertical contract, not a toy unrelated prototype;
5. add observability and failure diagnostics;
6. preserve future backend substitution;
7. update schemas/docs.

“Smallest complete vertical contract” means, for example:

- a working named-pipe call with auth, serialization, cancellation, tests, and error handling;
- not a stub that sends one unbounded JSON string.

## 43.5 Coding standards

Rust:

- stable Rust unless ADR says otherwise;
- explicit error types at library boundaries;
- no `unwrap`/`expect` in production paths without invariant explanation;
- cancellation-safe async code;
- bounded queues;
- RAII for handles/COM/process/job resources;
- `unsafe` isolated and documented;
- structured tracing;
- no secret values in default logs.

TypeScript/JavaScript:

- strict TypeScript for Weregopher-owned modules;
- generated code clearly marked;
- no `any` across protocol/adapter boundaries without documented reason;
- runtime validation for untrusted data;
- source maps;
- deterministic builds;
- semantic transforms instead of text replacement.

C/C++:

- only for unavoidable FFI/CEF/QuickJS bridge layers;
- narrow C ABI where possible;
- ownership/error contracts documented;
- fuzz or adversarial tests for input boundaries.

## 43.6 Test expectations

For every issue/fix, Codex should provide:

- reproducer or failing fixture;
- implementation;
- positive test;
- negative/error test;
- cleanup/lifetime test when resources are involved;
- update/compatibility regression test when package matching is involved;
- security test when trust/capability/path/IPC is involved.

## 43.7 OpenAI adapter instructions

When working on OpenAI/Codex:

- use official OpenAI app-server schemas generated from the exact bundled binary;
- preserve unknown methods/fields unless actively interpreting them;
- preserve packaged main-process logic by default;
- keep internal IPC opaque unless replacing a boundary;
- never substitute the web app;
- do not use a globally installed Codex binary unless explicitly configured;
- attach helper processes to logical thread/turn ownership where observable;
- treat approvals/sandbox semantics as critical security behavior;
- make candidate update ingestion automated and contract-driven;
- retain last-known-good package/state evidence;
- add a test proving an ordinary compatible package update does not require a hand-authored exact-build adapter.

## 43.8 Reporting work

At completion, Codex should report:

- files changed;
- contract implemented;
- tests run/results;
- remaining known limitations;
- security/resource implications;
- whether an ADR/schema/doc changed;
- exact commands for reproduction.

Do not use vague language such as “should work.” Distinguish implemented, tested, inferred, and unverified behavior.


---

# Appendix A: manifest example

The following is an illustrative, intentionally verbose family/build manifest. It is not a claim about current OpenAI package paths or channel identifiers. Discovery fills generated values from the installed package.

```toml
schema = 1

[adapter]
id = "openai.chatgpt.windows"
display_name = "OpenAI ChatGPT Desktop"
family = "openai.chatgpt"
adapter_version = "0.1.0"
license = "MIT"
publisher = "local-development"
status = "development"

[application]
platform = "windows"
architecture = ["x86_64", "aarch64"]
installed_package_is_source = true
public_web_fallback = false
scope = ["chat", "work", "codex"]
priority_surface = "codex"

[discovery]
strategies = ["msix", "squirrel", "uninstall-registry", "running-process"]
known_signer_policy = "family-catalog"
source_availability = "component-catalog"

[[discovery.package_families]]
# Generated/maintained family rules go here. Do not hard-code an example
# as factual until discovered and verified.
pattern = "<scanner-maintained-pattern>"
channel = "stable"

[matching]
mode = "family-contract"
exact_hash_for_identity = true
exact_hash_for_launch = false
require_known_signer = true
require_architecture_match = true
require_generated_build_descriptor = true
require_native_dependency_classification = true

[matching.contracts]
package = "openai-package-contract-v1"
main_runtime = "openai-main-contract-v1"
renderer = "openai-renderer-contract-v1"
app_server = "codex-app-server-contract-v1"
state = "openai-state-contract-v1"
security = "openai-security-contract-v1"

[package]
mode = "auto"
live_allowed = true
snapshot_allowed = true
snapshot_default_when_uncertain = true
modify_vendor_install = false
overlay = "overlay"
retain_last_known_good = 3

[package.live]
require_immutable_or_versioned_root = true
require_overlay_only = true
lease_opened_files = true
continue_running_on_vendor_update = true

[package.snapshot]
content_addressed = true
deduplicate = true
verify_on_open = true
include = [
  "resources/**",
  "*.exe",
  "*.dll",
  "*.pak",
  "locales/**"
]
exclude_reproducible_cache = true

[entry]
main = "discover:electron-main"
preloads = ["discover:browser-window-preloads"]
renderers = ["discover:renderer-roots"]

[execution]
mode = "hybrid-preserve-main"
runtime_isolation = "process"
runtime_selection = "probe"
runtime_preference = ["quickjs", "bun"]
preserve_vendor_main_logic = true
opaque_application_ipc = true
unknown_internal_channel = "pass-through"

[runtime.quickjs]
enabled = true
engine = "quickjs-ng"
heap_limit_mb = 512
stack_limit_kb = 4096
max_turn_ms = 5000
syntax_target = "generated"
node_profile = "generated-from-package"

[runtime.bun]
enabled = true
roles = ["alternate-main", "build-tool", "helper"]
version_policy = "certified-range"
ffi = "deny-unless-declared"
native_modules = "hash-certified"

[[runtime.services]]
id = "node-heavy-subsystem"
enabled_when = "generated-contract-requires"
engine = "bun"
entry = "adapter:services/node-heavy.ts"
capability_profile = "openai-node-heavy-helper"

[shell]
topology = "user-selectable"
default_topology = "standalone"
shared_topology_allowed = true
app_user_model_id = "generated:family-profile"
per_monitor_dpi_v2 = true
raw_win32 = true
direct_composition = "when-required"

[renderer]
selection = "probe"
preference = ["webview2", "cef", "specialized:openai"]
packaged_assets_only = true
public_remote_app_roots = false
private_origin = "generated"

[renderer.webview2]
enabled = true
distribution = "evergreen"
fixed_version_for_ci = true
user_data_folder = "adapter-selectable"
default_user_data_folder = "shared-v1"
profile = "openai-chatgpt-default"
separate_profile = true
allow_browser_process_sharing = true

[renderer.cef]
enabled = true
component = "optional"
version_range = "adapter-generated"
select_when = [
  "browser-extension-required",
  "webview2-contract-fails",
  "chromium-switch-required",
  "v8-world-contract-fails"
]

[renderer.specialized]
enabled = true
allow_full_vendor_electron = false
require_narrow_interface = true
require_resource_attribution = true

[renderer.security]
context_isolation = "preserve-package"
sandbox = "preserve-package"
node_integration = "preserve-package-with-capability-boundary"
origin_check = true
frame_scoped_handles = true
raw_host_object_to_page = false

[asar]
enabled = true
vfs = true
materialization_cache = true
preserve_virtual_paths = true

[module_loader]
commonjs = true
esm = true
json = true
wasm = true
dynamic_require = "analyze-and-adapt"
external_search_roots = []

[module_loader.aliases]
"electron" = "compat:electron"
"electron/main" = "compat:electron-main"
"electron/renderer" = "compat:electron-renderer"

[electron]
contract = "generated-used-surface"
unsupported_api = "trap-report-and-block-candidate-when-critical"
object_handles = "generation-checked"
event_ordering = "profile-and-fixture"

[electron.ipc]
channel_names = "opaque"
payloads = "generic-wire-codec"
application_specific_mapping = "only-replaced-boundaries"
sync_ipc = "supported-bounded"

[electron.session]
partition_mapping = "profile-based"
web_request = "backend-capability-probed"
protocols = "private-origin-and-adapter"

[preload]
discover = true
transform = true
document_start = true
context_bridge = true
isolated_world = "backend-capability-probed"
frame_generation_checks = true

[protocol]
transport = "windows-named-pipe"
codec = "messagepack-extensions"
authentication = "pid-sid-job-nonce"
explicit_pipe_dacl = true
max_frame_bytes = 16777216
max_object_depth = 128
max_pending_requests = 4096
max_remote_handles = 100000

[helpers]
default_job = "application"
verify_hash = true
verify_signer = true
inherit_handles = "explicit-only"
shutdown = "protocol-then-kill-tree"

[[helpers.classifiers]]
id = "codex-app-server"
locator = "discover:codex-app-server"
strategy = "vendor-helper"
transport = "stdio-jsonl"
owner = "app-server"

[[helpers.classifiers]]
id = "sandbox-setup"
locator = "discover:sandbox-helper"
strategy = "vendor-helper"
owner = "sandbox"

[[helpers.classifiers]]
id = "ripgrep"
locator = "discover:rg-helper"
strategy = "vendor-helper"
owner = "command"

[native_modules]
unknown = "block-contract-verification"
allow_rust_replacement = true
allow_bun_napi = true
allow_rebuilt = true
allow_vendor_helper = true
allow_abi_island = true
allow_full_electron_island = false

[[native_modules.rules]]
package = "node-pty"
strategy = "rust-replacement"
implementation = "compat:openai/conpty"

[capabilities]
mode = "hybrid"
unsafe_full_user_access = false
prompt_for_new_capability = true
cross_app_access = false

[capabilities.filesystem]
read = [
  "${PACKAGE_ROOT}/**",
  "${APP_DATA}/**",
  "${USER_HOME}/.codex/**",
  "${USER_GRANTED_PROJECTS}/**"
]
write = [
  "${APP_DATA}/**",
  "${USER_HOME}/.codex/**",
  "${USER_GRANTED_PROJECTS}/**"
]
follow_reparse_points = "capability-recheck"

[capabilities.process]
spawn = [
  "package:discover:codex-app-server",
  "package:discover:sandbox-helper",
  "package:discover:command-helpers",
  "user-approved:project-commands",
  "user-configured:mcp-servers"
]
shell = "approval-and-sandbox-policy"
job_ownership = true

[capabilities.network]
mode = "package-and-codex-policy"
renderer_permissions = "profile-and-origin"

[capabilities.devices]
microphone = "package-prompt"
camera = "package-prompt"
screen_capture = "package-prompt"

[authentication]
strategy = "reauthenticate"
copy_vendor_cookie_database = false
copy_protected_tokens = false
profile = "weregopher-dedicated"

[[state.roots]]
id = "browser-profile"
class = "BrowserProfile"
source = "none"
destination = "weregopher:profiles/openai-chatgpt"
strategy = "new-profile"
secret = true

[[state.roots]]
id = "codex-home"
class = "CodexConfiguration"
source = "host:${USER_HOME}/.codex"
destination = "same"
strategy = "shared-authoritative-after-probe"
secret = true

[[state.roots]]
id = "desktop-settings"
class = "ApplicationSettings"
source = "discover:vendor-settings"
destination = "weregopher:${APP_DATA}/settings"
strategy = "adapter-transform"
secret = false

[state]
epochs = true
candidate_probe = "disposable-clone"
checkpoint_before_irreversible_migration = true
unknown_rollback = "disable-auto-rollback"

[update]
policy = "follow-verified"
allow_follow_current = true
allow_pinned = true
watch_package_catalog = true
auto_generate_descriptor = true
auto_generate_delta_overlay = true
exact_hash_for_certification = true
minimum_launch_class = "contract-verified"

[update.follow_current]
require_known_signer = true
require_native_classification = true
require_runtime_bootstrap = true
require_renderer_preload_probe = true
require_app_server_handshake = true
require_state_dry_run = true

[update.fallback]
enabled = true
require_state_compatibility = true
last_known_good_count = 3

[codex]
enabled = true
priority = true
binary = "discover:codex-app-server"
use_global_codex = false
transport = "stdio-jsonl"
schema_generation = true
unknown_methods = "pass-through"
unknown_fields = "preserve"
proxy_mode = "transparent-supervised"

[codex.app_server]
initialize_required = true
bounded_queues = true
trace = "redacted"
process_ownership_observer = true

[[codex.app_server.intercepts]]
method_pattern = "*"
mode = "pass-through"

[[codex.app_server.intercepts]]
method_pattern = "*approval*"
mode = "observe-security-critical"

[[codex.app_server.intercepts]]
method_pattern = "*command*"
mode = "observe-process-ownership"

[codex.mcp]
preserve = true
stdio = true
remote = true
node_processes = "normal-supervised-children"
owner_scope = "infer-from-app-server"
cleanup = "protocol-then-job"

[codex.sandbox]
preserve_package_semantics = true
windows_native = true
wsl2 = true
display_actual_mode = true
weaker_than_displayed = "critical-blocker"

[codex.worktrees]
preserve = true
owner_scope = "thread"
protect_uncommitted_work = true

[codex.plugins]
preserve = true
discover = true
browser_extensions_may_select_cef = true

[codex.browser]
preserve_packaged_surface = true
external_web_substitution = false
backend = "probe"

[resource]
enabled = true
primary_memory_metric = "private-commit"
report_working_set = true
report_shared_browser_separately = true
process_ownership = true
orphan_cleanup = true

[resource.policy]
force_working_set_trim = false
quickjs_gc_at_safe_points = true
inactive_memory_priority = "adapter-policy"
eco_qos = "adapter-policy"
hard_memory_limit = "explicit-advanced-only"

[trace]
default = "local-redacted"
raw = "explicit-encrypted-only"
retain_days = 14

[certification]
classes = ["exact-certified", "contract-verified", "provisional", "blocked"]
stable_with_exceptions = true
critical_exceptions_block_stable = true
benchmark_required_for_efficiency_claim = true

[[certification.mandatory_scenarios]]
id = "openai-package-bootstrap"

[[certification.mandatory_scenarios]]
id = "openai-renderer-preload-bridge"

[[certification.mandatory_scenarios]]
id = "codex-app-server-handshake"

[[certification.mandatory_scenarios]]
id = "codex-benign-thread-turn"

[[certification.mandatory_scenarios]]
id = "codex-helper-clean-shutdown"

[[certification.mandatory_scenarios]]
id = "openai-state-open-close"

[efficiency]
allow_vendor_desktop_entry = false
allow_vendor_full_electron_browser = false
allow_vendor_browser_window_in_abi_island = false
allow_bounded_helpers = true
status = "benchmark-derived"
```

---

# Appendix B: protocol types

The following pseudocode elaborates the protocol and domain contracts. It is not intended to compile unchanged.

```rust
pub type RequestId = u64;
pub type Sequence = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AppInstanceId(pub u128);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RuntimeId(pub u128);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RendererId(pub u128);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ProtocolSessionId(pub u128);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ObjectHandle {
    pub app: AppInstanceId,
    pub id: u64,
    pub generation: u32,
    pub kind: ObjectKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    App,
    BrowserWindow,
    WebContents,
    Session,
    WebRequest,
    Menu,
    MenuItem,
    Tray,
    NativeImage,
    Notification,
    DownloadItem,
    MessagePort,
    UtilityProcess,
    AdapterDefined(u16),
}

#[repr(C)]
pub struct FrameHeader {
    pub payload_len: u32,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub message_kind: u8,
    pub flags: u8,
    pub reserved: u16,
    pub request_id: RequestId,
    pub sequence: Sequence,
}

pub enum Message {
    Hello(Hello),
    Welcome(Welcome),
    Reject(Reject),

    LoadApplication(LoadApplication),
    ApplicationReady(ApplicationReady),
    ApplicationExit(ApplicationExit),

    Call(Call),
    CallResult(CallResult),
    CallError(CallError),
    Cancel(Cancel),

    Event(Event),
    Subscribe(Subscribe),
    Unsubscribe(Unsubscribe),

    IpcSend(IpcSend),
    IpcInvoke(IpcInvoke),
    IpcReply(IpcReply),
    IpcError(IpcError),

    StreamOpen(StreamOpen),
    StreamWindow(StreamWindow),
    StreamData(StreamData),
    StreamEnd(StreamEnd),
    StreamError(StreamError),

    RetainHandle(RetainHandle),
    ReleaseHandle(ReleaseHandle),

    SharedBufferOffer(SharedBufferOffer),
    SharedBufferAccept(SharedBufferAccept),
    SharedBufferRelease(SharedBufferRelease),

    Heartbeat(Heartbeat),
    Diagnostics(Diagnostics),
    Shutdown(Shutdown),
}

pub struct Hello {
    pub runtime: RuntimeId,
    pub app: AppInstanceId,
    pub backend: RuntimeBackendIdentity,
    pub protocol_range: ProtocolVersionRange,
    pub nonce_proof: [u8; 32],
    pub capabilities: RuntimeCapabilities,
    pub requested_limits: ProtocolLimits,
}

pub struct Welcome {
    pub session: ProtocolSessionId,
    pub version: ProtocolVersion,
    pub limits: ProtocolLimits,
    pub compatibility: CompatibilityIdentity,
    pub heartbeat: HeartbeatPolicy,
    pub features: ProtocolFeatures,
}

pub struct Call {
    pub target: CallTarget,
    pub method: String,
    pub args: Vec<WireValue>,
    pub context: CallContext,
}

pub enum CallTarget {
    Service(String),
    Object(ObjectHandle),
    Runtime(RuntimeId),
}

pub struct CallContext {
    pub app: AppInstanceId,
    pub renderer: Option<RendererId>,
    pub frame: Option<FrameIdentity>,
    pub world: Option<WorldIdentity>,
    pub user_activation: bool,
    pub capability: CapabilityTokenId,
    pub deadline_ms: Option<u32>,
    pub trace_parent: Option<TraceId>,
}

pub enum WireValue {
    Undefined,
    Null,
    Bool(bool),
    Integer(i64),
    Float(f64),
    NegativeZero,
    NaN,
    PositiveInfinity,
    NegativeInfinity,
    BigInt {
        negative: bool,
        magnitude_be: Vec<u8>,
    },
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<WireValue>),
    Object(Vec<(String, WireValue)>),
    Reference(u32),
    DateMillis(i64),
    RegExp {
        source: String,
        flags: String,
    },
    Error(WireError),
    Handle(ObjectHandle),
    Function(RemoteFunctionHandle),
    Promise(RemotePromiseHandle),
    MessagePort(MessagePortHandle),
    TypedArray {
        kind: TypedArrayKind,
        byte_offset: u64,
        element_count: u64,
        storage: BufferStorage,
    },
}

pub enum BufferStorage {
    Inline(Vec<u8>),
    Shared(SharedBufferHandle),
    Stream(StreamHandle),
    Blob(ContentBlobId),
}

pub struct WireError {
    pub name: String,
    pub message: String,
    pub stack: Option<String>,
    pub code: Option<String>,
    pub kind: Option<String>,
    pub cause: Option<Box<WireValue>>,
    pub data: BTreeMap<String, WireValue>,
}

pub struct ProtocolLimits {
    pub max_frame_bytes: u32,
    pub max_graph_nodes: u32,
    pub max_object_depth: u16,
    pub max_string_bytes: u32,
    pub max_inline_buffer_bytes: u32,
    pub max_pending_requests: u32,
    pub max_remote_handles: u32,
    pub max_open_streams: u16,
    pub max_listener_count: u32,
}

pub struct FrameIdentity {
    pub renderer: RendererId,
    pub frame_id: u64,
    pub generation: u32,
    pub parent_frame_id: Option<u64>,
    pub origin: OriginIdentity,
    pub is_main_frame: bool,
}

pub struct WorldIdentity {
    pub frame: FrameIdentity,
    pub world_id: u64,
    pub generation: u32,
    pub kind: ScriptWorldKind,
}

pub enum ScriptWorldKind {
    Main,
    PreloadIsolated,
    AdapterIsolated,
    BackendSpecific(String),
}

pub struct IpcSend {
    pub renderer: RendererId,
    pub frame: FrameIdentity,
    pub channel: String,
    pub args: Vec<WireValue>,
}

pub struct IpcInvoke {
    pub renderer: RendererId,
    pub frame: FrameIdentity,
    pub channel: String,
    pub args: Vec<WireValue>,
}

pub struct Event {
    pub target: ObjectHandle,
    pub name: String,
    pub args: Vec<WireValue>,
    pub cancellation: Option<EventCancellationToken>,
    pub causal_parent: Option<TraceId>,
}

pub struct StreamOpen {
    pub stream: StreamHandle,
    pub kind: StreamKind,
    pub metadata: BTreeMap<String, WireValue>,
    pub initial_credit: u64,
}

pub struct StreamWindow {
    pub stream: StreamHandle,
    pub additional_credit: u64,
}

pub struct StreamData {
    pub stream: StreamHandle,
    pub sequence: u64,
    pub bytes: Vec<u8>,
}

pub struct SharedBufferOffer {
    pub buffer: SharedBufferHandle,
    pub byte_len: u64,
    pub access: SharedBufferAccess,
    pub duplicated_os_handle: u64,
    pub content_hash: Option<Sha256>,
}

pub struct RuntimeDiagnostics {
    pub backend: RuntimeBackendIdentity,
    pub state: RuntimeState,
    pub heap: Option<HeapStatistics>,
    pub loaded_modules: u32,
    pub pending_jobs: u32,
    pub pending_async_ops: u32,
    pub remote_handles: u32,
    pub event_loop_lag: Duration,
    pub last_host_call: Option<String>,
}

pub struct BuildFingerprint {
    pub package_family: Option<String>,
    pub package_version: Option<Version>,
    pub product_version: Option<Version>,
    pub architecture: Architecture,
    pub package_merkle_root: Sha256,
    pub app_asar_sha256: Option<Sha256>,
    pub unpacked_merkle_root: Option<Sha256>,
    pub main_entry_sha256: Option<Sha256>,
    pub preload_merkle_root: Option<Sha256>,
    pub native_module_merkle_root: Option<Sha256>,
    pub helper_binary_merkle_root: Option<Sha256>,
    pub signer: Option<SignerIdentity>,
    pub electron_version: Option<Version>,
    pub chromium_version: Option<Version>,
    pub node_version: Option<Version>,
}

pub struct BuildLease {
    pub app: ApplicationFamilyId,
    pub build: BuildFingerprint,
    pub package_source: BuildSource,
    pub package: Arc<dyn PackageView>,
    pub adapter: ResolvedAdapter,
    pub state_epoch: StateEpochId,
    pub renderer_identity: RendererBackendIdentity,
    pub runtime_identity: RuntimeBackendIdentity,
}

pub enum CertificationClass {
    ExactCertified,
    ContractVerified,
    Provisional,
    Blocked,
}

pub struct CertificationRecord {
    pub build: BuildFingerprint,
    pub adapter_version: Version,
    pub generated_overlay_hash: Sha256,
    pub class: CertificationClass,
    pub runtime: RuntimeBackendIdentity,
    pub renderer: RendererBackendIdentity,
    pub passed_scenarios: Vec<ScenarioId>,
    pub failed_scenarios: Vec<ScenarioFailure>,
    pub exceptions: Vec<FeatureException>,
    pub efficiency: EfficiencyStatus,
    pub tested_at: SystemTime,
}
```


---

# Appendix C: parity scenario DSL

The scenario DSL is declarative YAML with extension hooks. It supports vendor-oracle and Weregopher execution, state fixtures, UI Automation, semantic events, process/resource assertions, and differential comparison.

## C.1 Schema outline

```yaml
schema: 1
id: string
title: string
application: string
surface: optional-string
tags: [string]

requirements:
  authentication: optional-bool
  network: optional-bool
  administrator: optional-bool
  renderer_capabilities: [string]
  runtime_capabilities: [string]
  feature_flags: [string]

matrix:
  execution_targets: [vendor, weregopher]
  runtimes: [auto, quickjs, bun]
  renderers: [auto, webview2, cef]
  shell_topologies: [standalone, shared]
  package_modes: [auto, live, snapshot]

fixtures:
  profile: string
  state: string
  project: optional-string
  filesystem: optional-string
  extensions: optional-string

timeouts:
  scenario: duration
  step_default: duration
  shutdown: duration

steps:
  - operation: ...

assertions:
  - assertion: ...

normalization:
  rules: [string]

exceptions:
  allowed: [string]
```

## C.2 Full Codex example

```yaml
schema: 1
id: openai.codex.project-edit-approval-cleanup
title: Codex edits a project under workspace-write and cleans all turn-scoped helpers
application: openai.chatgpt
surface: codex

tags:
  - mandatory
  - codex
  - approval
  - sandbox
  - process-cleanup
  - resource

requirements:
  authentication: true
  network: true
  administrator: false
  renderer_capabilities:
    - isolated-worlds
    - document-start-script
  runtime_capabilities:
    - child-process
    - filesystem
    - streams
  feature_flags:
    - codex

matrix:
  execution_targets:
    - vendor
    - weregopher
  runtimes:
    - auto
  renderers:
    - auto
  shell_topologies:
    - standalone
  package_modes:
    - snapshot

timeouts:
  scenario: 15m
  step_default: 60s
  shutdown: 30s

fixtures:
  profile: authenticated-openai-test-profile
  state: clean-codex-state
  project: fixtures/repositories/simple-rust-project
  filesystem: fixtures/filesystems/codex-workspace-write

steps:
  - launch:
      application: openai.chatgpt
      surface: codex
      update_policy: pinned
      trace: redacted
      resource_sampling: fast

  - wait_for:
      semantic_event: application.ready

  - wait_for:
      semantic_event: openai.surface.ready
      where:
        surface: codex

  - open_project:
      path: "${FIXTURE_PROJECT}"

  - wait_for:
      semantic_event: codex.project.opened
      where:
        path: "${FIXTURE_PROJECT}"

  - set_codex_policy:
      sandbox: workspace-write
      approvals: on-request

  - capture_process_baseline:
      id: before-turn
      owner: current-application

  - start_codex_thread:
      bind: thread
      prompt: >-
        Create a file named result.txt at the repository root containing
        exactly the line `weregopher transformation test`. Do not modify any other file.

  - wait_for:
      semantic_event: codex.turn.started
      bind:
        turn: event.turn_id

  - wait_for:
      semantic_event: codex.approval.requested
      where:
        thread_id: "${thread.id}"
        turn_id: "${turn.id}"
      bind:
        approval: event

  - assert:
      equals:
        actual: "${approval.sandbox_mode}"
        expected: workspace-write

  - respond_to_approval:
      request_id: "${approval.request_id}"
      decision: accept

  - wait_for:
      semantic_event: codex.turn.completed
      where:
        thread_id: "${thread.id}"
        turn_id: "${turn.id}"

  - assert_file:
      path: "${FIXTURE_PROJECT}/result.txt"
      exists: true
      content_exact: "weregopher transformation test\n"

  - assert_git_diff:
      repository: "${FIXTURE_PROJECT}"
      changed_paths:
        - result.txt
      no_other_changes: true

  - wait_for_process_quiescence:
      owner:
        app: current
        thread_id: "${thread.id}"
        turn_id: "${turn.id}"
      grace: 10s

  - capture_process_snapshot:
      id: after-turn
      owner: current-application

  - close_application:
      graceful: true

  - wait_for:
      semantic_event: application.exited

assertions:
  - no_critical_trace_errors: true

  - process_delta:
      baseline: before-turn
      final: after-turn
      transient_owner:
        thread_id: "${thread.id}"
        turn_id: "${turn.id}"
      remaining_transient_processes: 0

  - no_orphan_processes:
      owner: current-application
      after_shutdown: true

  - resource_slope:
      metric: private_commit
      window: 5m
      maximum_mb_per_hour: 100
      confidence_minimum: 0.8

  - security_invariant:
      id: displayed-sandbox-equals-enforced-sandbox

  - state_invariant:
      id: no-unexpected-state-migration

normalization:
  rules:
    - process-identities
    - window-handles
    - request-ids
    - user-home
    - temporary-paths
    - timestamps-to-logical-time
    - redact-authentication
    - redact-environment-secrets

exceptions:
  allowed: []
```

## C.3 Operations

Representative operations:

```yaml
- launch: {}
- close_application: {}
- kill_process: {}
- restart_component: {}
- wait_for: {}
- click: {}
- type_text: {}
- press_key: {}
- invoke_menu: {}
- select_file_dialog: {}
- open_project: {}
- start_codex_thread: {}
- start_codex_turn: {}
- cancel_codex_turn: {}
- respond_to_approval: {}
- start_mcp_fixture: {}
- stop_mcp_fixture: {}
- create_worktree: {}
- run_scheduled_task: {}
- navigate_browser_surface: {}
- capture_screenshot: {}
- capture_accessibility_tree: {}
- capture_process_baseline: {}
- capture_process_snapshot: {}
- wait_for_process_quiescence: {}
- simulate_network_loss: {}
- simulate_sleep_resume: {}
- simulate_renderer_crash: {}
- simulate_runtime_crash: {}
- install_candidate_build: {}
- promote_candidate: {}
- rollback_build: {}
```

Each operation has a Rust handler and MAY have an adapter-specific extension. Adapter extensions run through constrained test interfaces, not arbitrary production backdoors.

## C.4 Semantic events

Generic:

```text
application.discovered
application.starting
application.ready
application.quitting
application.exited
runtime.started
runtime.crashed
renderer.created
renderer.ready
renderer.crashed
window.created
window.closed
state.migration.started
state.migration.completed
update.candidate.detected
update.candidate.promoted
update.candidate.blocked
process.spawned
process.exited
resource.anomaly
security.capability.requested
security.capability.decided
```

OpenAI/Codex examples:

```text
openai.surface.ready
codex.app_server.started
codex.app_server.initialized
codex.thread.started
codex.thread.resumed
codex.turn.started
codex.turn.completed
codex.turn.cancelled
codex.item.started
codex.item.completed
codex.approval.requested
codex.approval.resolved
codex.mcp.starting
codex.mcp.ready
codex.mcp.failed
codex.worktree.created
codex.worktree.cleaned
codex.browser.created
codex.browser.closed
codex.sandbox.mode_selected
codex.sandbox.setup_requested
```

Semantic events are derived from documented protocol, adapter observation, or reliable UI/runtime state. They are not fabricated solely to make tests pass.

## C.5 Assertions

### Functional

```yaml
- visible:
    selector: ui-automation-or-adapter-selector

- text_equals:
    selector: ...
    expected: ...

- file_exists: ...
- file_content: ...
- git_diff: ...
- window_count: ...
- notification_received: ...
- protocol_activation_delivered: ...
```

### Process/resource

```yaml
- no_orphan_processes: ...
- process_count_range: ...
- helper_count_range: ...
- private_commit_peak: ...
- private_commit_slope: ...
- cpu_idle_average: ...
- handle_slope: ...
- renderer_count_range: ...
```

### Security/state

```yaml
- capability_denied: ...
- origin_cannot_invoke: ...
- cross_app_handle_rejected: ...
- sandbox_operation_denied: ...
- approval_identity_preserved: ...
- no_secret_in_trace: ...
- rollback_status: ...
- state_schema_unchanged: ...
```

### Differential

```yaml
- trace_equivalent:
    vendor: "${VENDOR_TRACE}"
    weregopher: "${WEREGOPHER_TRACE}"
    profile: electron-main-lifecycle

- visual_equivalent:
    vendor_checkpoint: main-window
    weregopher_checkpoint: main-window
    tolerance_profile: packaged-renderer
```

## C.6 Scenario safety

Scenarios declare destructive capabilities. The runner refuses destructive tests outside disposable fixtures unless explicitly authorized.

```yaml
safety:
  filesystem_scope: fixture-only
  network_scope: configured-test-accounts
  may_modify_system_sandbox: false
  may_install_extensions: false
  may_delete_worktrees: fixture-only
  may_send_external_messages: false
```

## C.7 Reproducibility

The runner records:

- resolved scenario version/hash;
- package/build fingerprint;
- adapter lock;
- runtime/renderer versions;
- environment and Windows build;
- fixture hashes;
- state epoch;
- timing and retries;
- trace/resource outputs;
- every exception applied.

---

# Appendix D: research bibliography

The research links below are the primary sources used for the architectural claims. Application versions are intentionally not hard-coded as authoritative in this specification; installed-package discovery is authoritative.

## D.1 Electron

**[R1] Electron process model.** Main process, renderer processes, preload scripts, context bridge, and utility-process model.  
[Electron — Process Model](https://www.electronjs.org/docs/latest/tutorial/process-model)

**[R2] Electron ASAR archives.** Virtual filesystem behavior, limitations, and materialization requirements.  
[Electron — ASAR Archives](https://www.electronjs.org/docs/latest/tutorial/asar-archives)

**[R3] Electron context isolation.** Separate preload/page contexts and contextBridge security model.  
[Electron — Context Isolation](https://www.electronjs.org/docs/latest/tutorial/context-isolation)

**[R4] Electron native Node modules.** ABI/rebuild considerations for native modules.  
[Electron — Using Native Node Modules](https://www.electronjs.org/docs/latest/tutorial/using-native-node-modules)

**[R26] Electron session API.** Partitions, storage, protocols, web requests, and browser session behavior.  
[Electron — Session](https://www.electronjs.org/docs/latest/api/session)

## D.2 Microsoft Windows and WebView2

**[R5] WebView2 user-data folders.** Shared UDF process/resource implications and application coordination.  
[Microsoft Learn — Manage user data folders](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder)

**[R6] WebView2 multiple profiles.** Profile-level separation within an environment/UDF.  
[Microsoft Learn — Multiple profiles for WebView2 apps](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/multi-profile-support)

**[R7] WebView2 process model and environment sharing.** Browser/renderer/GPU/utility process architecture.  
[Microsoft Learn — Process model for WebView2 apps](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/process-model)

**[R8] WebView2 distribution.** Evergreen and Fixed Version deployment models.  
[Microsoft Learn — Distribute your app and the WebView2 Runtime](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)

**[R23] Windows PackageCatalog update events.** Current-user package update observation.  
[Microsoft Learn — PackageCatalog.PackageUpdating](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.packagecatalog.packageupdating)

**[R24] Windows named-pipe security.** Security descriptors and default access implications.  
[Microsoft Learn — Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)

**[R25] Windows process memory counters.** `PROCESS_MEMORY_COUNTERS_EX.PrivateUsage` and process-memory accounting.  
[Microsoft Learn — PROCESS_MEMORY_COUNTERS_EX](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex)

**[R27] WebView2 feature overview.** Request interception, scripting, messaging, CDP, profiles, and browser features.  
[Microsoft Learn — WebView2 features and APIs overview](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/overview-features-apis)

## D.3 CEF

**[R9] Chromium Embedded Framework architecture.** Stable embedding API, process model, and integration guidance.  
[CEF — General Usage](https://chromiumembedded.github.io/cef/general_usage.html)

## D.4 QuickJS, Rust, LLRT, and Bun

**[R10] QuickJS-NG.** Embeddable JavaScript engine project and documentation.  
[QuickJS-NG](https://quickjs-ng.github.io/quickjs/)

**[R11] `rquickjs`.** Rust bindings, runtime/context abstractions, async support, and module loader hooks.  
[`rquickjs` repository](https://github.com/DelSkayn/rquickjs)

**[R12] LLRT.** Rust/QuickJS runtime with partial Node-style APIs and an explicit non-drop-in-Node scope.  
[LLRT repository](https://github.com/awslabs/llrt)

**[R13] Bun plugins.** Module-resolution and module-loading plugin hooks.  
[Bun — Plugins](https://bun.sh/docs/runtime/plugins)

**[R14] Bun Node compatibility.** Bun’s documented Node API compatibility scope.  
[Bun — Node.js compatibility](https://bun.sh/docs/runtime/nodejs-apis)

## D.5 Prior art

**[R15] Electrico.** Experimental Rust/WRY Electron and Node compatibility container.  
[Electrico repository](https://github.com/thomastschurtschenthaler/electrico)

**[R16] Electrobun.** Bun main process, native webviews, RPC, windows, and optional CEF architecture.  
[Electrobun repository](https://github.com/blackboardsh/electrobun)

**[R17] DeskGap.** Node plus system-webview desktop framework with Electron-shaped APIs.  
[DeskGap repository](https://github.com/wan9chi/DeskGap)

## D.6 OpenAI Codex and Windows desktop

**[R18] Codex app-server.** JSON-RPC-like protocol, JSONL stdio transport, initialization, schema generation, and transport behavior.  
[OpenAI Developers — Codex app-server](https://developers.openai.com/codex/app-server)

**[R19] Codex Windows app.** Windows desktop workflows including native/WSL execution and application capabilities.  
[OpenAI Developers — Codex on Windows](https://developers.openai.com/codex/windows/windows-app)

**[R20] Codex Windows sandbox.** Native Windows sandbox implementations and boundaries.  
[OpenAI Developers — Windows sandbox](https://developers.openai.com/codex/windows/windows-sandbox)

**[R21] Codex Git worktrees.** Worktree-based parallel workflows and handoff behavior.  
[OpenAI Developers — Git worktrees](https://developers.openai.com/codex/environments/git-worktrees)

**[R22] Codex plugins.** Plugins, skills, connectors/MCP, browser extensions, hooks, and scheduled templates.  
[OpenAI Developers — Plugins](https://developers.openai.com/codex/plugins)

**[R28] Introducing the Codex app.** Multi-agent workflows, worktrees, skills, and shared Codex history/configuration context.  
[OpenAI — Introducing the Codex app](https://openai.com/index/introducing-the-codex-app/)

**[R29] OpenAI Codex repository.** Source for Codex CLI/core/app-server and Apache-2.0 licensing.  
[OpenAI Codex repository](https://github.com/openai/codex)

## D.7 Source-available target applications

**[R30] Blockbench repository.** GPL-3.0 source and Electron desktop application implementation.  
[Blockbench repository](https://github.com/JannisX11/blockbench)

**[R31] GitHub Desktop repository.** MIT-licensed Electron/TypeScript/React desktop application source.  
[GitHub Desktop repository](https://github.com/desktop/desktop)

**[R32] Visual Studio Code repository.** MIT-licensed Code-OSS source and product architecture; Microsoft-distributed VS Code includes product-specific configuration and licensing outside the generic source tree.  
[Visual Studio Code repository](https://github.com/microsoft/vscode)

## D.8 Research-use notes

- Verify current documentation and redistribution terms before shipping WebView2 Fixed Version, CEF, Bun, QuickJS-NG, or vendor components.
- Preserve third-party licenses and notices.
- Public source availability does not automatically grant rights to proprietary branded distributions or service-specific assets.
- For OpenAI product/API behavior, use current official OpenAI documentation and the exact bundled app-server schema as the source of truth.
- For installed application versions, use the scanner and build fingerprint, not this document.


## D.9 Reference link definitions

[R1]: https://www.electronjs.org/docs/latest/tutorial/process-model
[R2]: https://www.electronjs.org/docs/latest/tutorial/asar-archives
[R3]: https://www.electronjs.org/docs/latest/tutorial/context-isolation
[R4]: https://www.electronjs.org/docs/latest/tutorial/using-native-node-modules
[R5]: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder
[R6]: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/multi-profile-support
[R7]: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/process-model
[R8]: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution
[R9]: https://chromiumembedded.github.io/cef/general_usage.html
[R10]: https://quickjs-ng.github.io/quickjs/
[R11]: https://github.com/DelSkayn/rquickjs
[R12]: https://github.com/awslabs/llrt
[R13]: https://bun.sh/docs/runtime/plugins
[R14]: https://bun.sh/docs/runtime/nodejs-apis
[R15]: https://github.com/thomastschurtschenthaler/electrico
[R16]: https://github.com/blackboardsh/electrobun
[R17]: https://github.com/wan9chi/DeskGap
[R18]: https://developers.openai.com/codex/app-server
[R19]: https://developers.openai.com/codex/windows/windows-app
[R20]: https://developers.openai.com/codex/windows/windows-sandbox
[R21]: https://developers.openai.com/codex/environments/git-worktrees
[R22]: https://developers.openai.com/codex/plugins
[R23]: https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.packagecatalog.packageupdating
[R24]: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
[R25]: https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex
[R26]: https://www.electronjs.org/docs/latest/api/session
[R27]: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/overview-features-apis
[R28]: https://openai.com/index/introducing-the-codex-app/
[R29]: https://github.com/openai/codex
[R30]: https://github.com/JannisX11/blockbench
[R31]: https://github.com/desktop/desktop
[R32]: https://github.com/microsoft/vscode

---

**End of specification.**

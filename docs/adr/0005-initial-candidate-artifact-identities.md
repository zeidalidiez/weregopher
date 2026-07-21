# ADR-0005: Bind initial candidate rules to observed artifact identities

- Status: Accepted
- Date: 2026-07-21

## Context

Candidate names, executable names, and familiar directories are weak signals. Weregopher needs maintained artifact-family rules before it can turn discovery observations into package-verification inputs. Those rules must remain narrower than compatibility or authenticity claims, and fast-moving package versions must not become permanent family allowlists.

The initial candidate set includes Codex and Hermes Agent, but they use different Windows packaging models. Codex is installed through the Windows package catalog. Hermes Desktop is built with Electron Builder for both NSIS and MSI, and the NSIS configuration permits a user-selected installation directory.

## Evidence baseline

On 2026-07-21, a read-only Windows package-catalog query and the installed package manifest established this Codex package observation:

- package name `OpenAI.Codex`;
- package family `OpenAI.Codex_2p2nqsd0c76g0`;
- publisher identifier `2p2nqsd0c76g0`;
- application identifier `App`;
- observed package full name `OpenAI.Codex_26.715.8383.0_x64__2p2nqsd0c76g0`;
- manifest executable `app/ChatGPT.exe`;
- manifest protocol `codex`;
- fixed package markers `AppxManifest.xml` and `app/resources/app.asar`.

The versioned package full name records the observed build. It is not a durable allowlist and does not generalize to an unrelated application named Codex.

Hermes Desktop source metadata was inspected from the clean upstream checkout of `NousResearch/hermes-agent` at commit `a41d280f95c69f67380358b305b62345934ecaf3`, specifically `apps/desktop/package.json`. It establishes:

- product and executable name `Hermes`;
- author/publisher name `Nous Research`;
- application identifier `com.nousresearch.hermes`;
- main entry `dist/electron-main.mjs`;
- Electron Builder `^26.8.1` with Windows NSIS and MSI targets;
- ASAR packaging with `dist/**` unpacked;
- an extra resource named `install-stamp.json`;
- NSIS support for changing the installation directory.

A local unpacked build from that source established the fixed packaged layout `Hermes.exe`, `resources/app.asar`, `resources/app.asar.unpacked/dist/electron-main.mjs`, and `resources/install-stamp.json`. This is build-layout evidence, not proof of a separately installed or signed release.

## Decision

Weregopher supports Codex verification inputs only when correlated evidence contains the exact maintained package name, family, publisher identifier, application identifier, MSIX installation kind, and package-catalog provenance above. Verification then performs bounded checks of the fixed observed package layout. The current version string is preserved as evidence but is not hard-coded as the family identity.

Weregopher recognizes the default current-user NSIS location `%LOCALAPPDATA%/Programs/Hermes` only when `Hermes.exe` is a direct file. It also recognizes uninstall records whose display name is exactly `Hermes` or `Hermes <version>`, whose publisher is exactly `Nous Research`, whose installation root is absolute, and whose root contains a direct `Hermes.exe` marker. The uninstall record alone cannot distinguish NSIS from MSI, so its installation kind remains `Unknown`; no installer technology is invented.

Hermes verification accepts source-backed NSIS, MSI, or unknown-installer evidence and requires the complete fixed packaged layout listed above. It does not inspect a source checkout as an installed candidate, recursively search arbitrary roots, or infer identity from the word `Hermes` alone.

For every candidate:

1. discovery and layout inspection remain read-only and bounded;
2. original source observations and confidence values are retained;
3. absolute roots and direct fixed marker paths are required;
4. conflicting package identity, channel, or unsupported installer evidence fails closed;
5. symbolic-link and tested Windows junction traversal remain rejected by the maintained path probe;
6. layout presence is not signer trust, package coherence, Electron compatibility, transformability, or certification.

## Consequences

- Codex rules are durable across version updates that preserve the maintained package family and application identity.
- Hermes custom NSIS roots and MSI roots can be found through uninstall metadata without guessing arbitrary filesystem locations.
- Hermes uninstall evidence truthfully records an unknown installer kind unless another source identifies it.
- A future Codex package family, Hermes publisher/configuration change, or materially different layout requires new direct evidence and a superseding rule or ADR.
- Exact artifact hashes and coherent package leases remain later fingerprinting responsibilities; this decision only establishes bounded verification inputs.

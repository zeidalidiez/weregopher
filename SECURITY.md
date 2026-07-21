# Security policy

Weregopher executes and transforms desktop application code. Security reports should be treated as potentially sensitive.

## Reporting

Do not open a public issue for a vulnerability that could expose credentials, cross application boundaries, escalate privileges, bypass approval or sandbox semantics, or execute untrusted native code. Contact the maintainers privately through the repository security-advisory channel.

Include the Weregopher version, adapter/build fingerprint, runtime and renderer versions, Windows build, reproduction steps, and a redacted diagnostic bundle where possible. Never include authentication tokens or proprietary package contents.

## Current security status

The project is pre-release. No current adapter should be assumed to provide stronger isolation than the original vendor application. Bun workers, vendor helpers, and native compatibility components are unrestricted same-user processes unless a certification record explicitly proves OS confinement.

## Supported versions

No production version is supported yet. This section will be replaced by a version support table before the first public security-supported release.

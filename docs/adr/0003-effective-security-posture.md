# ADR-0003: Effective execution security posture

- Status: Accepted
- Date: 2026-07-20

## Context

Brokered QuickJS APIs can enforce Weregopher capabilities. Bun, vendor helpers, ABI islands, and ordinary same-user native processes can bypass JavaScript shims and Job Objects.

## Decision

Every executable component declares one effective posture:

- `broker_mediated`: all relevant host effects cross an enforcing Weregopher broker;
- `os_contained`: independently tested operating-system controls bound direct host access;
- `vendor_equivalent_full_trust`: unrestricted access available to the current Windows user.

Job Objects count and own processes but do not confer containment. Compatibility interception is not authorization. A component is never advertised as capability-limited without direct native-bypass tests proving the enforcement mechanism.

Generated overlays are authority-nonexpanding: they may only rebind and materialize behavior already authorized by a signed adapter rule set.

## Consequences

Security posture is recorded per component and surfaced in certification. Full-trust components can be supported, but no cross-profile filesystem or network isolation claim is made for them.

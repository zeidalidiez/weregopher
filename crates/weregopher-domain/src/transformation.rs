//! Build-bound semantic-transform rebinding contracts.
//!
//! Custom map visitors bound retained domain entries. Callers that parse hostile transport bytes
//! must also impose an outer byte/read limit before invoking Serde.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{Error as _, IgnoredAny, MapAccess, Visitor},
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::{AdapterId, ApplicationFamilyId, Sha256Digest, SourceUnitId, TransformRuleId};

/// Current serialized transform-rebinding contract version.
pub const TRANSFORM_REBINDING_FORMAT_VERSION: &str = "1";
/// Maximum signed transform rules in one adapter authority contract.
pub const MAX_AUTHORIZED_TRANSFORM_RULES: usize = 128;
/// Maximum generated transform rebindings in one build overlay.
pub const MAX_GENERATED_TRANSFORM_REBINDINGS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
enum TransformRebindingFormatVersion {
    #[serde(rename = "1")]
    V1,
}

/// Platform accepted by transform-rebinding format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformPlatform {
    /// Microsoft Windows under the initial release profile.
    Windows,
}

/// Architecture accepted by transform-rebinding format version 1.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformArchitecture {
    /// AMD64/x86-64 under the initial release profile.
    X86_64,
}

/// One semantic transform rule declared by a static adapter artifact.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedTransformRuleRef {
    rule_digest: Sha256Digest,
}

impl AuthorizedTransformRuleRef {
    /// Constructs an immutable reference to a static semantic-transform rule.
    #[must_use]
    pub const fn new(rule_digest: Sha256Digest) -> Self {
        Self { rule_digest }
    }

    /// Returns the digest committing to the rule's matcher, implementation, and assumptions.
    #[must_use]
    pub const fn rule_digest(&self) -> &Sha256Digest {
        &self.rule_digest
    }
}

/// Static semantic-transform authority declared by one adapter artifact.
///
/// This transport does not authenticate the authority artifact. Consumers must establish trust
/// in the exact serialized artifact through the separate canonical authority path.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterTransformAuthority {
    format_version: TransformRebindingFormatVersion,
    adapter_id: AdapterId,
    family: ApplicationFamilyId,
    adapter_content_digest: Sha256Digest,
    #[schemars(extend("minProperties" = 1, "maxProperties" = 128))]
    rules: BTreeMap<TransformRuleId, AuthorizedTransformRuleRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterTransformAuthorityTransport {
    format_version: TransformRebindingFormatVersion,
    adapter_id: AdapterId,
    family: ApplicationFamilyId,
    adapter_content_digest: Sha256Digest,
    #[serde(deserialize_with = "deserialize_authorized_transform_rules")]
    rules: BTreeMap<TransformRuleId, AuthorizedTransformRuleRef>,
}

fn deserialize_authorized_transform_rules<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<TransformRuleId, AuthorizedTransformRuleRef>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RulesVisitor;

    impl<'de> Visitor<'de> for RulesVisitor {
        type Value = BTreeMap<TransformRuleId, AuthorizedTransformRuleRef>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of static semantic-transform rules")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|length| length > MAX_AUTHORIZED_TRANSFORM_RULES)
            {
                return Err(A::Error::custom(
                    TransformContractError::TooManyTransformRules,
                ));
            }

            let mut rules = BTreeMap::new();
            while rules.len() < MAX_AUTHORIZED_TRANSFORM_RULES {
                let Some(rule_id) = map.next_key()? else {
                    return Ok(rules);
                };
                if rules.contains_key(&rule_id) {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(A::Error::custom(
                        "adapter transform authority contains duplicate rule identifiers",
                    ));
                }
                let rule = map.next_value()?;
                rules.insert(rule_id, rule);
            }
            if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    TransformContractError::TooManyTransformRules,
                ));
            }
            Ok(rules)
        }
    }

    deserializer.deserialize_map(RulesVisitor)
}

impl<'de> Deserialize<'de> for AdapterTransformAuthority {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let AdapterTransformAuthorityTransport {
            format_version,
            adapter_id,
            family,
            adapter_content_digest,
            rules,
        } = AdapterTransformAuthorityTransport::deserialize(deserializer)?;
        match format_version {
            TransformRebindingFormatVersion::V1 => {
                Self::new(adapter_id, family, adapter_content_digest, rules)
                    .map_err(serde::de::Error::custom)
            }
        }
    }
}

impl AdapterTransformAuthority {
    /// Constructs a static transform-authority contract.
    ///
    /// # Errors
    ///
    /// Returns [`TransformContractError`] when the rule map violates contract limits.
    pub fn new(
        adapter_id: AdapterId,
        family: ApplicationFamilyId,
        adapter_content_digest: Sha256Digest,
        rules: BTreeMap<TransformRuleId, AuthorizedTransformRuleRef>,
    ) -> Result<Self, TransformContractError> {
        if rules.is_empty() {
            return Err(TransformContractError::EmptyTransformAuthority);
        }
        if rules.len() > MAX_AUTHORIZED_TRANSFORM_RULES {
            return Err(TransformContractError::TooManyTransformRules);
        }
        Ok(Self {
            format_version: TransformRebindingFormatVersion::V1,
            adapter_id,
            family,
            adapter_content_digest,
            rules,
        })
    }

    /// Returns the canonical adapter identifier.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    /// Returns the application family covered by this authority contract.
    #[must_use]
    pub const fn family(&self) -> &ApplicationFamilyId {
        &self.family
    }

    /// Returns the exact adapter artifact identity.
    #[must_use]
    pub const fn adapter_content_digest(&self) -> &Sha256Digest {
        &self.adapter_content_digest
    }

    /// Returns authorized semantic-transform rules in canonical order.
    #[must_use]
    pub const fn rules(&self) -> &BTreeMap<TransformRuleId, AuthorizedTransformRuleRef> {
        &self.rules
    }

    /// Computes the SHA-256 digest of this format-v1 authority's canonical JSON bytes.
    ///
    /// This binds validation to the exact authority object. It does not authenticate the
    /// resulting digest or establish trust in the adapter artifact that supplied the object.
    #[must_use]
    pub fn canonical_document_digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(b"{\"format_version\":\"");
        hasher.update(TRANSFORM_REBINDING_FORMAT_VERSION.as_bytes());
        hasher.update(b"\",\"adapter_id\":\"");
        hasher.update(self.adapter_id.as_str().as_bytes());
        hasher.update(b"\",\"family\":\"");
        hasher.update(self.family.as_str().as_bytes());
        hasher.update(b"\",\"adapter_content_digest\":\"");
        update_canonical_digest_text(&mut hasher, &self.adapter_content_digest);
        hasher.update(b"\",\"rules\":{");

        let mut first = true;
        for (rule_id, rule) in &self.rules {
            if first {
                first = false;
            } else {
                hasher.update(b",");
            }
            hasher.update(b"\"");
            hasher.update(rule_id.as_str().as_bytes());
            hasher.update(b"\":{\"rule_digest\":\"");
            update_canonical_digest_text(&mut hasher, rule.rule_digest());
            hasher.update(b"\"}");
        }
        hasher.update(b"}}");

        Sha256Digest::from_bytes(hasher.finalize().into())
    }
}

fn update_canonical_digest_text(hasher: &mut Sha256, digest: &Sha256Digest) {
    hasher.update(b"sha256:");
    hasher.update(hex::encode(digest.as_bytes()).as_bytes());
}

/// Exact source unit selected for one authenticated static transform rule.
#[derive(Clone, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceUnitRef {
    unit_id: SourceUnitId,
    source_digest: Sha256Digest,
}

impl SourceUnitRef {
    /// Constructs a content-addressed source-unit reference.
    #[must_use]
    pub const fn new(unit_id: SourceUnitId, source_digest: Sha256Digest) -> Self {
        Self {
            unit_id,
            source_digest,
        }
    }

    /// Returns the build-descriptor source-unit identifier.
    #[must_use]
    pub const fn unit_id(&self) -> &SourceUnitId {
        &self.unit_id
    }

    /// Returns the exact source content identity.
    #[must_use]
    pub const fn source_digest(&self) -> &Sha256Digest {
        &self.source_digest
    }
}

/// Generated evidence binding one static semantic transform to one exact source unit.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformRebinding {
    rule_digest: Sha256Digest,
    source: SourceUnitRef,
    match_evidence_digest: Sha256Digest,
    transformed_source_digest: Sha256Digest,
    source_map_digest: Sha256Digest,
    audit_log_digest: Sha256Digest,
}

impl TransformRebinding {
    /// Constructs a generated transform rebinding from content-addressed artifacts.
    #[must_use]
    pub const fn new(
        rule_digest: Sha256Digest,
        source: SourceUnitRef,
        match_evidence_digest: Sha256Digest,
        transformed_source_digest: Sha256Digest,
        source_map_digest: Sha256Digest,
        audit_log_digest: Sha256Digest,
    ) -> Self {
        Self {
            rule_digest,
            source,
            match_evidence_digest,
            transformed_source_digest,
            source_map_digest,
            audit_log_digest,
        }
    }

    /// Returns the exact static rule identity.
    #[must_use]
    pub const fn rule_digest(&self) -> &Sha256Digest {
        &self.rule_digest
    }

    /// Returns the exact selected source unit.
    #[must_use]
    pub const fn source(&self) -> &SourceUnitRef {
        &self.source
    }

    /// Returns the exact semantic-match evidence identity.
    #[must_use]
    pub const fn match_evidence_digest(&self) -> &Sha256Digest {
        &self.match_evidence_digest
    }

    /// Returns the exact transformed-source artifact identity.
    #[must_use]
    pub const fn transformed_source_digest(&self) -> &Sha256Digest {
        &self.transformed_source_digest
    }

    /// Returns the exact source-map artifact identity.
    #[must_use]
    pub const fn source_map_digest(&self) -> &Sha256Digest {
        &self.source_map_digest
    }

    /// Returns the exact transform audit-log artifact identity.
    #[must_use]
    pub const fn audit_log_digest(&self) -> &Sha256Digest {
        &self.audit_log_digest
    }
}

/// Immutable identities binding generated transform evidence to exact source and adapter inputs.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformOverlayBinding {
    source_build_fingerprint_digest: Sha256Digest,
    family: ApplicationFamilyId,
    adapter_id: AdapterId,
    adapter_content_digest: Sha256Digest,
    adapter_transform_authority_digest: Sha256Digest,
    build_descriptor_digest: Sha256Digest,
}

impl TransformOverlayBinding {
    /// Constructs exact immutable identities for one generated transform overlay.
    #[must_use]
    pub const fn new(
        source_build_fingerprint_digest: Sha256Digest,
        family: ApplicationFamilyId,
        adapter_id: AdapterId,
        adapter_content_digest: Sha256Digest,
        adapter_transform_authority_digest: Sha256Digest,
        build_descriptor_digest: Sha256Digest,
    ) -> Self {
        Self {
            source_build_fingerprint_digest,
            family,
            adapter_id,
            adapter_content_digest,
            adapter_transform_authority_digest,
            build_descriptor_digest,
        }
    }

    /// Returns the exact source build-fingerprint artifact identity.
    #[must_use]
    pub const fn source_build_fingerprint_digest(&self) -> &Sha256Digest {
        &self.source_build_fingerprint_digest
    }

    /// Returns the durable application family.
    #[must_use]
    pub const fn family(&self) -> &ApplicationFamilyId {
        &self.family
    }

    /// Returns the durable adapter identifier.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    /// Returns the exact adapter artifact identity.
    #[must_use]
    pub const fn adapter_content_digest(&self) -> &Sha256Digest {
        &self.adapter_content_digest
    }

    /// Returns the exact static transform-authority document identity.
    #[must_use]
    pub const fn adapter_transform_authority_digest(&self) -> &Sha256Digest {
        &self.adapter_transform_authority_digest
    }

    /// Returns the exact source build-descriptor artifact identity.
    #[must_use]
    pub const fn build_descriptor_digest(&self) -> &Sha256Digest {
        &self.build_descriptor_digest
    }
}

/// Generated per-build semantic-transform overlay evidence.
///
/// This is content-addressed structural evidence, not transformation or execution authority.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedTransformOverlay {
    format_version: TransformRebindingFormatVersion,
    platform: TransformPlatform,
    architecture: TransformArchitecture,
    binding: TransformOverlayBinding,
    #[schemars(extend("minProperties" = 1, "maxProperties" = 128))]
    rebindings: BTreeMap<TransformRuleId, TransformRebinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GeneratedTransformOverlayTransport {
    format_version: TransformRebindingFormatVersion,
    platform: TransformPlatform,
    architecture: TransformArchitecture,
    binding: TransformOverlayBinding,
    #[serde(deserialize_with = "deserialize_transform_rebindings")]
    rebindings: BTreeMap<TransformRuleId, TransformRebinding>,
}

fn deserialize_transform_rebindings<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<TransformRuleId, TransformRebinding>, D::Error>
where
    D: Deserializer<'de>,
{
    struct RebindingsVisitor;

    impl<'de> Visitor<'de> for RebindingsVisitor {
        type Value = BTreeMap<TransformRuleId, TransformRebinding>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map of generated semantic-transform rebindings")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            if map
                .size_hint()
                .is_some_and(|length| length > MAX_GENERATED_TRANSFORM_REBINDINGS)
            {
                return Err(A::Error::custom(
                    TransformContractError::TooManyTransformRebindings,
                ));
            }

            let mut rebindings = BTreeMap::new();
            while rebindings.len() < MAX_GENERATED_TRANSFORM_REBINDINGS {
                let Some(rule_id) = map.next_key()? else {
                    return Ok(rebindings);
                };
                if rebindings.contains_key(&rule_id) {
                    let _: IgnoredAny = map.next_value()?;
                    return Err(A::Error::custom(
                        "generated transform overlay contains duplicate rule identifiers",
                    ));
                }
                let rebinding = map.next_value()?;
                rebindings.insert(rule_id, rebinding);
            }
            if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                return Err(A::Error::custom(
                    TransformContractError::TooManyTransformRebindings,
                ));
            }
            Ok(rebindings)
        }
    }

    deserializer.deserialize_map(RebindingsVisitor)
}

impl<'de> Deserialize<'de> for GeneratedTransformOverlay {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let GeneratedTransformOverlayTransport {
            format_version,
            platform,
            architecture,
            binding,
            rebindings,
        } = GeneratedTransformOverlayTransport::deserialize(deserializer)?;
        match (format_version, platform, architecture) {
            (
                TransformRebindingFormatVersion::V1,
                TransformPlatform::Windows,
                TransformArchitecture::X86_64,
            ) => Self::windows_x64(binding, rebindings).map_err(serde::de::Error::custom),
        }
    }
}

impl GeneratedTransformOverlay {
    /// Constructs the only transform-overlay target accepted by format version 1.
    ///
    /// # Errors
    ///
    /// Returns [`TransformContractError`] when the rebinding map violates contract limits.
    pub fn windows_x64(
        binding: TransformOverlayBinding,
        rebindings: BTreeMap<TransformRuleId, TransformRebinding>,
    ) -> Result<Self, TransformContractError> {
        if rebindings.is_empty() {
            return Err(TransformContractError::EmptyTransformOverlay);
        }
        if rebindings.len() > MAX_GENERATED_TRANSFORM_REBINDINGS {
            return Err(TransformContractError::TooManyTransformRebindings);
        }
        let mut source_units = BTreeSet::new();
        for rebinding in rebindings.values() {
            if !source_units.insert(&rebinding.source.unit_id) {
                return Err(TransformContractError::DuplicateSourceUnit);
            }
        }
        Ok(Self {
            format_version: TransformRebindingFormatVersion::V1,
            platform: TransformPlatform::Windows,
            architecture: TransformArchitecture::X86_64,
            binding,
            rebindings,
        })
    }

    /// Verifies that the generated overlay only rebinds rules from the supplied authority.
    ///
    /// This structural check binds the overlay to caller-supplied exact source identities and
    /// the supplied authority's computed canonical document digest. It does not authenticate
    /// artifacts, execute a matcher, establish complete rule coverage, authorize transformation,
    /// or authorize launch.
    ///
    /// # Errors
    ///
    /// Returns [`TransformContractError`] when identities or rule bindings do not match.
    pub fn validate_against(
        &self,
        authority: &AdapterTransformAuthority,
        source_build_fingerprint_digest: Sha256Digest,
        build_descriptor_digest: Sha256Digest,
    ) -> Result<(), TransformContractError> {
        if self.binding.source_build_fingerprint_digest != source_build_fingerprint_digest {
            return Err(TransformContractError::SourceBuildMismatch);
        }
        if self.binding.build_descriptor_digest != build_descriptor_digest {
            return Err(TransformContractError::BuildDescriptorMismatch);
        }
        if self.binding.adapter_id != authority.adapter_id
            || self.binding.family != authority.family
            || self.binding.adapter_content_digest != authority.adapter_content_digest
        {
            return Err(TransformContractError::AuthorityIdentityMismatch);
        }
        if self.binding.adapter_transform_authority_digest != authority.canonical_document_digest()
        {
            return Err(TransformContractError::AuthorityDigestMismatch);
        }
        for (rule_id, rebinding) in &self.rebindings {
            let authorized_rule = authority
                .rules
                .get(rule_id)
                .ok_or(TransformContractError::UnknownTransformRule)?;
            if authorized_rule.rule_digest != rebinding.rule_digest {
                return Err(TransformContractError::TransformRuleDigestMismatch);
            }
        }
        Ok(())
    }

    /// Returns generated transform rebindings in canonical order.
    #[must_use]
    pub const fn rebindings(&self) -> &BTreeMap<TransformRuleId, TransformRebinding> {
        &self.rebindings
    }

    /// Returns the exact source and adapter identities for this overlay.
    #[must_use]
    pub const fn binding(&self) -> &TransformOverlayBinding {
        &self.binding
    }
}

/// Error constructing or structurally validating transform-rebinding contracts.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum TransformContractError {
    /// The static authority did not declare any transform rules.
    #[error("adapter transform authority must declare at least one rule")]
    EmptyTransformAuthority,
    /// The static authority exceeded the rule limit.
    #[error("adapter transform authority exceeds the rule limit")]
    TooManyTransformRules,
    /// The generated overlay did not contain any rebindings.
    #[error("generated transform overlay must contain at least one rebinding")]
    EmptyTransformOverlay,
    /// The generated overlay exceeded the rebinding limit.
    #[error("generated transform overlay exceeds the rebinding limit")]
    TooManyTransformRebindings,
    /// Two generated rules selected the same source unit.
    #[error("generated transform overlay targets one source unit more than once")]
    DuplicateSourceUnit,
    /// The overlay referenced a different source build.
    #[error("generated transform overlay references a different source build")]
    SourceBuildMismatch,
    /// The overlay referenced a different build-descriptor artifact.
    #[error("generated transform overlay references a different build descriptor")]
    BuildDescriptorMismatch,
    /// An overlay identity did not match its static authority.
    #[error("generated transform overlay identity does not match adapter authority")]
    AuthorityIdentityMismatch,
    /// The canonical authority document digest did not match the overlay.
    #[error("generated transform overlay references a different authority artifact")]
    AuthorityDigestMismatch,
    /// An overlay referenced a rule absent from the static authority.
    #[error("generated transform overlay references an unknown transform rule")]
    UnknownTransformRule,
    /// An overlay substituted the content of a known static rule.
    #[error("generated transform overlay rule digest does not match static authority")]
    TransformRuleDigestMismatch,
}

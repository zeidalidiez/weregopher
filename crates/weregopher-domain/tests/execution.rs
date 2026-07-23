//! Authority-nonexpanding execution-artifact rebinding contract tests.

use std::collections::BTreeMap;

use serde_json::json;
use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterExecutionAuthority, AdapterId, ApplicationFamilyId, AuthorizedExecutionTargetRef,
    EXECUTION_REBINDING_FORMAT_VERSION, ExecutionArtifactBinding, ExecutionArtifactDigests,
    ExecutionArtifactSource, ExecutionContractError, ExecutionOverlayBinding,
    ExecutionOverlayContext, ExecutionTargetId, ExecutionTargetKind, GeneratedExecutionOverlay,
    MAX_AUTHORIZED_EXECUTION_TARGETS, MAX_GENERATED_EXECUTION_BINDINGS, Sha256Digest,
};

#[test]
fn execution_binding_construction_uses_role_named_digest_contexts()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.allowed", digest(0x31))?;
    let context = execution_context();
    let artifact = ExecutionArtifactBinding::new(ExecutionArtifactDigests {
        execution_contract_digest: digest(0x31).into(),
        artifact_source_digest: digest(0x42).into(),
        executable_digest: digest(0x45).into(),
        resolution_evidence_digest: digest(0x46).into(),
    });
    let overlay = GeneratedExecutionOverlay::windows_x64(
        ExecutionOverlayBinding::new(context, &authority),
        BTreeMap::from([(ExecutionTargetId::new("helper.allowed")?, artifact)]),
    )?;

    overlay.validate_against(&authority, context)?;
    Ok(())
}

#[test]
fn exact_execution_binding_is_structurally_valid() -> Result<(), Box<dyn std::error::Error>> {
    let target_id = ExecutionTargetId::new("helper.codex-app-server")?;
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x11);
    let contract_digest = digest(0x12);
    let authority = AdapterExecutionAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            target_id.clone(),
            AuthorizedExecutionTargetRef::new(
                ExecutionTargetKind::VendorHelper,
                ExecutionArtifactSource::PackageSnapshot,
                contract_digest.into(),
            ),
        )]),
    )?;
    let package_tree_merkle = digest(0x21);
    let context = ExecutionOverlayContext {
        source_build_fingerprint_digest: digest(0x20),
        package_tree_merkle,
        execution_environment_digest: digest(0x22),
        build_descriptor_digest: digest(0x23),
    };
    let overlay = GeneratedExecutionOverlay::windows_x64(
        ExecutionOverlayBinding::new(context, &authority),
        BTreeMap::from([(
            target_id.clone(),
            artifact_binding(
                contract_digest,
                package_tree_merkle,
                digest(0x24),
                digest(0x25),
            ),
        )]),
    )?;

    let validated = overlay.validate_against(&authority, context)?;
    assert_eq!(validated.overlay(), &overlay);
    assert_eq!(validated.authority(), &authority);
    assert_eq!(
        serde_json::to_value(&authority)?["format_version"],
        EXECUTION_REBINDING_FORMAT_VERSION
    );
    assert_eq!(
        serde_json::to_value(&overlay)?["format_version"],
        EXECUTION_REBINDING_FORMAT_VERSION
    );
    let target = authority
        .targets()
        .get(&target_id)
        .ok_or("expected authorized target")?;
    assert_eq!(target.kind(), ExecutionTargetKind::VendorHelper);
    assert_eq!(
        target.artifact_source(),
        ExecutionArtifactSource::PackageSnapshot
    );
    let generated = overlay
        .bindings()
        .get(&target_id)
        .ok_or("expected generated binding")?;
    assert_eq!(generated.executable_digest().as_sha256(), &digest(0x24));
    assert_eq!(
        generated.resolution_evidence_digest().as_sha256(),
        &digest(0x25)
    );
    Ok(())
}

#[test]
fn generated_execution_overlay_cannot_expand_static_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.allowed", digest(0x31))?;
    let unknown = overlay("helper.generated", digest(0x31), digest(0x42))?;
    assert_eq!(
        unknown.validate_against(&authority, execution_context()),
        Err(ExecutionContractError::UnknownExecutionTarget)
    );

    let substituted = overlay("helper.allowed", digest(0xff), digest(0x42))?;
    assert_eq!(
        substituted.validate_against(&authority, execution_context()),
        Err(ExecutionContractError::ExecutionContractDigestMismatch)
    );
    Ok(())
}

#[test]
fn package_snapshot_target_must_bind_the_overlay_package_tree()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.allowed", digest(0x31))?;
    let overlay = overlay("helper.allowed", digest(0x31), digest(0xfe))?;

    assert_eq!(
        overlay.validate_against(&authority, execution_context()),
        Err(ExecutionContractError::PackageSnapshotDigestMismatch)
    );
    Ok(())
}

#[test]
fn managed_artifact_target_can_bind_a_distinct_materialization_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let target_id = ExecutionTargetId::new("runtime.main")?;
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x61);
    let contract_digest = digest(0x62);
    let authority = AdapterExecutionAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            target_id.clone(),
            AuthorizedExecutionTargetRef::new(
                ExecutionTargetKind::MainRuntime,
                ExecutionArtifactSource::ManagedArtifact,
                contract_digest.into(),
            ),
        )]),
    )?;
    let context = ExecutionOverlayContext {
        source_build_fingerprint_digest: digest(0x63),
        package_tree_merkle: digest(0x64),
        execution_environment_digest: digest(0x65),
        build_descriptor_digest: digest(0x66),
    };
    let overlay = GeneratedExecutionOverlay::windows_x64(
        ExecutionOverlayBinding::new(context, &authority),
        BTreeMap::from([(
            target_id,
            artifact_binding(contract_digest, digest(0x67), digest(0x68), digest(0x69)),
        )]),
    )?;

    overlay.validate_against(&authority, context)?;
    Ok(())
}

#[test]
fn execution_overlay_is_bound_to_every_external_context_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.allowed", digest(0x71))?;
    let overlay = overlay("helper.allowed", digest(0x71), digest(0x42))?;

    for (source, package, environment, descriptor, expected) in [
        (
            digest(0xff),
            digest(0x42),
            digest(0x43),
            digest(0x44),
            ExecutionContractError::SourceBuildMismatch,
        ),
        (
            digest(0x40),
            digest(0xff),
            digest(0x43),
            digest(0x44),
            ExecutionContractError::PackageTreeMismatch,
        ),
        (
            digest(0x40),
            digest(0x42),
            digest(0xff),
            digest(0x44),
            ExecutionContractError::ExecutionEnvironmentMismatch,
        ),
        (
            digest(0x40),
            digest(0x42),
            digest(0x43),
            digest(0xff),
            ExecutionContractError::BuildDescriptorMismatch,
        ),
    ] {
        assert_eq!(
            overlay.validate_against(
                &authority,
                ExecutionOverlayContext {
                    source_build_fingerprint_digest: source,
                    package_tree_merkle: package,
                    execution_environment_digest: environment,
                    build_descriptor_digest: descriptor,
                },
            ),
            Err(expected)
        );
    }
    Ok(())
}

#[test]
fn execution_overlay_must_reference_the_exact_authority_object()
-> Result<(), Box<dyn std::error::Error>> {
    let overlay = overlay("helper.allowed", digest(0x31), digest(0x42))?;
    let wrong_family = AdapterExecutionAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("microsoft.vscode.windows")?,
        digest(0x32),
        BTreeMap::from([(
            ExecutionTargetId::new("helper.allowed")?,
            AuthorizedExecutionTargetRef::new(
                ExecutionTargetKind::VendorHelper,
                ExecutionArtifactSource::PackageSnapshot,
                digest(0x31).into(),
            ),
        )]),
    )?;
    assert_eq!(
        overlay.validate_against(&wrong_family, execution_context()),
        Err(ExecutionContractError::AuthorityIdentityMismatch)
    );

    let substituted_contract = authority("helper.allowed", digest(0xff))?;
    assert_eq!(
        overlay.validate_against(&substituted_contract, execution_context()),
        Err(ExecutionContractError::AuthorityDigestMismatch)
    );
    Ok(())
}

#[test]
fn execution_contracts_enforce_nonempty_bounded_maps() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        AdapterExecutionAuthority::new(
            AdapterId::new("openai.desktop")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0x81),
            BTreeMap::new(),
        ),
        Err(ExecutionContractError::EmptyExecutionAuthority)
    );
    let targets = (0..=MAX_AUTHORIZED_EXECUTION_TARGETS)
        .map(|index| {
            Ok((
                ExecutionTargetId::new(format!("helper.target-{index}"))?,
                AuthorizedExecutionTargetRef::new(
                    ExecutionTargetKind::VendorHelper,
                    ExecutionArtifactSource::PackageSnapshot,
                    digest(0x82).into(),
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    assert_eq!(
        AdapterExecutionAuthority::new(
            AdapterId::new("openai.desktop")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0x83),
            targets,
        ),
        Err(ExecutionContractError::TooManyExecutionTargets)
    );

    let overlay_authority = authority("helper.fixture", digest(0x87))?;
    let overlay_context = ExecutionOverlayContext {
        source_build_fingerprint_digest: digest(0x84),
        package_tree_merkle: digest(0x85),
        execution_environment_digest: digest(0x86),
        build_descriptor_digest: digest(0x89),
    };
    assert_eq!(
        GeneratedExecutionOverlay::windows_x64(
            ExecutionOverlayBinding::new(overlay_context, &overlay_authority),
            BTreeMap::new(),
        ),
        Err(ExecutionContractError::EmptyExecutionOverlay)
    );
    let bindings = (0..=MAX_GENERATED_EXECUTION_BINDINGS)
        .map(|index| {
            Ok((
                ExecutionTargetId::new(format!("helper.target-{index}"))?,
                artifact_binding(digest(0x8a), digest(0x8b), digest(0x8c), digest(0x8d)),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    assert_eq!(
        GeneratedExecutionOverlay::windows_x64(
            ExecutionOverlayBinding::new(overlay_context, &overlay_authority),
            bindings,
        ),
        Err(ExecutionContractError::TooManyExecutionBindings)
    );
    Ok(())
}

#[test]
fn execution_transport_rejects_excess_duplicate_and_unknown_data()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.seed", digest(0x91))?;
    let mut authority_document = serde_json::to_value(&authority)?;
    let target = serde_json::to_value(AuthorizedExecutionTargetRef::new(
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactSource::PackageSnapshot,
        digest(0x92).into(),
    ))?;
    let targets = authority_document["targets"]
        .as_object_mut()
        .ok_or("serialized targets must be an object")?;
    targets.clear();
    for index in 0..MAX_AUTHORIZED_EXECUTION_TARGETS {
        targets.insert(format!("helper.target-{index:03}"), target.clone());
    }
    targets.insert("zzzz.excess".to_owned(), json!({"invalid": ["payload"]}));
    let Err(error) = serde_json::from_value::<AdapterExecutionAuthority>(authority_document) else {
        return Err("the first excess target must fail at the map boundary".into());
    };
    assert!(
        error.to_string().contains("target limit"),
        "unexpected error: {error}"
    );

    let digest_json = serde_json::to_string(&digest(0x93))?;
    let target_json = serde_json::to_string(&target)?;
    let duplicate = format!(
        r#"{{"format_version":"1","adapter_id":"openai.desktop","family":"openai.chatgpt.windows","adapter_content_digest":{digest_json},"targets":{{"helper.same":{target_json},"helper.same":{{"invalid":["payload"]}}}}}}"#
    );
    let Err(error) = serde_json::from_str::<AdapterExecutionAuthority>(&duplicate) else {
        return Err("duplicate execution target identifiers must fail closed".into());
    };
    assert!(error.to_string().contains("duplicate execution target"));

    let mut unknown = serde_json::to_value(&authority)?;
    unknown["execution_authorized"] = json!(true);
    assert!(serde_json::from_value::<AdapterExecutionAuthority>(unknown).is_err());

    let mut nested_unknown = serde_json::to_value(&authority)?;
    nested_unknown["targets"]["helper.seed"]["capabilities"] = json!(["network"]);
    assert!(serde_json::from_value::<AdapterExecutionAuthority>(nested_unknown).is_err());
    Ok(())
}

#[test]
fn generated_execution_binding_map_is_bounded_and_duplicate_strict()
-> Result<(), Box<dyn std::error::Error>> {
    let seed = overlay("helper.seed", digest(0xa1), digest(0x42))?;
    let mut document = serde_json::to_value(&seed)?;
    let generated = serde_json::to_value(artifact_binding(
        digest(0xa2),
        digest(0xa3),
        digest(0xa4),
        digest(0xa5),
    ))?;
    let bindings = document["bindings"]
        .as_object_mut()
        .ok_or("serialized bindings must be an object")?;
    bindings.clear();
    for index in 0..MAX_GENERATED_EXECUTION_BINDINGS {
        bindings.insert(format!("helper.target-{index:03}"), generated.clone());
    }
    bindings.insert("zzzz.excess".to_owned(), json!({"invalid": ["payload"]}));
    let Err(error) = serde_json::from_value::<GeneratedExecutionOverlay>(document) else {
        return Err("the first excess generated binding must fail at the map boundary".into());
    };
    assert!(
        error.to_string().contains("binding limit"),
        "unexpected error: {error}"
    );

    let serialized = serde_json::to_string(&seed)?;
    let binding_json = serde_json::to_string(
        seed.bindings()
            .get(&ExecutionTargetId::new("helper.seed")?)
            .ok_or("expected seed binding")?,
    )?;
    let single = format!(r#""bindings":{{"helper.seed":{binding_json}}}"#);
    let duplicate = format!(
        r#""bindings":{{"helper.seed":{binding_json},"helper.seed":{{"invalid":["payload"]}}}}"#
    );
    let duplicate_document = serialized.replacen(&single, &duplicate, 1);
    assert_ne!(duplicate_document, serialized);
    let Err(error) = serde_json::from_str::<GeneratedExecutionOverlay>(&duplicate_document) else {
        return Err("duplicate generated target identifiers must fail closed".into());
    };
    assert!(error.to_string().contains("duplicate execution target"));
    Ok(())
}

#[test]
fn streamed_authority_parser_ignores_the_first_malformed_excess_value()
-> Result<(), Box<dyn std::error::Error>> {
    let target = serde_json::to_string(&AuthorizedExecutionTargetRef::new(
        ExecutionTargetKind::VendorHelper,
        ExecutionArtifactSource::PackageSnapshot,
        digest(0xb0).into(),
    ))?;
    let targets = (0..MAX_AUTHORIZED_EXECUTION_TARGETS)
        .map(|index| format!(r#""helper.target-{index:03}":{target}"#))
        .collect::<Vec<_>>()
        .join(",");
    let digest = serde_json::to_string(&digest(0xb1))?;
    let exact = format!(
        r#"{{"format_version":"1","adapter_id":"openai.desktop","family":"openai.chatgpt.windows","adapter_content_digest":{digest},"targets":{{{targets}}}}}"#
    );
    assert_eq!(
        serde_json::from_str::<AdapterExecutionAuthority>(&exact)?
            .targets()
            .len(),
        MAX_AUTHORIZED_EXECUTION_TARGETS
    );

    let excess = format!(
        r#"{{"format_version":"1","adapter_id":"openai.desktop","family":"openai.chatgpt.windows","adapter_content_digest":{digest},"targets":{{{targets},"zzzz.excess":{{"invalid":["payload"]}}}}}}"#
    );
    let Err(error) = serde_json::from_str::<AdapterExecutionAuthority>(&excess) else {
        return Err("streamed authority parser accepted an excess target".into());
    };
    assert!(
        error.to_string().contains("target limit"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn streamed_overlay_parser_ignores_the_first_malformed_excess_value()
-> Result<(), Box<dyn std::error::Error>> {
    let seed = overlay("helper.seed", digest(0xb2), digest(0x42))?;
    let serialized = serde_json::to_string(&seed)?;
    let binding = serde_json::to_string(
        seed.bindings()
            .get(&ExecutionTargetId::new("helper.seed")?)
            .ok_or("expected seed binding")?,
    )?;
    let single = format!(r#""bindings":{{"helper.seed":{binding}}}"#);
    let bindings = (0..MAX_GENERATED_EXECUTION_BINDINGS)
        .map(|index| format!(r#""helper.target-{index:03}":{binding}"#))
        .collect::<Vec<_>>()
        .join(",");
    let exact = serialized.replacen(&single, &format!(r#""bindings":{{{bindings}}}"#), 1);
    assert_ne!(exact, serialized);
    assert_eq!(
        serde_json::from_str::<GeneratedExecutionOverlay>(&exact)?
            .bindings()
            .len(),
        MAX_GENERATED_EXECUTION_BINDINGS
    );

    let excess_fragment =
        format!(r#""bindings":{{{bindings},"zzzz.excess":{{"invalid":["payload"]}}}}"#);
    let excess = serialized.replacen(&single, &excess_fragment, 1);
    let Err(error) = serde_json::from_str::<GeneratedExecutionOverlay>(&excess) else {
        return Err("streamed overlay parser accepted an excess binding".into());
    };
    assert!(
        error.to_string().contains("binding limit"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn execution_overlay_rejects_independent_adapter_identity_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let overlay = overlay("helper.allowed", digest(0x31), digest(0x42))?;
    for authority in [
        AdapterExecutionAuthority::new(
            AdapterId::new("microsoft.vscode")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0x32),
            authority_targets("helper.allowed", digest(0x31))?,
        )?,
        AdapterExecutionAuthority::new(
            AdapterId::new("openai.desktop")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0xff),
            authority_targets("helper.allowed", digest(0x31))?,
        )?,
    ] {
        assert_eq!(
            overlay.validate_against(&authority, execution_context()),
            Err(ExecutionContractError::AuthorityIdentityMismatch)
        );
    }
    Ok(())
}

#[test]
fn execution_overlay_transport_is_strict_and_lexically_versioned()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.seed", digest(0x91))?;
    let authority_document = serde_json::to_value(&authority)?;
    for version in [
        json!(1),
        json!(1.0),
        json!(null),
        json!(true),
        json!([]),
        json!({}),
        json!(""),
        json!("2"),
    ] {
        let mut invalid = authority_document.clone();
        invalid["format_version"] = version;
        assert!(serde_json::from_value::<AdapterExecutionAuthority>(invalid).is_err());
    }
    for field in [
        "format_version",
        "adapter_id",
        "family",
        "adapter_content_digest",
        "targets",
    ] {
        let mut invalid = authority_document.clone();
        invalid
            .as_object_mut()
            .ok_or("authority transport must be an object")?
            .remove(field);
        assert!(serde_json::from_value::<AdapterExecutionAuthority>(invalid).is_err());
    }
    for (field, value) in [
        ("kind", "full_vendor_app"),
        ("artifact_source", "filesystem"),
    ] {
        let mut invalid = authority_document.clone();
        invalid["targets"]["helper.seed"][field] = json!(value);
        assert!(serde_json::from_value::<AdapterExecutionAuthority>(invalid).is_err());
    }

    let overlay = overlay("helper.seed", digest(0xa1), digest(0x42))?;
    let document = serde_json::to_value(&overlay)?;
    for version in [
        json!(1),
        json!(1.0),
        json!(null),
        json!(true),
        json!([]),
        json!({}),
        json!(""),
        json!("2"),
    ] {
        let mut invalid = document.clone();
        invalid["format_version"] = version;
        assert!(serde_json::from_value::<GeneratedExecutionOverlay>(invalid).is_err());
    }
    for (field, value) in [("platform", "linux"), ("architecture", "aarch64")] {
        let mut invalid = document.clone();
        invalid[field] = json!(value);
        assert!(serde_json::from_value::<GeneratedExecutionOverlay>(invalid).is_err());
    }
    let mut unknown = document.clone();
    unknown["launch_authorized"] = json!(true);
    assert!(serde_json::from_value::<GeneratedExecutionOverlay>(unknown).is_err());
    let mut nested_unknown = document;
    nested_unknown["bindings"]["helper.seed"]["arguments"] = json!(["--unsafe"]);
    assert!(serde_json::from_value::<GeneratedExecutionOverlay>(nested_unknown).is_err());

    let mut authority_unknown = serde_json::to_value(&overlay)?;
    authority_unknown["binding"]["authority"]["security_exceptions"] = json!(["none"]);
    assert!(serde_json::from_value::<GeneratedExecutionOverlay>(authority_unknown).is_err());
    let mut binding_unknown = serde_json::to_value(&overlay)?;
    binding_unknown["binding"]["launch_context"] = json!({});
    assert!(serde_json::from_value::<GeneratedExecutionOverlay>(binding_unknown).is_err());
    for field in [
        "format_version",
        "platform",
        "architecture",
        "binding",
        "bindings",
    ] {
        let mut invalid = serde_json::to_value(&overlay)?;
        invalid
            .as_object_mut()
            .ok_or("overlay transport must be an object")?
            .remove(field);
        assert!(serde_json::from_value::<GeneratedExecutionOverlay>(invalid).is_err());
    }
    Ok(())
}

#[test]
fn execution_contract_maps_accept_the_exact_serialized_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let targets = (0..MAX_AUTHORIZED_EXECUTION_TARGETS)
        .map(|index| {
            Ok((
                ExecutionTargetId::new(format!("helper.target-{index:03}"))?,
                AuthorizedExecutionTargetRef::new(
                    ExecutionTargetKind::VendorHelper,
                    ExecutionArtifactSource::PackageSnapshot,
                    digest(0xc1).into(),
                ),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    let authority = AdapterExecutionAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xc2),
        targets,
    )?;
    assert_eq!(
        serde_json::from_slice::<AdapterExecutionAuthority>(&serde_json::to_vec(&authority)?)?,
        authority
    );

    let bindings = (0..MAX_GENERATED_EXECUTION_BINDINGS)
        .map(|index| {
            Ok((
                ExecutionTargetId::new(format!("helper.target-{index:03}"))?,
                artifact_binding(digest(0xc3), digest(0xc4), digest(0xc5), digest(0xc6)),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    let generated = GeneratedExecutionOverlay::windows_x64(
        ExecutionOverlayBinding::new(
            ExecutionOverlayContext {
                source_build_fingerprint_digest: digest(0xc7),
                package_tree_merkle: digest(0xc8),
                execution_environment_digest: digest(0xc9),
                build_descriptor_digest: digest(0xcc),
            },
            &authority,
        ),
        bindings,
    )?;
    assert_eq!(
        serde_json::from_slice::<GeneratedExecutionOverlay>(&serde_json::to_vec(&generated)?)?,
        generated
    );
    Ok(())
}

#[test]
fn authority_digest_and_serialization_are_insertion_order_independent()
-> Result<(), Box<dyn std::error::Error>> {
    let first = AdapterExecutionAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xb1),
        BTreeMap::from([
            (
                ExecutionTargetId::new("helper.alpha")?,
                AuthorizedExecutionTargetRef::new(
                    ExecutionTargetKind::VendorHelper,
                    ExecutionArtifactSource::PackageSnapshot,
                    digest(0xb2).into(),
                ),
            ),
            (
                ExecutionTargetId::new("runtime.main")?,
                AuthorizedExecutionTargetRef::new(
                    ExecutionTargetKind::MainRuntime,
                    ExecutionArtifactSource::ManagedArtifact,
                    digest(0xb3).into(),
                ),
            ),
        ]),
    )?;
    let second = AdapterExecutionAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xb1),
        [
            (
                ExecutionTargetId::new("runtime.main")?,
                AuthorizedExecutionTargetRef::new(
                    ExecutionTargetKind::MainRuntime,
                    ExecutionArtifactSource::ManagedArtifact,
                    digest(0xb3).into(),
                ),
            ),
            (
                ExecutionTargetId::new("helper.alpha")?,
                AuthorizedExecutionTargetRef::new(
                    ExecutionTargetKind::VendorHelper,
                    ExecutionArtifactSource::PackageSnapshot,
                    digest(0xb2).into(),
                ),
            ),
        ]
        .into_iter()
        .collect(),
    )?;
    let serialized = serde_json::to_vec(&first)?;
    assert_eq!(serialized, serde_json::to_vec(&second)?);
    assert_eq!(
        first.canonical_document_digest(),
        second.canonical_document_digest()
    );
    assert_eq!(
        first.canonical_document_digest(),
        Sha256Digest::from_bytes(Sha256::digest(serialized).into())
    );
    Ok(())
}

#[test]
fn generated_execution_serialization_is_insertion_order_independent()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = authority("helper.alpha", digest(0xd7))?;
    let binding = ExecutionOverlayBinding::new(
        ExecutionOverlayContext {
            source_build_fingerprint_digest: digest(0xd1),
            package_tree_merkle: digest(0xd2),
            execution_environment_digest: digest(0xd3),
            build_descriptor_digest: digest(0xd6),
        },
        &authority,
    );
    let entries = [
        (
            ExecutionTargetId::new("helper.alpha")?,
            artifact_binding(digest(0xd7), digest(0xd8), digest(0xd9), digest(0xda)),
        ),
        (
            ExecutionTargetId::new("runtime.main")?,
            artifact_binding(digest(0xdb), digest(0xdc), digest(0xdd), digest(0xde)),
        ),
    ];
    let first = GeneratedExecutionOverlay::windows_x64(binding.clone(), entries.clone().into())?;
    let second =
        GeneratedExecutionOverlay::windows_x64(binding, entries.into_iter().rev().collect())?;
    assert_eq!(serde_json::to_vec(&first)?, serde_json::to_vec(&second)?);
    Ok(())
}

fn authority(
    target_id: &str,
    contract_digest: Sha256Digest,
) -> Result<AdapterExecutionAuthority, Box<dyn std::error::Error>> {
    Ok(AdapterExecutionAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0x32),
        authority_targets(target_id, contract_digest)?,
    )?)
}

fn authority_targets(
    target_id: &str,
    contract_digest: Sha256Digest,
) -> Result<BTreeMap<ExecutionTargetId, AuthorizedExecutionTargetRef>, Box<dyn std::error::Error>> {
    Ok(BTreeMap::from([(
        ExecutionTargetId::new(target_id)?,
        AuthorizedExecutionTargetRef::new(
            ExecutionTargetKind::VendorHelper,
            ExecutionArtifactSource::PackageSnapshot,
            contract_digest.into(),
        ),
    )]))
}

fn overlay(
    target_id: &str,
    contract_digest: Sha256Digest,
    artifact_source_digest: Sha256Digest,
) -> Result<GeneratedExecutionOverlay, Box<dyn std::error::Error>> {
    let authority = authority("helper.allowed", digest(0x31))?;
    Ok(GeneratedExecutionOverlay::windows_x64(
        ExecutionOverlayBinding::new(execution_context(), &authority),
        BTreeMap::from([(
            ExecutionTargetId::new(target_id)?,
            artifact_binding(
                contract_digest,
                artifact_source_digest,
                digest(0x45),
                digest(0x46),
            ),
        )]),
    )?)
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn artifact_binding(
    execution_contract_digest: Sha256Digest,
    artifact_source_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    resolution_evidence_digest: Sha256Digest,
) -> ExecutionArtifactBinding {
    ExecutionArtifactBinding::new(ExecutionArtifactDigests {
        execution_contract_digest: execution_contract_digest.into(),
        artifact_source_digest: artifact_source_digest.into(),
        executable_digest: executable_digest.into(),
        resolution_evidence_digest: resolution_evidence_digest.into(),
    })
}

fn execution_context() -> ExecutionOverlayContext {
    ExecutionOverlayContext {
        source_build_fingerprint_digest: digest(0x40),
        package_tree_merkle: digest(0x42),
        execution_environment_digest: digest(0x43),
        build_descriptor_digest: digest(0x44),
    }
}

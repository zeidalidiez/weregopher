//! Authority-nonexpanding semantic-transform rebinding contract tests.

use std::collections::BTreeMap;

use serde_json::json;
use sha2::{Digest as _, Sha256};
use weregopher_domain::{
    AdapterId, AdapterTransformAuthority, ApplicationFamilyId, AuthorizedTransformRuleRef,
    GeneratedTransformOverlay, MAX_AUTHORIZED_TRANSFORM_RULES, MAX_GENERATED_TRANSFORM_REBINDINGS,
    Sha256Digest, SourceUnitId, SourceUnitRef, TRANSFORM_REBINDING_FORMAT_VERSION,
    TransformContractError, TransformOverlayBinding, TransformRebinding, TransformRuleId,
};

#[test]
fn exact_signed_rule_rebinding_is_structurally_valid() -> Result<(), Box<dyn std::error::Error>> {
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x11);
    let rule_id = TransformRuleId::new("main.replace-node-pty")?;
    let rule_digest = digest(0x13);

    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule_digest),
        )]),
    )?;
    assert_eq!(
        serde_json::to_value(&authority)?["format_version"],
        TRANSFORM_REBINDING_FORMAT_VERSION
    );
    let authority_digest = authority.canonical_document_digest();
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x21),
            family,
            adapter_id,
            adapter_content_digest,
            authority_digest,
            digest(0x22),
        ),
        BTreeMap::from([(
            rule_id,
            TransformRebinding::new(
                rule_digest,
                SourceUnitRef::new(SourceUnitId::new("module.main.bootstrap")?, digest(0x23)),
                digest(0x24),
                digest(0x25),
                digest(0x26),
                digest(0x27),
            ),
        )]),
    )?;
    assert_eq!(
        serde_json::to_value(&overlay)?["format_version"],
        TRANSFORM_REBINDING_FORMAT_VERSION
    );

    overlay.validate_against(&authority, digest(0x21), digest(0x22))?;
    assert_eq!(
        overlay.binding().source_build_fingerprint_digest(),
        &digest(0x21)
    );
    assert_eq!(overlay.binding().build_descriptor_digest(), &digest(0x22));
    let generated = overlay
        .rebindings()
        .get(&TransformRuleId::new("main.replace-node-pty")?)
        .ok_or("expected generated rebinding")?;
    assert_eq!(generated.match_evidence_digest(), &digest(0x24));
    assert_eq!(generated.transformed_source_digest(), &digest(0x25));
    assert_eq!(generated.source_map_digest(), &digest(0x26));
    assert_eq!(generated.audit_log_digest(), &digest(0x27));
    Ok(())
}

#[test]
fn generated_overlay_cannot_introduce_a_transform_rule() -> Result<(), Box<dyn std::error::Error>> {
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x31);
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            TransformRuleId::new("main.authorized")?,
            AuthorizedTransformRuleRef::new(digest(0x33)),
        )]),
    )?;
    let authority_digest = authority.canonical_document_digest();
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x34),
            family,
            adapter_id,
            adapter_content_digest,
            authority_digest,
            digest(0x35),
        ),
        BTreeMap::from([(
            TransformRuleId::new("main.generated")?,
            TransformRebinding::new(
                digest(0x36),
                SourceUnitRef::new(SourceUnitId::new("module.main")?, digest(0x37)),
                digest(0x38),
                digest(0x39),
                digest(0x3a),
                digest(0x3b),
            ),
        )]),
    )?;

    assert_eq!(
        overlay.validate_against(&authority, digest(0x34), digest(0x35)),
        Err(TransformContractError::UnknownTransformRule)
    );
    Ok(())
}

#[test]
fn generated_overlay_cannot_substitute_static_rule_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x41);
    let rule_id = TransformRuleId::new("main.authorized")?;
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(digest(0x43)),
        )]),
    )?;
    let authority_digest = authority.canonical_document_digest();
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x44),
            family,
            adapter_id,
            adapter_content_digest,
            authority_digest,
            digest(0x45),
        ),
        BTreeMap::from([(
            rule_id,
            TransformRebinding::new(
                digest(0x46),
                SourceUnitRef::new(SourceUnitId::new("module.main")?, digest(0x47)),
                digest(0x48),
                digest(0x49),
                digest(0x4a),
                digest(0x4b),
            ),
        )]),
    )?;

    assert_eq!(
        overlay.validate_against(&authority, digest(0x44), digest(0x45)),
        Err(TransformContractError::TransformRuleDigestMismatch)
    );
    Ok(())
}

#[test]
fn generated_overlay_cannot_be_replayed_for_another_family()
-> Result<(), Box<dyn std::error::Error>> {
    let adapter_id = AdapterId::new("openai.desktop")?;
    let adapter_content_digest = digest(0x53);
    let rule_id = TransformRuleId::new("main.authorized")?;
    let rule_digest = digest(0x54);
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        ApplicationFamilyId::new("microsoft.vscode.windows")?,
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule_digest),
        )]),
    )?;
    let authority_digest = authority.canonical_document_digest();
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x55),
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            adapter_id,
            adapter_content_digest,
            authority_digest,
            digest(0x56),
        ),
        BTreeMap::from([(
            rule_id,
            TransformRebinding::new(
                rule_digest,
                SourceUnitRef::new(SourceUnitId::new("module.main")?, digest(0x57)),
                digest(0x58),
                digest(0x59),
                digest(0x5a),
                digest(0x5b),
            ),
        )]),
    )?;

    assert_eq!(
        overlay.validate_against(&authority, digest(0x55), digest(0x56)),
        Err(TransformContractError::AuthorityIdentityMismatch)
    );
    Ok(())
}

#[test]
fn generated_overlay_must_reference_the_exact_authority_document()
-> Result<(), Box<dyn std::error::Error>> {
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x61);
    let rule_id = TransformRuleId::new("main.authorized")?;
    let rule_digest = digest(0x62);
    let authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(rule_digest),
        )]),
    )?;
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x63),
            family,
            adapter_id,
            adapter_content_digest,
            digest(0x64),
            digest(0x65),
        ),
        BTreeMap::from([(
            rule_id,
            TransformRebinding::new(
                rule_digest,
                SourceUnitRef::new(SourceUnitId::new("module.main")?, digest(0x66)),
                digest(0x67),
                digest(0x68),
                digest(0x69),
                digest(0x6a),
            ),
        )]),
    )?;

    assert_eq!(
        overlay.validate_against(&authority, digest(0x63), digest(0x65)),
        Err(TransformContractError::AuthorityDigestMismatch)
    );
    Ok(())
}

#[test]
fn overlay_digest_cannot_bless_different_authority_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let adapter_content_digest = digest(0x71);
    let trusted_authority_digest = digest(0x72);
    let rule_id = TransformRuleId::new("main.same-id")?;
    let forged_rule_digest = digest(0x73);
    let forged_authority = AdapterTransformAuthority::new(
        adapter_id.clone(),
        family.clone(),
        adapter_content_digest,
        BTreeMap::from([(
            rule_id.clone(),
            AuthorizedTransformRuleRef::new(forged_rule_digest),
        )]),
    )?;
    let overlay = GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x74),
            family,
            adapter_id,
            adapter_content_digest,
            trusted_authority_digest,
            digest(0x75),
        ),
        BTreeMap::from([(
            rule_id,
            TransformRebinding::new(
                forged_rule_digest,
                SourceUnitRef::new(SourceUnitId::new("module.main")?, digest(0x76)),
                digest(0x77),
                digest(0x78),
                digest(0x79),
                digest(0x7a),
            ),
        )]),
    )?;

    assert_eq!(
        overlay.validate_against(&forged_authority, digest(0x74), digest(0x75),),
        Err(TransformContractError::AuthorityDigestMismatch)
    );
    Ok(())
}

#[test]
fn authority_document_digest_matches_canonical_serialization()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0x81),
        BTreeMap::from([
            (
                TransformRuleId::new("main.alpha")?,
                AuthorizedTransformRuleRef::new(digest(0x82)),
            ),
            (
                TransformRuleId::new("main.beta")?,
                AuthorizedTransformRuleRef::new(digest(0x83)),
            ),
        ]),
    )?;
    let canonical_json = serde_json::to_vec(&authority)?;
    let expected = Sha256Digest::from_bytes(Sha256::digest(canonical_json).into());

    assert_eq!(authority.canonical_document_digest(), expected);
    assert_eq!(
        expected.to_string(),
        "sha256:50b848a5886e5b81d7606bc161671eba505cdfb1521776806ec6c42d0347986c"
    );
    Ok(())
}

#[test]
fn generated_overlay_cannot_be_replayed_for_another_source_build()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0x92),
        BTreeMap::from([(
            TransformRuleId::new("main.seed")?,
            AuthorizedTransformRuleRef::new(digest(0x95)),
        )]),
    )?;
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;

    assert_eq!(
        overlay.validate_against(&authority, digest(0xff), digest(0x94)),
        Err(TransformContractError::SourceBuildMismatch)
    );
    assert_eq!(
        overlay.validate_against(&authority, digest(0x91), digest(0xfe)),
        Err(TransformContractError::BuildDescriptorMismatch)
    );
    Ok(())
}

#[test]
fn static_authority_requires_a_transform_rule() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        AdapterTransformAuthority::new(
            AdapterId::new("openai.desktop")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0x71),
            BTreeMap::new(),
        ),
        Err(TransformContractError::EmptyTransformAuthority)
    );
    Ok(())
}

#[test]
fn static_authority_enforces_its_rule_limit() -> Result<(), Box<dyn std::error::Error>> {
    let rules = (0..=MAX_AUTHORIZED_TRANSFORM_RULES)
        .map(|index| {
            Ok((
                TransformRuleId::new(format!("main.rule-{index}"))?,
                AuthorizedTransformRuleRef::new(digest(0x72)),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    let accepted = rules
        .iter()
        .take(MAX_AUTHORIZED_TRANSFORM_RULES)
        .map(|(id, rule)| (id.clone(), rule.clone()))
        .collect();

    assert!(
        AdapterTransformAuthority::new(
            AdapterId::new("openai.desktop")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0x73),
            accepted,
        )
        .is_ok()
    );
    assert_eq!(
        AdapterTransformAuthority::new(
            AdapterId::new("openai.desktop")?,
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            digest(0x73),
            rules,
        ),
        Err(TransformContractError::TooManyTransformRules)
    );
    Ok(())
}

#[test]
fn generated_overlay_requires_a_rebinding() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        GeneratedTransformOverlay::windows_x64(
            TransformOverlayBinding::new(
                digest(0x81),
                ApplicationFamilyId::new("openai.chatgpt.windows")?,
                AdapterId::new("openai.desktop")?,
                digest(0x82),
                digest(0x83),
                digest(0x84),
            ),
            BTreeMap::new(),
        ),
        Err(TransformContractError::EmptyTransformOverlay)
    );
    Ok(())
}

#[test]
fn generated_overlay_enforces_its_rebinding_limit() -> Result<(), Box<dyn std::error::Error>> {
    let rebindings = (0..=MAX_GENERATED_TRANSFORM_REBINDINGS)
        .map(|index| {
            Ok((
                TransformRuleId::new(format!("main.rule-{index}"))?,
                rebinding(format!("module.unit-{index}"))?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn std::error::Error>>>()?;
    let accepted = rebindings
        .iter()
        .take(MAX_GENERATED_TRANSFORM_REBINDINGS)
        .map(|(id, rebinding)| (id.clone(), rebinding.clone()))
        .collect();

    assert!(overlay_with_rebindings(accepted)?.is_ok());
    assert_eq!(
        overlay_with_rebindings(rebindings)?,
        Err(TransformContractError::TooManyTransformRebindings)
    );
    Ok(())
}

#[test]
fn generated_overlay_cannot_target_one_source_unit_twice() -> Result<(), Box<dyn std::error::Error>>
{
    let first = rebinding("module.same".to_owned())?;
    let contradictory_second = TransformRebinding::new(
        digest(0x95),
        SourceUnitRef::new(SourceUnitId::new("module.same")?, digest(0xa6)),
        digest(0x97),
        digest(0x98),
        digest(0x99),
        digest(0x9a),
    );
    let rebindings = BTreeMap::from([
        (TransformRuleId::new("main.first")?, first),
        (TransformRuleId::new("main.second")?, contradictory_second),
    ]);

    assert_eq!(
        overlay_with_rebindings(rebindings)?,
        Err(TransformContractError::DuplicateSourceUnit)
    );
    Ok(())
}

#[test]
fn deserialization_cannot_create_an_empty_static_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0x71),
        BTreeMap::from([(
            TransformRuleId::new("main.authorized")?,
            AuthorizedTransformRuleRef::new(digest(0x72)),
        )]),
    )?;
    let mut document = serde_json::to_value(authority)?;
    document["rules"] = json!({});

    assert!(serde_json::from_value::<AdapterTransformAuthority>(document).is_err());
    Ok(())
}

#[test]
fn excess_static_rule_is_rejected_without_deserializing_its_value()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xa1),
        BTreeMap::from([(
            TransformRuleId::new("main.seed")?,
            AuthorizedTransformRuleRef::new(digest(0xa2)),
        )]),
    )?;
    let mut document = serde_json::to_value(authority)?;
    let rule = serde_json::to_value(AuthorizedTransformRuleRef::new(digest(0xa2)))?;
    let rules = document["rules"]
        .as_object_mut()
        .ok_or("serialized rules must be an object")?;
    rules.clear();
    for index in 0..MAX_AUTHORIZED_TRANSFORM_RULES {
        rules.insert(format!("main.rule-{index:03}"), rule.clone());
    }
    rules.insert("zzzz.excess".to_owned(), json!({"invalid": ["payload"]}));

    let Err(error) = serde_json::from_value::<AdapterTransformAuthority>(document) else {
        return Err("the first excess rule must fail at the map boundary".into());
    };
    assert!(
        error.to_string().contains("exceeds the rule limit"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn streamed_excess_static_rule_is_ignored_at_the_map_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let adapter_digest = serde_json::to_string(&digest(0xa1))?;
    let rule = serde_json::to_string(&AuthorizedTransformRuleRef::new(digest(0xa2)))?;
    let mut entries = Vec::with_capacity(MAX_AUTHORIZED_TRANSFORM_RULES + 1);
    for index in 0..MAX_AUTHORIZED_TRANSFORM_RULES {
        entries.push(format!(r#""main.rule-{index:03}":{rule}"#));
    }
    entries.push(r#""zzzz.excess":{"invalid":["payload"]}"#.to_owned());
    let document = format!(
        r#"{{"format_version":"1","adapter_id":"openai.desktop","family":"openai.chatgpt.windows","adapter_content_digest":{adapter_digest},"rules":{{{}}}}}"#,
        entries.join(",")
    );

    let Err(error) = serde_json::from_str::<AdapterTransformAuthority>(&document) else {
        return Err("the streamed excess rule must fail at the map boundary".into());
    };
    assert!(
        error.to_string().contains("exceeds the rule limit"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn duplicate_static_rule_keys_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let digest_json = serde_json::to_string(&digest(0xb1))?;
    let rule_json = serde_json::to_string(&AuthorizedTransformRuleRef::new(digest(0xb2)))?;
    let document = format!(
        r#"{{"format_version":"1","adapter_id":"openai.desktop","family":"openai.chatgpt.windows","adapter_content_digest":{digest_json},"rules":{{"main.same":{rule_json},"main.same":{rule_json}}}}}"#
    );

    let Err(error) = serde_json::from_str::<AdapterTransformAuthority>(&document) else {
        return Err("duplicate static rule identifiers must fail closed".into());
    };
    assert!(
        error.to_string().contains("duplicate rule identifiers"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn deserialization_cannot_create_an_empty_generated_overlay()
-> Result<(), Box<dyn std::error::Error>> {
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;
    let mut document = serde_json::to_value(overlay)?;
    document["rebindings"] = json!({});

    assert!(serde_json::from_value::<GeneratedTransformOverlay>(document).is_err());
    Ok(())
}

#[test]
fn excess_generated_rebinding_is_rejected_without_deserializing_its_value()
-> Result<(), Box<dyn std::error::Error>> {
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;
    let mut document = serde_json::to_value(overlay)?;
    let rebindings = document["rebindings"]
        .as_object_mut()
        .ok_or("serialized rebindings must be an object")?;
    rebindings.clear();
    for index in 0..MAX_GENERATED_TRANSFORM_REBINDINGS {
        rebindings.insert(
            format!("main.rule-{index:03}"),
            serde_json::to_value(rebinding(format!("module.unit-{index:03}"))?)?,
        );
    }
    rebindings.insert("zzzz.excess".to_owned(), json!({"invalid": ["payload"]}));

    let Err(error) = serde_json::from_value::<GeneratedTransformOverlay>(document) else {
        return Err("the first excess rebinding must fail at the map boundary".into());
    };
    assert!(
        error.to_string().contains("exceeds the rebinding limit"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn streamed_excess_generated_rebinding_is_ignored_at_the_map_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let seed_rebinding = rebinding("module.seed".to_owned())?;
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        seed_rebinding.clone(),
    )]))??;
    let serialized = serde_json::to_string(&overlay)?;
    let seed_json = serde_json::to_string(&seed_rebinding)?;
    let marker = format!(r#""rebindings":{{"main.seed":{seed_json}}}"#);
    let mut entries = Vec::with_capacity(MAX_GENERATED_TRANSFORM_REBINDINGS + 1);
    for index in 0..MAX_GENERATED_TRANSFORM_REBINDINGS {
        let value = serde_json::to_string(&rebinding(format!("module.unit-{index:03}"))?)?;
        entries.push(format!(r#""main.rule-{index:03}":{value}"#));
    }
    entries.push(r#""zzzz.excess":{"invalid":["payload"]}"#.to_owned());
    let replacement = format!(r#""rebindings":{{{}}}"#, entries.join(","));
    let document = serialized.replacen(&marker, &replacement, 1);
    assert_ne!(document, serialized, "test fixture must replace rebindings");

    let Err(error) = serde_json::from_str::<GeneratedTransformOverlay>(&document) else {
        return Err("the streamed excess rebinding must fail at the map boundary".into());
    };
    assert!(
        error.to_string().contains("exceeds the rebinding limit"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn duplicate_generated_rebinding_keys_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let generated = rebinding("module.seed".to_owned())?;
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        generated.clone(),
    )]))??;
    let serialized = serde_json::to_string(&overlay)?;
    let generated_json = serde_json::to_string(&generated)?;
    let single = format!(r#""rebindings":{{"main.seed":{generated_json}}}"#);
    let duplicate =
        format!(r#""rebindings":{{"main.seed":{generated_json},"main.seed":{generated_json}}}"#);
    let document = serialized.replacen(&single, &duplicate, 1);
    assert_ne!(
        document, serialized,
        "test fixture must inject a duplicate key"
    );

    let Err(error) = serde_json::from_str::<GeneratedTransformOverlay>(&document) else {
        return Err("duplicate generated rule identifiers must fail closed".into());
    };
    assert!(
        error.to_string().contains("duplicate rule identifiers"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn deserialization_cannot_target_one_source_unit_twice() -> Result<(), Box<dyn std::error::Error>> {
    let overlay = overlay_with_rebindings(BTreeMap::from([
        (
            TransformRuleId::new("main.first")?,
            rebinding("module.first".to_owned())?,
        ),
        (
            TransformRuleId::new("main.second")?,
            rebinding("module.second".to_owned())?,
        ),
    ]))??;
    let mut document = serde_json::to_value(overlay)?;
    document["rebindings"]["main.second"]["source"] =
        document["rebindings"]["main.first"]["source"].clone();

    let Err(error) = serde_json::from_value::<GeneratedTransformOverlay>(document) else {
        return Err("duplicate source units must fail during deserialization".into());
    };
    assert!(
        error
            .to_string()
            .contains("targets one source unit more than once"),
        "unexpected error: {error}"
    );
    Ok(())
}

#[test]
fn serialized_contracts_reject_unknown_and_unsupported_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xc1),
        BTreeMap::from([(
            TransformRuleId::new("main.seed")?,
            AuthorizedTransformRuleRef::new(digest(0xc2)),
        )]),
    )?;
    let authority_document = serde_json::to_value(authority)?;
    let mut authority_cases = Vec::new();
    for version in [json!(1), json!("2"), serde_json::Value::Null] {
        let mut document = authority_document.clone();
        document["format_version"] = version;
        authority_cases.push(document);
    }
    let mut authority_unknown = authority_document.clone();
    authority_unknown["transformation_authorized"] = json!(true);
    authority_cases.push(authority_unknown);
    let mut rule_unknown = authority_document;
    rule_unknown["rules"]["main.seed"]["capabilities"] = json!(["network"]);
    authority_cases.push(rule_unknown);
    for document in authority_cases {
        assert!(serde_json::from_value::<AdapterTransformAuthority>(document).is_err());
    }

    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;
    let overlay_document = serde_json::to_value(overlay)?;
    let mut overlay_cases = Vec::new();
    for version in [json!(1), json!("2"), serde_json::Value::Null] {
        let mut document = overlay_document.clone();
        document["format_version"] = version;
        overlay_cases.push(document);
    }
    for (field, unsupported) in [("platform", "linux"), ("architecture", "aarch64")] {
        let mut document = overlay_document.clone();
        document[field] = json!(unsupported);
        overlay_cases.push(document);
    }
    let mut overlay_unknown = overlay_document.clone();
    overlay_unknown["execution_authorized"] = json!(true);
    overlay_cases.push(overlay_unknown);
    let mut rebinding_unknown = overlay_document.clone();
    rebinding_unknown["rebindings"]["main.seed"]["replacement_module"] = json!("evil.js");
    overlay_cases.push(rebinding_unknown);
    let mut source_unknown = overlay_document;
    source_unknown["rebindings"]["main.seed"]["source"]["byte_offset"] = json!(42);
    overlay_cases.push(source_unknown);
    for document in overlay_cases {
        assert!(serde_json::from_value::<GeneratedTransformOverlay>(document).is_err());
    }
    Ok(())
}

#[test]
fn format_versions_are_lexically_exact() -> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xe1),
        BTreeMap::from([(
            TransformRuleId::new("main.seed")?,
            AuthorizedTransformRuleRef::new(digest(0xe2)),
        )]),
    )?;
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;
    let authority_document = serde_json::to_value(authority)?;
    let overlay_document = serde_json::to_value(overlay)?;

    for invalid_version in [json!(1), json!(1.0), json!(null), json!("2")] {
        let mut invalid_authority = authority_document.clone();
        invalid_authority["format_version"] = invalid_version.clone();
        assert!(
            serde_json::from_value::<AdapterTransformAuthority>(invalid_authority).is_err(),
            "authority accepted invalid format version {invalid_version}"
        );

        let mut invalid_overlay = overlay_document.clone();
        invalid_overlay["format_version"] = invalid_version.clone();
        assert!(
            serde_json::from_value::<GeneratedTransformOverlay>(invalid_overlay).is_err(),
            "overlay accepted invalid format version {invalid_version}"
        );
    }

    let mut missing_authority_version = authority_document;
    missing_authority_version
        .as_object_mut()
        .ok_or("authority document must be an object")?
        .remove("format_version");
    assert!(
        serde_json::from_value::<AdapterTransformAuthority>(missing_authority_version).is_err()
    );
    let mut missing_overlay_version = overlay_document;
    missing_overlay_version
        .as_object_mut()
        .ok_or("overlay document must be an object")?
        .remove("format_version");
    assert!(serde_json::from_value::<GeneratedTransformOverlay>(missing_overlay_version).is_err());
    Ok(())
}

#[test]
fn serialized_identifiers_and_digests_must_be_canonical() -> Result<(), Box<dyn std::error::Error>>
{
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xf1),
        BTreeMap::from([(
            TransformRuleId::new("main.seed")?,
            AuthorizedTransformRuleRef::new(digest(0xf2)),
        )]),
    )?;
    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;

    for (pointer, invalid) in [
        ("/adapter_id", json!("OpenAI.desktop")),
        ("/family", json!("openai..windows")),
        ("/adapter_content_digest", json!("sha256:ABCD")),
        (
            "/rules",
            json!({ "main/seed": { "rule_digest": digest(0xf2) } }),
        ),
    ] {
        let mut document = serde_json::to_value(&authority)?;
        *document
            .pointer_mut(pointer)
            .ok_or("authority pointer must exist")? = invalid;
        assert!(serde_json::from_value::<AdapterTransformAuthority>(document).is_err());
    }

    for (pointer, invalid) in [
        ("/binding/adapter_id", json!("openai/desktop")),
        (
            "/binding/source_build_fingerprint_digest",
            json!("sha256:00"),
        ),
        ("/rebindings/main.seed/source/unit_id", json!("module/seed")),
        ("/rebindings/main.seed/audit_log_digest", json!("SHA256:00")),
    ] {
        let mut document = serde_json::to_value(&overlay)?;
        *document
            .pointer_mut(pointer)
            .ok_or("overlay pointer must exist")? = invalid;
        assert!(serde_json::from_value::<GeneratedTransformOverlay>(document).is_err());
    }
    Ok(())
}

#[test]
fn serialized_maps_are_independent_of_insertion_order() -> Result<(), Box<dyn std::error::Error>> {
    let first_rule = (
        TransformRuleId::new("main.alpha")?,
        AuthorizedTransformRuleRef::new(digest(0xd1)),
    );
    let second_rule = (
        TransformRuleId::new("main.beta")?,
        AuthorizedTransformRuleRef::new(digest(0xd2)),
    );
    let adapter_id = AdapterId::new("openai.desktop")?;
    let family = ApplicationFamilyId::new("openai.chatgpt.windows")?;
    let authority = |rules| {
        AdapterTransformAuthority::new(adapter_id.clone(), family.clone(), digest(0xd3), rules)
    };
    let forward = authority(BTreeMap::from([first_rule.clone(), second_rule.clone()]))?;
    let reverse = authority(BTreeMap::from([second_rule, first_rule]))?;
    assert_eq!(serde_json::to_vec(&forward)?, serde_json::to_vec(&reverse)?);

    let first_rebinding = (
        TransformRuleId::new("main.alpha")?,
        rebinding("module.alpha".to_owned())?,
    );
    let second_rebinding = (
        TransformRuleId::new("main.beta")?,
        rebinding("module.beta".to_owned())?,
    );
    let forward = overlay_with_rebindings(BTreeMap::from([
        first_rebinding.clone(),
        second_rebinding.clone(),
    ]))??;
    let reverse = overlay_with_rebindings(BTreeMap::from([second_rebinding, first_rebinding]))??;
    assert_eq!(serde_json::to_vec(&forward)?, serde_json::to_vec(&reverse)?);
    Ok(())
}

#[test]
fn contracts_do_not_serialize_transformation_or_execution_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = AdapterTransformAuthority::new(
        AdapterId::new("openai.desktop")?,
        ApplicationFamilyId::new("openai.chatgpt.windows")?,
        digest(0xe1),
        BTreeMap::from([(
            TransformRuleId::new("main.seed")?,
            AuthorizedTransformRuleRef::new(digest(0xe2)),
        )]),
    )?;
    let authority = serde_json::to_value(authority)?;
    assert_eq!(
        object_keys(&authority)?,
        [
            "adapter_content_digest",
            "adapter_id",
            "family",
            "format_version",
            "rules",
        ]
    );
    assert_eq!(
        object_keys(&authority["rules"]["main.seed"])?,
        ["rule_digest"]
    );

    let overlay = overlay_with_rebindings(BTreeMap::from([(
        TransformRuleId::new("main.seed")?,
        rebinding("module.seed".to_owned())?,
    )]))??;
    let overlay = serde_json::to_value(overlay)?;
    assert_eq!(
        object_keys(&overlay)?,
        [
            "architecture",
            "binding",
            "format_version",
            "platform",
            "rebindings"
        ]
    );
    assert_eq!(
        object_keys(&overlay["binding"])?,
        [
            "adapter_content_digest",
            "adapter_id",
            "adapter_transform_authority_digest",
            "build_descriptor_digest",
            "family",
            "source_build_fingerprint_digest",
        ]
    );
    assert_eq!(
        object_keys(&overlay["rebindings"]["main.seed"])?,
        [
            "audit_log_digest",
            "match_evidence_digest",
            "rule_digest",
            "source",
            "source_map_digest",
            "transformed_source_digest",
        ]
    );
    Ok(())
}

fn object_keys(value: &serde_json::Value) -> Result<Vec<&str>, Box<dyn std::error::Error>> {
    Ok(value
        .as_object()
        .ok_or("expected a serialized object")?
        .keys()
        .map(String::as_str)
        .collect())
}

fn overlay_with_rebindings(
    rebindings: BTreeMap<TransformRuleId, TransformRebinding>,
) -> Result<Result<GeneratedTransformOverlay, TransformContractError>, Box<dyn std::error::Error>> {
    Ok(GeneratedTransformOverlay::windows_x64(
        TransformOverlayBinding::new(
            digest(0x91),
            ApplicationFamilyId::new("openai.chatgpt.windows")?,
            AdapterId::new("openai.desktop")?,
            digest(0x92),
            digest(0x93),
            digest(0x94),
        ),
        rebindings,
    ))
}

fn rebinding(unit_id: String) -> Result<TransformRebinding, Box<dyn std::error::Error>> {
    Ok(TransformRebinding::new(
        digest(0x95),
        SourceUnitRef::new(SourceUnitId::new(unit_id)?, digest(0x96)),
        digest(0x97),
        digest(0x98),
        digest(0x99),
        digest(0x9a),
    ))
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

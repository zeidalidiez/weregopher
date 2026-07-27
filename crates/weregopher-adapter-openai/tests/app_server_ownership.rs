//! Non-authorizing Codex execution and owned-resource correlation behavior.

use std::time::Duration;

use weregopher_adapter_openai::{
    AppServerEventDetail, AppServerEventLimits, AppServerJsonLimits, AppServerOwnedResourceId,
    AppServerOwnedResourceKind, AppServerOwnershipError, AppServerOwnershipLimits,
    AppServerOwnershipRegistry, AppServerProxyError, AppServerProxyLimits, AppServerQueueLimits,
    AppServerSessionEventJournal, CodexExecutionIdentity, TransparentAppServerProxy,
};

fn proxy_limits() -> Result<AppServerProxyLimits, AppServerProxyError> {
    AppServerProxyLimits::new(
        4_096,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerJsonLimits::new(16, 256)?,
        8,
        32,
        Duration::from_secs(30),
    )
}

fn request_token()
-> Result<weregopher_adapter_openai::AppServerCorrelationToken, Box<dyn std::error::Error>> {
    request_token_at(1)
}

fn request_token_at(
    index: u64,
) -> Result<weregopher_adapter_openai::AppServerCorrelationToken, Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits()?);
    let mut journal = AppServerSessionEventJournal::new(AppServerEventLimits::new(4)?);
    let mut result = None;
    for value in 1..=index {
        let line = format!(
            r#"{{"id":"wire-private-{value}","method":"turn/start","params":{{"threadId":"private-thread"}}}}"#
        );
        let observation = proxy.ingest_client(line.as_bytes())?;
        journal.record_accepted(&observation)?;
        let event = journal.next_event().ok_or("accepted event was absent")?;
        let AppServerEventDetail::Message(message) = event.detail() else {
            return Err("accepted message event had the wrong shape".into());
        };
        result = message.correlation();
    }
    result.ok_or_else(|| "request correlation was absent".into())
}

#[test]
fn execution_identity_enforces_hierarchy_and_redacts_debug()
-> Result<(), Box<dyn std::error::Error>> {
    let identity = CodexExecutionIdentity::new(
        Some("thread-private".to_owned()),
        Some("turn-private".to_owned()),
        Some("item-private".to_owned()),
    )?;
    assert_eq!(identity.thread_id(), Some("thread-private"));
    assert_eq!(identity.turn_id(), Some("turn-private"));
    assert_eq!(identity.item_id(), Some("item-private"));
    let debug = format!("{identity:?}");
    assert!(!debug.contains("thread-private"));
    assert!(!debug.contains("turn-private"));
    assert!(!debug.contains("item-private"));

    assert!(matches!(
        CodexExecutionIdentity::new(None, Some("turn".to_owned()), None),
        Err(AppServerOwnershipError::InvalidIdentityHierarchy)
    ));
    assert!(matches!(
        CodexExecutionIdentity::new(Some("thread".to_owned()), None, Some("item".to_owned())),
        Err(AppServerOwnershipError::InvalidIdentityHierarchy)
    ));
    assert!(matches!(
        CodexExecutionIdentity::new(Some("\n".to_owned()), None, None),
        Err(AppServerOwnershipError::InvalidExecutionId)
    ));
    Ok(())
}

#[test]
fn registry_releases_only_resources_within_the_completed_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let token = request_token()?;
    let mut registry = AppServerOwnershipRegistry::new(AppServerOwnershipLimits::new(8, 8)?);
    let turn = CodexExecutionIdentity::new(
        Some("thread-a".to_owned()),
        Some("turn-a1".to_owned()),
        None,
    )?;
    let thread = CodexExecutionIdentity::new(Some("thread-a".to_owned()), None, None)?;
    let app = CodexExecutionIdentity::new(None, None, None)?;
    registry.bind_correlation(&token, turn.clone())?;
    registry.register_from_correlation(
        AppServerOwnedResourceId::new(1)?,
        AppServerOwnedResourceKind::CommandProcess,
        &token,
    )?;
    registry.register(
        AppServerOwnedResourceId::new(2)?,
        AppServerOwnedResourceKind::McpProcess,
        thread.clone(),
    )?;
    registry.register(
        AppServerOwnedResourceId::new(3)?,
        AppServerOwnedResourceKind::McpProcess,
        app,
    )?;

    let turn_release = registry.release_scope(&turn)?;
    assert_eq!(turn_release.released_correlations(), 1);
    assert_eq!(turn_release.resources().len(), 1);
    assert_eq!(
        turn_release.resources()[0].id(),
        AppServerOwnedResourceId::new(1)?
    );
    assert_eq!(registry.diagnostics().resources(), 2);

    let thread_release = registry.release_scope(&thread)?;
    assert_eq!(thread_release.released_correlations(), 0);
    assert_eq!(thread_release.resources().len(), 1);
    assert_eq!(
        thread_release.resources()[0].id(),
        AppServerOwnedResourceId::new(2)?
    );
    assert_eq!(registry.diagnostics().resources(), 1);

    let session_release = registry.close_session();
    assert_eq!(session_release.resources().len(), 1);
    assert_eq!(
        session_release.resources()[0].id(),
        AppServerOwnedResourceId::new(3)?
    );
    assert_eq!(registry.diagnostics().resources(), 0);
    Ok(())
}

#[test]
fn registry_rejects_rebinding_unknown_correlations_and_capacity_growth()
-> Result<(), Box<dyn std::error::Error>> {
    let token = request_token()?;
    let identity = CodexExecutionIdentity::new(Some("thread-a".to_owned()), None, None)?;
    let mut registry = AppServerOwnershipRegistry::new(AppServerOwnershipLimits::new(1, 1)?);
    registry.bind_correlation(&token, identity.clone())?;
    assert!(matches!(
        registry.bind_correlation(&token, identity.clone()),
        Err(AppServerOwnershipError::DuplicateCorrelation)
    ));
    registry.register_from_correlation(
        AppServerOwnedResourceId::new(1)?,
        AppServerOwnedResourceKind::HelperProcess,
        &token,
    )?;
    assert!(matches!(
        registry.register(
            AppServerOwnedResourceId::new(2)?,
            AppServerOwnedResourceKind::BrowserSession,
            identity
        ),
        Err(AppServerOwnershipError::ResourceLimitExceeded)
    ));
    assert!(matches!(
        registry.register_from_correlation(
            AppServerOwnedResourceId::new(3)?,
            AppServerOwnedResourceKind::HelperProcess,
            &request_token_at(2)?
        ),
        Err(AppServerOwnershipError::UnknownCorrelation)
    ));
    Ok(())
}

#[test]
fn registry_rejects_same_sequence_token_from_another_journal()
-> Result<(), Box<dyn std::error::Error>> {
    let first_session = request_token()?;
    let other_session = request_token()?;
    assert_eq!(first_session.get(), other_session.get());
    assert_ne!(first_session, other_session);

    let identity = CodexExecutionIdentity::new(Some("thread-a".to_owned()), None, None)?;
    let mut registry = AppServerOwnershipRegistry::new(AppServerOwnershipLimits::new(2, 2)?);
    registry.bind_correlation(&first_session, identity.clone())?;
    assert!(matches!(
        registry.bind_correlation(&other_session, identity),
        Err(AppServerOwnershipError::ForeignJournal)
    ));
    assert!(matches!(
        registry.register_from_correlation(
            AppServerOwnedResourceId::new(1)?,
            AppServerOwnedResourceKind::HelperProcess,
            &other_session
        ),
        Err(AppServerOwnershipError::UnknownCorrelation)
    ));
    Ok(())
}

#[test]
fn registry_debug_omits_execution_ids_and_has_no_effect_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let token = request_token()?;
    let mut registry = AppServerOwnershipRegistry::new(AppServerOwnershipLimits::new(4, 4)?);
    let identity = CodexExecutionIdentity::new(
        Some("thread-debug-private".to_owned()),
        Some("turn-debug-private".to_owned()),
        None,
    )?;
    registry.bind_correlation(&token, identity)?;
    registry.register_from_correlation(
        AppServerOwnedResourceId::new(9)?,
        AppServerOwnedResourceKind::HelperProcess,
        &token,
    )?;
    let debug = format!("{registry:?}");
    assert!(!debug.contains("thread-debug-private"));
    assert!(!debug.contains("turn-debug-private"));
    assert!(!debug.contains("wire-private"));
    assert_eq!(registry.diagnostics().resources(), 1);
    assert_eq!(registry.diagnostics().correlations(), 1);
    Ok(())
}

#[test]
fn ownership_limits_reject_zero_and_absolute_excess() {
    assert!(matches!(
        AppServerOwnershipLimits::new(0, 1),
        Err(AppServerOwnershipError::InvalidLimits)
    ));
    assert!(matches!(
        AppServerOwnershipLimits::new(1, 65_537),
        Err(AppServerOwnershipError::InvalidLimits)
    ));
}

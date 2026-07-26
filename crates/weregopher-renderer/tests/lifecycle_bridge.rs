//! Portable renderer lifecycle and bridge-authority behavior.

use uuid::Uuid;
use weregopher_domain::{
    AppInstanceId, ProtocolLimits, RendererBridgeInvocation, RendererBridgeNonce, RendererId,
    WireValue,
};
use weregopher_renderer::{
    PrivateOrigin, RendererBridgeAuthority, RendererBridgeError, RendererLifecycle,
    RendererLifecycleState,
};

fn app_id() -> AppInstanceId {
    AppInstanceId::from_uuid(Uuid::from_u128(1))
}

#[test]
fn lifecycle_rejects_stale_or_out_of_order_navigation_events()
-> Result<(), Box<dyn std::error::Error>> {
    let mut lifecycle = RendererLifecycle::new(RendererId::new(7));
    assert_eq!(lifecycle.state(), RendererLifecycleState::Creating);
    lifecycle.mark_initialized()?;
    let first = lifecycle.begin_navigation()?;
    lifecycle.mark_dom_content_loaded(first)?;
    lifecycle.mark_loaded(first)?;
    assert_eq!(lifecycle.state(), RendererLifecycleState::Loaded);

    let second = lifecycle.begin_navigation()?;
    assert!(lifecycle.mark_loaded(first).is_err());
    assert!(lifecycle.mark_loaded(second).is_err());
    lifecycle.mark_dom_content_loaded(second)?;
    lifecycle.mark_loaded(second)?;
    lifecycle.begin_close()?;
    lifecycle.mark_closed()?;
    assert_eq!(lifecycle.state(), RendererLifecycleState::Closed);
    assert!(lifecycle.begin_navigation().is_err());
    Ok(())
}

#[test]
fn crashed_renderer_can_only_progress_through_deterministic_close()
-> Result<(), Box<dyn std::error::Error>> {
    let mut lifecycle = RendererLifecycle::new(RendererId::new(7));
    lifecycle.mark_initialized()?;
    let generation = lifecycle.begin_navigation()?;
    lifecycle.mark_crashed()?;
    assert_eq!(lifecycle.state(), RendererLifecycleState::Crashed);
    assert!(lifecycle.mark_dom_content_loaded(generation).is_err());
    assert!(lifecycle.begin_navigation().is_err());
    lifecycle.begin_close()?;
    lifecycle.mark_closed()?;
    assert_eq!(lifecycle.state(), RendererLifecycleState::Closed);
    assert!(lifecycle.mark_crashed().is_err());
    Ok(())
}

#[test]
fn bridge_derives_authority_and_rejects_nonce_source_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let renderer = RendererId::new(7);
    let origin = PrivateOrigin::for_app(app_id());
    let source = origin.entry_url("index.html")?;
    let nonce = RendererBridgeNonce::new([0x7c; 16])?;
    let mut authority = RendererBridgeAuthority::new(
        app_id(),
        renderer,
        origin,
        1,
        nonce,
        "fixture.renderer",
        limits,
    )?;
    let invocation = RendererBridgeInvocation::new(
        nonce,
        41,
        "echo",
        vec![WireValue::String {
            value: "from-renderer".to_owned(),
        }],
        &limits,
    )?;

    let authorized = authority.authorize(&source, &invocation)?;
    assert_eq!(authorized.envelope().app(), app_id());
    assert_eq!(authorized.envelope().renderer(), renderer);
    assert_eq!(authorized.envelope().navigation_generation(), 1);
    assert_eq!(authorized.call().method(), "echo");
    assert_eq!(authorized.call().context().app, app_id());
    assert_eq!(authorized.call().context().renderer, Some(renderer));
    assert_eq!(
        authorized.call().context().frame.as_ref(),
        Some(authorized.envelope().frame())
    );
    assert_eq!(
        authorized.call().context().world.as_ref(),
        Some(authorized.envelope().world())
    );

    assert!(authority.authorize(&source, &invocation).is_err());
    let wrong_source = "https://other.weregopher.invalid/index.html";
    let fresh = RendererBridgeInvocation::new(nonce, 42, "echo", Vec::new(), &limits)?;
    assert!(authority.authorize(wrong_source, &fresh).is_err());
    let wrong_nonce = RendererBridgeInvocation::new(
        RendererBridgeNonce::new([0x8d; 16])?,
        43,
        "echo",
        Vec::new(),
        &limits,
    )?;
    assert!(authority.authorize(&source, &wrong_nonce).is_err());
    Ok(())
}

#[test]
fn rotating_navigation_authority_invalidates_the_previous_nonce()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits::secure_default();
    let origin = PrivateOrigin::for_app(app_id());
    let source = origin.entry_url("index.html")?;
    let old_nonce = RendererBridgeNonce::new([0x11; 16])?;
    let mut next = RendererBridgeAuthority::new(
        app_id(),
        RendererId::new(7),
        origin,
        2,
        RendererBridgeNonce::new([0x22; 16])?,
        "fixture.renderer",
        limits,
    )?;
    let stale = RendererBridgeInvocation::new(old_nonce, 1, "echo", Vec::new(), &limits)?;
    assert!(next.authorize(&source, &stale).is_err());
    Ok(())
}

#[test]
fn bridge_request_budget_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let limits = ProtocolLimits {
        max_pending_requests: 1,
        ..ProtocolLimits::secure_default()
    };
    let origin = PrivateOrigin::for_app(app_id());
    let source = origin.entry_url("index.html")?;
    let nonce = RendererBridgeNonce::new([0x33; 16])?;
    let mut authority = RendererBridgeAuthority::new(
        app_id(),
        RendererId::new(7),
        origin,
        1,
        nonce,
        "fixture.renderer",
        limits,
    )?;
    let first = RendererBridgeInvocation::new(nonce, 1, "echo", Vec::new(), &limits)?;
    let second = RendererBridgeInvocation::new(nonce, 2, "echo", Vec::new(), &limits)?;

    authority.authorize(&source, &first)?;
    assert_eq!(
        authority.authorize(&source, &second),
        Err(RendererBridgeError::RequestBudgetExceeded { maximum: 1 })
    );
    Ok(())
}

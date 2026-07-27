//! Bounded redacted app-server observation and authority-reducing policy behavior.

use std::time::{Duration, Instant};

use weregopher_adapter_openai::{
    AppServerBlockRule, AppServerControlError, AppServerCorrelationToken, AppServerEventDetail,
    AppServerEventLimits, AppServerEventStage, AppServerInterceptRuleId,
    AppServerInterceptionDecision, AppServerInterceptionPolicy, AppServerJsonLimits,
    AppServerMethodFingerprint, AppServerProxyDirection, AppServerProxyError, AppServerProxyLimits,
    AppServerProxyMessageKind, AppServerQueueLimits, AppServerSessionEventJournal,
    TransparentAppServerProxy,
};

fn proxy_limits() -> Result<AppServerProxyLimits, AppServerProxyError> {
    AppServerProxyLimits::new(
        4_096,
        AppServerQueueLimits::new(16, 32 * 1_024)?,
        AppServerQueueLimits::new(16, 32 * 1_024)?,
        AppServerJsonLimits::new(32, 1_024)?,
        16,
        128,
        Duration::from_secs(30),
    )
}

#[test]
fn journal_correlates_redacted_request_lifecycle_without_wire_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits()?);
    let mut journal = AppServerSessionEventJournal::new(AppServerEventLimits::new(16)?);
    let now = Instant::now();
    let request =
        br#"{"id":"wire-secret","method":"thread/start","params":{"token":"payload-secret"}}"#;

    let accepted_request = proxy.ingest_client(request)?;
    journal.record_accepted(&accepted_request)?;
    let forwarded_request = proxy
        .next_for_server(now)?
        .ok_or("request frame was absent")?;
    journal.record_forwarded(forwarded_request.observation())?;

    let response = br#"{"id":"wire-secret","result":{"thread":{"id":"private-thread"}}}"#;
    let accepted_response = proxy.ingest_server(response)?;
    journal.record_accepted(&accepted_response)?;
    let forwarded_response = proxy
        .next_for_client(now)?
        .ok_or("response frame was absent")?;
    journal.record_forwarded(forwarded_response.observation())?;

    let events = std::iter::from_fn(|| journal.next_event()).collect::<Vec<_>>();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].sequence(), 1);
    assert_eq!(events[3].sequence(), 4);
    let expected_method = AppServerMethodFingerprint::for_method("thread/start")?;
    let mut correlations = Vec::<AppServerCorrelationToken>::new();
    for (index, event) in events.iter().enumerate() {
        let AppServerEventDetail::Message(message) = event.detail() else {
            return Err("expected only message events".into());
        };
        assert_eq!(
            message.stage(),
            if index % 2 == 0 {
                AppServerEventStage::Accepted
            } else {
                AppServerEventStage::Forwarded
            }
        );
        if index < 2 {
            assert_eq!(message.method(), Some(&expected_method));
        } else {
            assert!(message.method().is_none());
        }
        correlations.push(message.correlation().ok_or("correlation was absent")?);
    }
    assert!(correlations.iter().all(|value| value == &correlations[0]));

    let debug = format!("{events:?}");
    assert!(!debug.contains("wire-secret"));
    assert!(!debug.contains("thread/start"));
    assert!(!debug.contains("payload-secret"));
    assert!(!debug.contains("private-thread"));
    Ok(())
}

#[test]
fn journal_reports_bounded_eviction_instead_of_silent_growth()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits()?);
    let mut journal = AppServerSessionEventJournal::new(AppServerEventLimits::new(2)?);
    for method in ["notice/one", "notice/two", "notice/three"] {
        let line = format!(r#"{{"method":"{method}","params":{{}}}}"#);
        let observation = proxy.ingest_client(line.as_bytes())?;
        journal.record_accepted(&observation)?;
        assert!(proxy.next_for_server(Instant::now())?.is_some());
    }

    let diagnostics = journal.diagnostics();
    assert_eq!(diagnostics.queued_events(), 2);
    assert_eq!(diagnostics.evicted_events(), 1);
    assert_eq!(
        journal
            .next_event()
            .ok_or("second event was absent")?
            .sequence(),
        2
    );
    assert_eq!(
        journal
            .next_event()
            .ok_or("third event was absent")?
            .sequence(),
        3
    );
    assert!(journal.next_event().is_none());
    Ok(())
}

#[test]
fn exact_method_policy_can_only_forward_or_block_before_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let rule_id = AppServerInterceptRuleId::new(7)?;
    let policy = AppServerInterceptionPolicy::new(vec![AppServerBlockRule::new(
        rule_id,
        AppServerProxyDirection::ServerToClient,
        AppServerProxyMessageKind::Request,
        "approval/request",
    )?])?;
    let proxy = TransparentAppServerProxy::new(proxy_limits()?);

    let matching = proxy.prepare_server(
        br#"{"id":"approval-secret","method":"approval/request","params":{"reason":"secret"}}"#,
    )?;
    assert_eq!(
        policy.evaluate(matching.observation()),
        AppServerInterceptionDecision::Block(rule_id)
    );
    let unknown = proxy
        .prepare_server(br#"{"id":2,"method":"future/unknown","params":{"additive":true}}"#)?;
    assert_eq!(
        policy.evaluate(unknown.observation()),
        AppServerInterceptionDecision::Forward
    );

    let debug = format!("{policy:?}");
    assert!(!debug.contains("approval/request"));
    assert!(!debug.contains("approval-secret"));
    Ok(())
}

#[test]
fn expiration_event_reuses_local_correlation_and_never_exposes_wire_id()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(AppServerProxyLimits::new(
        4_096,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerJsonLimits::new(16, 128)?,
        8,
        32,
        Duration::from_millis(10),
    )?);
    let mut journal = AppServerSessionEventJournal::new(AppServerEventLimits::new(8)?);
    let start = Instant::now();
    let request = proxy.ingest_client(
        br#"{"id":"expires-secret","method":"turn/start","params":{"private":true}}"#,
    )?;
    journal.record_accepted(&request)?;
    let forwarded = proxy
        .next_for_server(start)?
        .ok_or("request frame was absent")?;
    journal.record_forwarded(forwarded.observation())?;
    let expired = proxy.expire_requests(start + Duration::from_millis(10))?;
    journal.record_expired(&expired[0])?;

    let accepted = journal.next_event().ok_or("accepted event was absent")?;
    let forwarded = journal.next_event().ok_or("forwarded event was absent")?;
    let expired = journal.next_event().ok_or("expired event was absent")?;
    let AppServerEventDetail::Message(accepted) = accepted.detail() else {
        return Err("accepted event shape was wrong".into());
    };
    let AppServerEventDetail::Message(forwarded) = forwarded.detail() else {
        return Err("forwarded event shape was wrong".into());
    };
    let AppServerEventDetail::RequestExpired(expired) = expired.detail() else {
        return Err("expired event shape was wrong".into());
    };
    assert_eq!(accepted.correlation(), forwarded.correlation());
    assert_eq!(accepted.correlation(), Some(expired.correlation()));
    assert_eq!(expired.origin(), AppServerProxyDirection::ClientToServer);
    assert!(!format!("{expired:?}").contains("expires-secret"));
    Ok(())
}

#[test]
fn late_and_unmatched_responses_never_invent_local_correlations()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits()?);
    let mut journal = AppServerSessionEventJournal::new(AppServerEventLimits::new(16)?);
    let now = Instant::now();
    let request = proxy.ingest_client(br#"{"id":4,"method":"turn/start","params":{}}"#)?;
    journal.record_accepted(&request)?;
    let request_frame = proxy
        .next_for_server(now)?
        .ok_or("request frame was absent")?;
    journal.record_forwarded(request_frame.observation())?;

    let completed = proxy.ingest_server(br#"{"id":4,"result":{"ok":true}}"#)?;
    journal.record_accepted(&completed)?;
    let late = proxy.ingest_server(br#"{"id":4,"result":{"duplicate":true}}"#)?;
    journal.record_accepted(&late)?;
    let unmatched = proxy.ingest_server(br#"{"id":99,"error":{"code":-32000}}"#)?;
    journal.record_accepted(&unmatched)?;
    for _ in 0..3 {
        let frame = proxy
            .next_for_client(now)?
            .ok_or("response frame was absent")?;
        journal.record_forwarded(frame.observation())?;
    }

    let events = std::iter::from_fn(|| journal.next_event()).collect::<Vec<_>>();
    let correlations = events
        .iter()
        .filter_map(|event| {
            let AppServerEventDetail::Message(message) = event.detail() else {
                return None;
            };
            (message.kind() == AppServerProxyMessageKind::SuccessResponse
                || message.kind() == AppServerProxyMessageKind::ErrorResponse)
                .then_some(message.correlation())
        })
        .collect::<Vec<_>>();
    assert_eq!(correlations.len(), 6);
    assert!(correlations[0].is_some());
    assert!(correlations[1].is_none());
    assert!(correlations[2].is_none());
    assert!(correlations[3].is_some());
    assert!(correlations[4].is_none());
    assert!(correlations[5].is_none());
    Ok(())
}

#[test]
fn control_limits_and_rule_ambiguity_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        AppServerEventLimits::new(0),
        Err(AppServerControlError::InvalidEventLimits)
    ));
    assert!(matches!(
        AppServerEventLimits::new(65_537),
        Err(AppServerControlError::InvalidEventLimits)
    ));
    assert!(matches!(
        AppServerInterceptRuleId::new(0),
        Err(AppServerControlError::InvalidRuleId)
    ));
    let id = AppServerInterceptRuleId::new(1)?;
    assert!(matches!(
        AppServerBlockRule::new(
            id,
            AppServerProxyDirection::ServerToClient,
            AppServerProxyMessageKind::SuccessResponse,
            "response/cannot-have-method"
        ),
        Err(AppServerControlError::InvalidRuleMessageKind)
    ));
    let first = AppServerBlockRule::new(
        id,
        AppServerProxyDirection::ServerToClient,
        AppServerProxyMessageKind::Request,
        "approval/request",
    )?;
    let duplicate_id = AppServerBlockRule::new(
        id,
        AppServerProxyDirection::ClientToServer,
        AppServerProxyMessageKind::Notification,
        "other/method",
    )?;
    assert!(matches!(
        AppServerInterceptionPolicy::new(vec![first.clone(), duplicate_id]),
        Err(AppServerControlError::DuplicateRuleId)
    ));
    let duplicate_selector = AppServerBlockRule::new(
        AppServerInterceptRuleId::new(2)?,
        AppServerProxyDirection::ServerToClient,
        AppServerProxyMessageKind::Request,
        "approval/request",
    )?;
    assert!(matches!(
        AppServerInterceptionPolicy::new(vec![first, duplicate_selector]),
        Err(AppServerControlError::DuplicateRuleSelector)
    ));
    Ok(())
}

//! Bounded transparent app-server proxy behavior.

use std::time::{Duration, Instant};

use weregopher_adapter_openai::{
    AppServerJsonLimits, AppServerProxyDirection, AppServerProxyError, AppServerProxyLimits,
    AppServerProxyMessageKind, AppServerProxyState, AppServerQueueLimits, AppServerRequestId,
    TransparentAppServerProxy,
};

fn proxy_limits(
    to_server_messages: usize,
    to_server_bytes: usize,
    to_client_messages: usize,
    to_client_bytes: usize,
    active_requests: usize,
    request_timeout: Duration,
) -> Result<AppServerProxyLimits, AppServerProxyError> {
    AppServerProxyLimits::new(
        4_096,
        AppServerQueueLimits::new(to_server_messages, to_server_bytes)?,
        AppServerQueueLimits::new(to_client_messages, to_client_bytes)?,
        AppServerJsonLimits::new(32, 1_024)?,
        active_requests,
        128,
        request_timeout,
    )
}

#[test]
fn proxy_preserves_unknown_messages_and_exact_json_bytes() -> Result<(), Box<dyn std::error::Error>>
{
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        8,
        16_384,
        8,
        16_384,
        8,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();
    let request = br#"  { "id":7, "method":"future/do", "params":{"unknown":true,"items":[1,2]}, "futureTopLevel":"kept" }  "#;

    let request_observation = proxy.ingest_client(request)?;
    assert_eq!(
        request_observation.direction(),
        AppServerProxyDirection::ClientToServer
    );
    assert_eq!(
        request_observation.kind(),
        AppServerProxyMessageKind::Request
    );
    assert_eq!(request_observation.method(), Some("future/do"));
    assert_eq!(
        request_observation.request_id(),
        Some(&AppServerRequestId::Unsigned(7))
    );

    let forwarded_request = proxy
        .next_for_server(now)?
        .ok_or("client request was not queued")?;
    assert_eq!(forwarded_request.json_bytes(), request);
    let frame_debug = format!("{forwarded_request:?}");
    assert!(!frame_debug.contains("futureTopLevel"));
    assert!(!frame_debug.contains("future/do"));

    let response =
        br#"{ "id":7, "result":{"newVariant":{"nested":"preserved"}}, "unknownResponseField":9 }"#;
    let response_observation = proxy.ingest_server(response)?;
    assert_eq!(
        response_observation.kind(),
        AppServerProxyMessageKind::SuccessResponse
    );
    let forwarded_response = proxy
        .next_for_client(now)?
        .ok_or("server response was not queued")?;
    assert_eq!(forwarded_response.json_bytes(), response);
    assert_eq!(proxy.diagnostics().pending_client_requests(), 0);
    assert_eq!(proxy.diagnostics().unmatched_responses(), 0);
    Ok(())
}

#[test]
fn proxy_prepares_exact_frames_without_admitting_them() -> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        8,
        16_384,
        8,
        16_384,
        8,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();
    let request = br#" { "id":"candidate-secret", "method":"future/candidate", "params":{"token":"not-for-debug"} } "#;

    let candidate = proxy.prepare_client(request)?;
    assert_eq!(
        candidate.observation().direction(),
        AppServerProxyDirection::ClientToServer
    );
    assert_eq!(
        candidate.observation().kind(),
        AppServerProxyMessageKind::Request
    );
    assert_eq!(candidate.observation().method(), Some("future/candidate"));
    assert_eq!(candidate.json_bytes(), request);
    assert_eq!(proxy.diagnostics().accepted_client_messages(), 0);
    assert_eq!(proxy.diagnostics().queued_to_server_messages(), 0);

    let candidate_debug = format!("{candidate:?}");
    assert!(!candidate_debug.contains("candidate-secret"));
    assert!(!candidate_debug.contains("future/candidate"));
    assert!(!candidate_debug.contains("not-for-debug"));

    let observation = proxy.admit(candidate)?;
    assert_eq!(observation.method(), Some("future/candidate"));
    assert_eq!(proxy.diagnostics().accepted_client_messages(), 1);
    let forwarded = proxy
        .next_for_server(now)?
        .ok_or("prepared candidate was not admitted")?;
    assert_eq!(forwarded.json_bytes(), request);
    Ok(())
}

#[test]
fn proxy_rechecks_dynamic_state_when_admitting_a_prepared_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        1,
        1_024,
        1,
        1_024,
        4,
        Duration::from_secs(30),
    )?);

    let candidate = proxy.prepare_client(br#"{"method":"candidate/second"}"#)?;
    proxy.ingest_client(br#"{"method":"candidate/first"}"#)?;
    assert!(matches!(
        proxy.admit(candidate),
        Err(AppServerProxyError::QueueMessageLimitExceeded {
            direction: AppServerProxyDirection::ClientToServer
        })
    ));
    assert_eq!(proxy.diagnostics().accepted_client_messages(), 1);
    assert_eq!(proxy.diagnostics().queued_to_server_messages(), 1);
    Ok(())
}

#[test]
fn proxy_rejects_candidates_prepared_under_different_limits()
-> Result<(), Box<dyn std::error::Error>> {
    let source = TransparentAppServerProxy::new(proxy_limits(
        2,
        2_048,
        2,
        2_048,
        2,
        Duration::from_secs(30),
    )?);
    let candidate = source.prepare_client(br#"{"method":"candidate/limits"}"#)?;
    let mut destination = TransparentAppServerProxy::new(proxy_limits(
        3,
        2_048,
        2,
        2_048,
        2,
        Duration::from_secs(30),
    )?);

    assert!(matches!(
        destination.admit(candidate),
        Err(AppServerProxyError::CandidateLimitsMismatch)
    ));
    assert_eq!(destination.diagnostics().accepted_client_messages(), 0);
    assert_eq!(destination.diagnostics().queued_to_server_messages(), 0);
    Ok(())
}

#[test]
fn proxy_correlates_bidirectional_requests_in_independent_id_spaces()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        8,
        8_192,
        8,
        8_192,
        8,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();

    proxy.ingest_client(br#"{"id":1,"method":"thread/start","params":{}}"#)?;
    proxy.ingest_server(br#"{"id":1,"method":"approval/request","params":{"future":true}}"#)?;
    assert!(proxy.next_for_server(now)?.is_some());
    assert!(proxy.next_for_client(now)?.is_some());
    assert_eq!(proxy.diagnostics().pending_client_requests(), 1);
    assert_eq!(proxy.diagnostics().pending_server_requests(), 1);

    proxy.ingest_server(br#"{"id":1,"result":{"thread":{"id":"t"}}}"#)?;
    proxy.ingest_client(br#"{"id":1,"error":{"code":-32000,"message":"denied"}}"#)?;
    assert_eq!(proxy.diagnostics().pending_client_requests(), 0);
    assert_eq!(proxy.diagnostics().pending_server_requests(), 0);
    assert_eq!(proxy.diagnostics().unmatched_responses(), 0);
    Ok(())
}

#[test]
fn proxy_enforces_queue_and_line_limits_without_partial_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy =
        TransparentAppServerProxy::new(proxy_limits(1, 80, 1, 80, 4, Duration::from_secs(30))?);
    let now = Instant::now();

    proxy.ingest_client(br#"{"method":"notice/one","params":{}}"#)?;
    assert!(matches!(
        proxy.ingest_client(br#"{"method":"notice/two","params":{}}"#),
        Err(AppServerProxyError::QueueMessageLimitExceeded {
            direction: AppServerProxyDirection::ClientToServer
        })
    ));
    assert_eq!(proxy.diagnostics().queued_to_server_messages(), 1);
    assert!(proxy.next_for_server(now)?.is_some());

    let queue_oversized =
        br#"{"method":"notice/large","params":{"value":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}}"#;
    assert!(matches!(
        proxy.ingest_client(queue_oversized),
        Err(AppServerProxyError::QueueByteLimitExceeded {
            direction: AppServerProxyDirection::ClientToServer
        })
    ));
    assert_eq!(proxy.diagnostics().queued_to_server_messages(), 0);

    let line_oversized = format!(
        "{{\"method\":\"notice/too-large\",\"params\":{{\"value\":\"{}\"}}}}",
        "x".repeat(4_096)
    );
    assert!(matches!(
        proxy.ingest_client(line_oversized.as_bytes()),
        Err(AppServerProxyError::LineTooLarge)
    ));
    assert_eq!(proxy.diagnostics().accepted_client_messages(), 1);
    Ok(())
}

#[test]
fn proxy_preserves_fifo_order_and_exact_accounting_under_bounded_load()
-> Result<(), Box<dyn std::error::Error>> {
    let message_count = 64_usize;
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        message_count,
        64 * 1_024,
        4,
        4_096,
        4,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();
    let mut expected = Vec::with_capacity(message_count);
    let mut expected_bytes = 0_usize;
    let expected_message_count = u64::try_from(message_count)?;

    for index in 0..message_count {
        let line = format!(
            " {{\"method\":\"future/notice/{index}\",\"params\":{{\"index\":{index},\"unknown\":true}}}} "
        )
        .into_bytes();
        expected_bytes = expected_bytes
            .checked_add(line.len())
            .ok_or("fixture byte count overflowed")?;
        proxy.ingest_client(&line)?;
        expected.push(line);
    }

    let queued = proxy.diagnostics();
    assert_eq!(queued.accepted_client_messages(), expected_message_count);
    assert_eq!(
        queued.accepted_client_bytes(),
        u64::try_from(expected_bytes)?
    );
    assert_eq!(queued.queued_to_server_messages(), message_count);
    assert_eq!(queued.queued_to_server_bytes(), expected_bytes);
    assert_eq!(queued.peak_to_server_messages(), message_count);
    assert_eq!(queued.peak_to_server_bytes(), expected_bytes);

    for expected_line in &expected {
        let frame = proxy
            .next_for_server(now)?
            .ok_or("bounded queue ended before every frame was forwarded")?;
        assert_eq!(frame.json_bytes(), expected_line);
    }
    assert!(proxy.next_for_server(now)?.is_none());
    let drained = proxy.diagnostics();
    assert_eq!(
        drained.forwarded_to_server_messages(),
        expected_message_count
    );
    assert_eq!(drained.queued_to_server_messages(), 0);
    assert_eq!(drained.queued_to_server_bytes(), 0);
    assert_eq!(drained.peak_to_server_messages(), message_count);
    Ok(())
}

#[test]
fn proxy_deadlines_start_on_forward_and_late_responses_remain_visible()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        4,
        4_096,
        4,
        4_096,
        4,
        Duration::from_millis(100),
    )?);
    let start = Instant::now();
    let forward_time = start + Duration::from_secs(1);
    let deadline = forward_time + Duration::from_millis(100);

    proxy.ingest_client(br#"{"id":"request-secret","method":"thread/start","params":{}}"#)?;
    assert!(proxy.expire_requests(forward_time)?.is_empty());

    assert!(proxy.next_for_server(forward_time)?.is_some());
    let expired = proxy.expire_requests(deadline)?;
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].origin(), AppServerProxyDirection::ClientToServer);
    assert_eq!(
        expired[0].request_id(),
        &AppServerRequestId::Text("request-secret".to_owned())
    );
    assert!(!format!("{:?}", expired[0]).contains("request-secret"));

    proxy.ingest_server(br#"{"id":"request-secret","result":{"late":true}}"#)?;
    assert_eq!(proxy.diagnostics().expired_requests(), 1);
    assert_eq!(proxy.diagnostics().late_responses(), 1);
    assert_eq!(proxy.diagnostics().unmatched_responses(), 0);
    assert!(proxy.next_for_client(deadline)?.is_some());
    Ok(())
}

#[test]
fn proxy_prevents_request_id_reuse_and_bounds_retired_history()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(AppServerProxyLimits::new(
        1_024,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerJsonLimits::new(16, 128)?,
        1,
        2,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();

    proxy.ingest_client(br#"{"id":1,"method":"first","params":{}}"#)?;
    assert!(proxy.next_for_server(now)?.is_some());
    proxy.ingest_server(br#"{"id":1,"result":{"ok":true}}"#)?;
    assert_eq!(proxy.diagnostics().client_request_history(), 1);
    assert!(matches!(
        proxy.ingest_client(br#"{"id":1,"method":"reused","params":{}}"#),
        Err(AppServerProxyError::ReusedRequestId {
            direction: AppServerProxyDirection::ClientToServer
        })
    ));

    proxy.ingest_client(br#"{"id":2,"method":"second","params":{}}"#)?;
    assert!(proxy.next_for_server(now)?.is_some());
    proxy.ingest_server(br#"{"id":2,"result":{"ok":true}}"#)?;
    assert_eq!(proxy.diagnostics().client_request_history(), 2);
    assert!(matches!(
        proxy.ingest_client(br#"{"id":3,"method":"history/full","params":{}}"#),
        Err(AppServerProxyError::RequestHistoryLimitExceeded)
    ));

    proxy.ingest_server(br#"{"id":1,"result":{"duplicate":true}}"#)?;
    assert_eq!(proxy.diagnostics().late_responses(), 1);
    assert_eq!(proxy.diagnostics().unmatched_responses(), 0);
    proxy.ingest_server(br#"{"id":999,"error":{"code":-32000}}"#)?;
    assert_eq!(proxy.diagnostics().unmatched_responses(), 1);
    let close = proxy.close();
    assert_eq!(close.cleared_request_history(), 2);
    assert_eq!(proxy.diagnostics().client_request_history(), 0);
    Ok(())
}

#[test]
fn proxy_rejects_ambiguous_or_adversarial_json() -> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(AppServerProxyLimits::new(
        2_048,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerJsonLimits::new(4, 16)?,
        4,
        16,
        Duration::from_secs(30),
    )?);

    proxy.ingest_client(br#"{"id":1,"method":"one","params":{}}"#)?;
    assert!(matches!(
        proxy.ingest_client(br#"{"id":1,"method":"duplicate","params":{}}"#),
        Err(AppServerProxyError::DuplicateRequestId {
            direction: AppServerProxyDirection::ClientToServer
        })
    ));
    assert!(matches!(
        proxy.ingest_server(br#"{"id":1,"result":{},"error":{}}"#),
        Err(AppServerProxyError::AmbiguousMessageShape)
    ));
    assert!(matches!(
        proxy.ingest_server(br#"{"id":1.5,"result":{}}"#),
        Err(AppServerProxyError::InvalidRequestId)
    ));
    assert!(matches!(
        proxy.ingest_server(br#"{"method":"notice","params":{"key":1,"key":2}}"#),
        Err(AppServerProxyError::DuplicateObjectKey)
    ));
    assert!(matches!(
        proxy.ingest_server(br#"{"method":"notice","params":[[[[0]]]]}"#),
        Err(AppServerProxyError::JsonDepthLimitExceeded)
    ));
    assert!(matches!(
        proxy.ingest_server(
            br#"{"method":"notice","params":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]}"#
        ),
        Err(AppServerProxyError::JsonNodeLimitExceeded)
    ));
    assert!(matches!(
        proxy.ingest_server(br#"["not","an","object"]"#),
        Err(AppServerProxyError::TopLevelNotObject)
    ));
    assert!(matches!(
        proxy.ingest_server(b" \t "),
        Err(AppServerProxyError::EmptyLine)
    ));
    assert!(matches!(
        proxy.ingest_server(br#"{"id":null,"method":"invalid/null-id"}"#),
        Err(AppServerProxyError::InvalidRequestId)
    ));
    let oversized_method = format!("{{\"method\":\"{}\"}}", "m".repeat(1_025));
    assert!(matches!(
        proxy.ingest_server(oversized_method.as_bytes()),
        Err(AppServerProxyError::InvalidMethod)
    ));
    let oversized_id = format!("{{\"id\":\"{}\",\"result\":{{}}}}", "i".repeat(257));
    assert!(matches!(
        proxy.ingest_server(oversized_id.as_bytes()),
        Err(AppServerProxyError::InvalidRequestId)
    ));
    assert!(matches!(
        proxy.ingest_server(br#"{"method":"malformed",}"#),
        Err(AppServerProxyError::InvalidJson(_))
    ));
    assert!(matches!(
        proxy.ingest_server(b"{\"method\":\"notice\"}\n{\"method\":\"smuggled\"}"),
        Err(AppServerProxyError::EmbeddedLineBreak)
    ));
    assert_eq!(proxy.diagnostics().accepted_client_messages(), 1);
    assert_eq!(proxy.diagnostics().accepted_server_messages(), 0);
    Ok(())
}

#[test]
fn proxy_limit_construction_rejects_zero_and_incoherent_dimensions()
-> Result<(), Box<dyn std::error::Error>> {
    assert!(matches!(
        AppServerQueueLimits::new(0, 1),
        Err(AppServerProxyError::InvalidQueueLimits)
    ));
    assert!(matches!(
        AppServerJsonLimits::new(0, 1),
        Err(AppServerProxyError::InvalidJsonLimits)
    ));

    let queue = AppServerQueueLimits::new(1, 1)?;
    let json = AppServerJsonLimits::new(1, 1)?;
    assert!(matches!(
        AppServerProxyLimits::new(0, queue, queue, json, 1, 1, Duration::from_secs(1)),
        Err(AppServerProxyError::InvalidLineLimit)
    ));
    assert!(matches!(
        AppServerProxyLimits::new(1, queue, queue, json, 0, 1, Duration::from_secs(1)),
        Err(AppServerProxyError::InvalidActiveRequestLimit)
    ));
    assert!(matches!(
        AppServerProxyLimits::new(1, queue, queue, json, 2, 1, Duration::from_secs(1)),
        Err(AppServerProxyError::InvalidRequestHistoryLimit)
    ));
    assert!(matches!(
        AppServerProxyLimits::new(1, queue, queue, json, 1, 1, Duration::ZERO),
        Err(AppServerProxyError::InvalidRequestTimeout)
    ));
    Ok(())
}

#[test]
fn proxy_rejects_non_monotonic_deadline_clock() -> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        4,
        4_096,
        4,
        4_096,
        4,
        Duration::from_secs(30),
    )?);
    let start = Instant::now();
    let later = start + Duration::from_secs(2);
    let earlier = start + Duration::from_secs(1);

    assert!(proxy.next_for_server(later)?.is_none());
    assert!(matches!(
        proxy.next_for_client(earlier),
        Err(AppServerProxyError::NonMonotonicClock)
    ));
    assert!(matches!(
        proxy.expire_requests(earlier),
        Err(AppServerProxyError::NonMonotonicClock)
    ));
    assert!(proxy.expire_requests(later)?.is_empty());
    Ok(())
}

#[test]
fn proxy_active_request_limit_and_response_ordering_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(AppServerProxyLimits::new(
        1_024,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerQueueLimits::new(8, 8_192)?,
        AppServerJsonLimits::new(16, 128)?,
        1,
        8,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();

    proxy.ingest_client(br#"{"id":1,"method":"queued","params":{}}"#)?;
    assert!(matches!(
        proxy.ingest_server(br#"{"id":1,"result":{"impossible":true}}"#),
        Err(AppServerProxyError::ResponseBeforeRequestForwarded)
    ));
    assert_eq!(proxy.diagnostics().accepted_server_messages(), 0);
    assert_eq!(proxy.diagnostics().queued_to_server_messages(), 1);
    assert!(matches!(
        proxy.ingest_server(br#"{"id":1,"method":"server/request","params":{}}"#),
        Err(AppServerProxyError::ActiveRequestLimitExceeded)
    ));

    assert!(proxy.next_for_server(now)?.is_some());
    proxy.ingest_server(br#"{"id":1,"result":{"ok":true}}"#)?;
    assert_eq!(proxy.diagnostics().pending_client_requests(), 0);
    assert_eq!(proxy.diagnostics().client_request_history(), 1);
    Ok(())
}

#[test]
fn proxy_close_clears_state_and_debug_output_redacts_payloads()
-> Result<(), Box<dyn std::error::Error>> {
    let mut proxy = TransparentAppServerProxy::new(proxy_limits(
        4,
        4_096,
        4,
        4_096,
        4,
        Duration::from_secs(30),
    )?);
    let now = Instant::now();
    proxy.ingest_client(
        br#"{"id":"private-request-id","method":"private/method","params":{"token":"do-not-log"}}"#,
    )?;
    assert!(proxy.next_for_server(now)?.is_some());
    proxy.ingest_server(
        br#"{"method":"private/notice","params":{"secret":"not-for-diagnostics"}}"#,
    )?;

    let debug = format!("{proxy:?}");
    assert!(!debug.contains("private-request-id"));
    assert!(!debug.contains("not-for-diagnostics"));

    let close = proxy.close();
    assert_eq!(close.abandoned_messages(), 1);
    assert_eq!(close.abandoned_requests(), 1);
    assert!(close.abandoned_bytes() > 0);
    assert_eq!(proxy.state(), AppServerProxyState::Closed);
    assert_eq!(proxy.diagnostics().queued_to_client_messages(), 0);
    assert_eq!(proxy.diagnostics().pending_client_requests(), 0);
    assert!(matches!(
        proxy.ingest_client(br#"{"method":"after/close"}"#),
        Err(AppServerProxyError::Closed)
    ));
    assert!(proxy.next_for_client(now)?.is_none());
    let second_close = proxy.close();
    assert_eq!(second_close.abandoned_messages(), 0);
    assert_eq!(second_close.abandoned_requests(), 0);
    assert_eq!(second_close.cleared_request_history(), 0);
    Ok(())
}

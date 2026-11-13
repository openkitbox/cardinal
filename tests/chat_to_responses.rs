//! Chat client → Responses upstream, driven through the public translation
//! API with real wire bytes in both directions: the request a Chat client
//! sends is translated to the body the upstream receives, and the SSE bytes a
//! Responses upstream emits are decoded and re-framed as the Chat chunks the
//! client receives. The relay's dispatch wiring (credentials, failover,
//! billing) is out of scope here; it needs a database.

use bytes::Bytes;
use cardinal::protocol::sse::RawFrame;
use cardinal::protocol::{Decoder, ProtocolId, Terminal};
use cardinal::translation::stream::StreamTranslator;
use cardinal::translation::{for_protocol, openai_chat};
use serde_json::{Value, json};

fn upstream_body(chat_request: &Value, model: &str) -> Value {
    let (ir, _) = openai_chat::to_ir(chat_request, u64::MAX).expect("chat request parses");
    let dialect = for_protocol(ProtocolId::OpenAiResponses).expect("responses dialect");
    let (body, _) = (dialect.from_ir)(&ir, model).expect("responses body builds");
    body
}

fn sse(event: &Value) -> RawFrame {
    RawFrame {
        event: event["type"].as_str().map(str::to_owned),
        id: None,
        data: Bytes::from(event.to_string()),
    }
}

/// Run upstream events through the decoder and translator the way the relay's
/// translated pump does, returning the Chat chunks (parsed) the client sees.
fn chat_chunks(events: &[Value]) -> (Vec<Value>, Terminal) {
    let mut decoder = Decoder::new(ProtocolId::OpenAiResponses, None);
    let mut translator = StreamTranslator::new(
        ProtocolId::OpenAiChat,
        ProtocolId::OpenAiResponses,
        "gpt-5.4",
        "req-1",
    )
    .expect("chat client");
    let mut out = Vec::new();
    for event in events {
        let upstream = decoder.observe_raw(&sse(event)).expect("frame decodes");
        out.extend(translator.translate(upstream).expect("events translate"));
    }
    let chunks = out
        .iter()
        .filter(|frame| frame.data.as_ref() != b"[DONE]")
        .map(|frame| serde_json::from_slice(&frame.data).expect("chat chunk is JSON"))
        .collect();
    (chunks, decoder.finish())
}

#[test]
fn chat_request_reaches_the_upstream_as_a_responses_body() {
    let body = upstream_body(
        &json!({
            "model": "gpt-5.4",
            "temperature": 0.2,
            "reasoning_effort": "high",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "weather in Paris?"},
                {"role": "assistant", "content": null, "reasoning_content": "check tool",
                 "tool_calls": [{"id": "call_1", "type": "function",
                                 "function": {"name": "weather", "arguments": "{\"city\":\"Paris\"}"}}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "sunny"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "weather", "description": "d",
                "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}]
        }),
        "gpt-5.4",
    );

    assert_eq!(body["model"], "gpt-5.4");
    assert_eq!(body["instructions"], "be terse");
    assert_eq!(body["reasoning"]["effort"], "high");
    assert_eq!(body["reasoning"]["summary"], "auto");
    assert!(
        body.get("temperature").is_none(),
        "reasoning models take no sampling parameters: {body}"
    );
    assert!(body.get("stream").is_none() && body.get("store").is_none());
    assert!(
        body["prompt_cache_key"]
            .as_str()
            .is_some_and(|key| key.starts_with("cardinal_cc_")),
        "a target-scoped derived cache key is sent when the client sent none: {body}"
    );

    let tool = &body["tools"][0];
    assert_eq!(tool["type"], "function");
    assert_eq!(tool["name"], "weather");
    assert_eq!(tool["strict"], false);

    let input = body["input"].as_array().expect("typed input items");
    let types: Vec<&str> = input
        .iter()
        .map(|item| item["type"].as_str().expect("every item is typed"))
        .collect();
    assert_eq!(types, ["message", "function_call", "function_call_output"]);
    assert_eq!(input[1]["call_id"], "call_1");
    assert_eq!(input[1]["arguments"], "{\"city\":\"Paris\"}");
    assert_eq!(input[2]["call_id"], "call_1");
    assert_eq!(input[2]["output"], "sunny");
    assert!(
        !body.to_string().contains("check tool"),
        "replayed reasoning text must not reach the upstream: {body}"
    );
}

#[test]
fn text_stream_becomes_chat_chunks_with_stop() {
    let (chunks, terminal) = chat_chunks(&[
        json!({"type": "response.reasoning_summary_text.delta", "output_index": 0, "delta": "hm"}),
        json!({"type": "response.output_text.delta", "output_index": 1, "delta": "Hel"}),
        json!({"type": "response.output_text.delta", "output_index": 1, "delta": "lo"}),
        json!({"type": "response.completed", "response": {"status": "completed",
               "usage": {"input_tokens": 12, "output_tokens": 5,
                         "input_tokens_details": {"cached_tokens": 8}}}}),
    ]);
    assert!(matches!(terminal, Terminal::Completed));

    let text: String = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["delta"]["content"].as_str())
        .collect();
    assert_eq!(text, "Hello");
    let reasoning: String = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["delta"]["reasoning_content"].as_str())
        .collect();
    assert_eq!(reasoning, "hm");
    let finish = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["finish_reason"].as_str())
        .next_back();
    assert_eq!(finish, Some("stop"));
}

#[test]
fn tool_call_stream_finishes_as_tool_calls() {
    let (chunks, _) = chat_chunks(&[
        json!({"type": "response.output_item.added", "output_index": 0,
               "item": {"type": "reasoning", "id": "rs_1"}}),
        json!({"type": "response.output_item.added", "output_index": 1,
               "item": {"type": "function_call", "call_id": "call_9", "name": "weather", "arguments": ""}}),
        json!({"type": "response.function_call_arguments.delta", "output_index": 1, "delta": "{\"city\":"}),
        json!({"type": "response.function_call_arguments.delta", "output_index": 1, "delta": "\"Paris\"}"}),
        json!({"type": "response.completed", "response": {"status": "completed",
               "output": [
                   {"type": "reasoning", "id": "rs_1", "summary": []},
                   {"type": "function_call", "call_id": "call_9", "name": "weather",
                    "arguments": "{\"city\":\"Paris\"}"}
               ],
               "usage": {"input_tokens": 3, "output_tokens": 2}}}),
    ]);

    let calls: Vec<&Value> = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["delta"]["tool_calls"].get(0))
        .collect();
    assert_eq!(
        calls[0]["index"], 0,
        "tool slots are dense, not output positions"
    );
    assert_eq!(calls[0]["id"], "call_9");
    assert_eq!(calls[0]["function"]["name"], "weather");
    let arguments: String = calls
        .iter()
        .filter_map(|call| call["function"]["arguments"].as_str())
        .collect();
    assert_eq!(arguments, "{\"city\":\"Paris\"}");
    let finish = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["finish_reason"].as_str())
        .next_back();
    assert_eq!(finish, Some("tool_calls"));
}

#[test]
fn output_limit_finishes_as_length() {
    let (chunks, _) = chat_chunks(&[
        json!({"type": "response.output_text.delta", "output_index": 0, "delta": "cut"}),
        json!({"type": "response.incomplete", "response": {"status": "incomplete",
               "incomplete_details": {"reason": "max_output_tokens"},
               "usage": {"input_tokens": 3, "output_tokens": 2}}}),
    ]);
    let finish = chunks
        .iter()
        .filter_map(|chunk| chunk["choices"][0]["finish_reason"].as_str())
        .next_back();
    assert_eq!(finish, Some("length"));
}

#[test]
fn upstream_failure_is_not_reported_as_completed() {
    let (chunks, terminal) = chat_chunks(&[
        json!({"type": "response.output_text.delta", "output_index": 0, "delta": "x"}),
        json!({"type": "response.failed", "response": {"status": "failed",
               "error": {"code": "server_error", "message": "boom"}}}),
    ]);
    assert!(
        !matches!(terminal, Terminal::Completed),
        "a failed upstream must not settle as a completed stream"
    );
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk["choices"][0]["finish_reason"].is_null()),
        "a failed upstream must not hand the client a finish reason: {chunks:?}"
    );
}

#[test]
fn non_streaming_response_translates_to_a_chat_completion() {
    let upstream = json!({
        "model": "gpt-5.4", "status": "completed",
        "output": [
            {"type": "reasoning", "summary": [{"type": "summary_text", "text": "plan"}]},
            {"type": "message", "content": [{"type": "output_text", "text": "calling"}]},
            {"type": "function_call", "call_id": "call_2", "name": "weather",
             "arguments": "{\"city\":\"Rome\"}"}
        ],
        "usage": {"input_tokens": 7, "output_tokens": 4}
    });
    let responses = for_protocol(ProtocolId::OpenAiResponses).expect("responses dialect");
    let ir = (responses.response_to_ir)(upstream.to_string().as_bytes(), None)
        .expect("upstream body parses");
    let chat = for_protocol(ProtocolId::OpenAiChat).expect("chat dialect");
    let emitted = (chat.emit_response_json)(&ir).expect("chat body emits");
    let body: Value = serde_json::from_slice(&emitted).expect("chat body is JSON");

    let message = &body["choices"][0]["message"];
    assert_eq!(message["content"], "calling");
    assert_eq!(message["tool_calls"][0]["id"], "call_2");
    assert_eq!(message["tool_calls"][0]["function"]["name"], "weather");
    assert_eq!(body["choices"][0]["finish_reason"], "tool_calls");
}

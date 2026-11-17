//! `POST ai/v1/chat/completions`: decrypt the user's turns, forward them to an
//! OpenAI-compatible model API, and stream the answer back encrypted with the
//! request key (Lumo's "U2L" scheme).

use std::time::Duration;

use axum::{
    Json,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use leptiq_core::{AppState, auth::AuthUser};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::{AssistantConfig, keys};

fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    retry_after: Option<HeaderValue>,
) -> Response {
    let mut resp = (
        status,
        Json(json!({ "error": { "code": code, "type": code, "message": message } })),
    )
        .into_response();
    if let Some(ra) = retry_after {
        resp.headers_mut().insert(header::RETRY_AFTER, ra);
    }
    resp
}

/// Encryption for one request: the unwrapped AES key and the request id.
struct U2l {
    key: [u8; 32],
    request_id: String,
}

impl U2l {
    fn open(&self, value: &str) -> anyhow::Result<String> {
        let bytes = keys::decrypt(&self.key, value, &keys::request_ad(&self.request_id))?;
        Ok(String::from_utf8(bytes)?)
    }

    fn seal(&self, plaintext: &str) -> String {
        keys::encrypt(
            &self.key,
            plaintext.as_bytes(),
            &keys::response_ad(&self.request_id),
        )
    }
}

/// Plain-text content of a turn (decrypting it if needed). Images and other
/// non-text parts are dropped: the upstream model may not accept them.
fn turn_text(turn: &Value, u2l: Option<&U2l>) -> anyhow::Result<String> {
    let encrypted_turn = turn["encrypted"].as_bool().unwrap_or(false);
    let open = |s: &str, encrypted: bool| -> anyhow::Result<String> {
        match (encrypted, u2l) {
            (true, Some(u)) => u.open(s),
            (true, None) => anyhow::bail!("encrypted turn without a request key"),
            (false, _) => Ok(s.to_string()),
        }
    };
    match &turn["content"] {
        Value::String(s) => open(s, encrypted_turn),
        Value::Array(parts) => {
            let mut out = Vec::new();
            for p in parts {
                if p["type"] == "text"
                    && let Some(t) = p["text"].as_str()
                {
                    out.push(open(t, p["encrypted"].as_bool().unwrap_or(encrypted_turn))?);
                }
            }
            Ok(out.join("\n"))
        }
        _ => Ok(String::new()),
    }
}

/// Builds the upstream chat request from the client's turns.
fn upstream_messages(
    body: &Value,
    u2l: Option<&U2l>,
    config: &AssistantConfig,
) -> anyhow::Result<Vec<Value>> {
    let mut messages = Vec::new();
    if !config.system_prompt.is_empty() {
        messages.push(json!({ "role": "system", "content": config.system_prompt }));
    }
    for turn in body["messages"].as_array().into_iter().flatten() {
        let role = turn["role"].as_str().unwrap_or("user");
        let role = match role {
            "system" | "user" | "assistant" => role,
            // Tool calls/results are Lumo-specific; tools are not offered.
            _ => continue,
        };
        let text = turn_text(turn, u2l)?;
        if text.is_empty() && role != "assistant" {
            continue;
        }
        messages.push(json!({ "role": role, "content": text }));
    }
    Ok(messages)
}

pub async fn completions(
    State(state): State<AppState>,
    _user: AuthUser,
    Json(body): Json<Value>,
) -> Response {
    let config = state.ext::<AssistantConfig>().clone();
    let lumo = &body["lumo"];
    let target = lumo["target"].as_str().unwrap_or("message").to_string();
    let u2l = match (lumo["request_key"].as_str(), lumo["request_id"].as_str()) {
        (Some(k), Some(id)) => {
            let server_key = match crate::server_key(&state).await {
                Ok(k) => k,
                Err(e) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "error",
                        &e.to_string(),
                        None,
                    );
                }
            };
            match server_key.request_key(k) {
                Ok(key) => Some(U2l {
                    key,
                    request_id: id.to_string(),
                }),
                Err(e) => {
                    tracing::warn!("assistant: cannot unwrap request key: {e}");
                    return error_response(
                        StatusCode::BAD_REQUEST,
                        "rejected",
                        "The request key is not encrypted to this server's key (client built for another server?)",
                        None,
                    );
                }
            }
        }
        _ => None,
    };
    let messages = match upstream_messages(&body, u2l.as_ref(), &config) {
        Ok(m) => m,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, "rejected", &e.to_string(), None),
    };
    let client_model = body["model"].as_str().unwrap_or("lumo-lite").to_string();
    let model = config
        .models
        .get(&client_model)
        .cloned()
        .unwrap_or_else(|| config.model.clone());
    let mut upstream_body = json!({ "model": model, "messages": messages, "stream": true });
    if let Some(max) = config.max_tokens {
        upstream_body["max_tokens"] = json!(max);
    }

    let http = crate::http_client();
    let url = format!("{}/chat/completions", config.base_url.trim_end_matches('/'));
    let mut req = http
        .post(&url)
        .json(&upstream_body)
        .timeout(Duration::from_secs(600));
    if !config.api_key.is_empty() {
        req = req.bearer_auth(&config.api_key);
    }
    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("assistant: upstream request failed: {e}");
            return error_response(
                StatusCode::BAD_GATEWAY,
                "error",
                "The model provider is unreachable",
                None,
            );
        }
    };
    if !upstream.status().is_success() {
        let status = upstream.status();
        let retry_after = upstream.headers().get(header::RETRY_AFTER).cloned();
        let text = upstream.text().await.unwrap_or_default();
        tracing::warn!(
            "assistant: upstream returned {status}: {}",
            text.chars().take(300).collect::<String>()
        );
        return if status == StatusCode::TOO_MANY_REQUESTS {
            error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "rejected",
                "The model provider's rate limit was reached; try again later",
                retry_after,
            )
        } else {
            error_response(
                StatusCode::BAD_GATEWAY,
                "error",
                "The model provider returned an error",
                None,
            )
        };
    }

    // Relay the upstream SSE stream, re-encoding each delta for the client.
    let (tx, rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let mut stream = upstream.bytes_stream();
        let mut buf = String::new();
        let send = |v: Value| Bytes::from(format!("data: {v}\n\n"));
        let _ = tx.send(Bytes::from_static(b": ingesting\n\n")).await;
        'outer: while let Some(chunk) = stream.next().await {
            let Ok(chunk) = chunk else { break };
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(pos) = buf.find('\n') {
                let line = buf[..pos].trim_end_matches('\r').to_string();
                buf.drain(..=pos);
                let Some(data) = line.strip_prefix("data:").map(str::trim) else {
                    continue;
                };
                if data == "[DONE]" {
                    break 'outer;
                }
                let Ok(v) = serde_json::from_str::<Value>(data) else {
                    continue;
                };
                let choice = &v["choices"][0];
                let finish = choice["finish_reason"].clone();
                for (field, tgt) in [
                    ("reasoning_content", "reasoning"),
                    ("reasoning", "reasoning"),
                    ("content", target.as_str()),
                ] {
                    let Some(text) = choice["delta"][field].as_str().filter(|t| !t.is_empty())
                    else {
                        continue;
                    };
                    let delta = match &u2l {
                        Some(u) => {
                            json!({ "content": u.seal(text), "encrypted": true, "target": tgt })
                        }
                        None => json!({ "content": text, "target": tgt }),
                    };
                    let out = json!({
                        "model": client_model,
                        "choices": [{ "index": 0, "delta": delta, "finish_reason": null }],
                    });
                    if tx.send(send(out)).await.is_err() {
                        return;
                    }
                }
                if !finish.is_null() {
                    let out = json!({
                        "model": client_model,
                        "choices": [{ "index": 0, "delta": {}, "finish_reason": finish }],
                    });
                    let _ = tx.send(send(out)).await;
                }
            }
        }
        let _ = tx.send(Bytes::from_static(b"data: [DONE]\n\n")).await;
    });
    let body = Body::from_stream(futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|b| (Ok::<_, std::io::Error>(b), rx))
    }));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

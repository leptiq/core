mod common;

use std::sync::{Arc, Mutex};

use axum::{Json, Router, response::IntoResponse, routing::post};
use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use pgp::composed::{Deserializable, MessageBuilder, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use serde_json::{Value, json};

/// A minimal OpenAI-compatible upstream: records the request and streams a
/// fixed answer, or answers 429 when `limited`.
async fn mock_upstream(seen: Arc<Mutex<Vec<Value>>>, limited: bool) -> String {
    let app = Router::new().route(
        "/v1/chat/completions",
        post(move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
            let seen = seen.clone();
            async move {
                let mut b = body.clone();
                b["auth"] = json!(headers.get("authorization").and_then(|v| v.to_str().ok()));
                seen.lock().unwrap().push(b);
                if limited {
                    return (
                        axum::http::StatusCode::TOO_MANY_REQUESTS,
                        [("retry-after", "42")],
                        r#"{"error":{"type":"FreeUsageLimitError"}}"#.to_string(),
                    )
                        .into_response();
                }
                let chunks = ["Hel", "lo", " there"];
                let mut sse = String::new();
                for c in chunks {
                    sse.push_str(&format!(
                        "data: {}\n\n",
                        json!({ "choices": [{ "index": 0, "delta": { "content": c }, "finish_reason": null }] })
                    ));
                }
                sse.push_str(&format!(
                    "data: {}\n\n",
                    json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }] })
                ));
                sse.push_str("data: [DONE]\n\n");
                ([("content-type", "text/event-stream")], sse).into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/v1")
}

fn wrap_key(public_armored: &str, key: &[u8; 32]) -> String {
    let (public, _) = SignedPublicKey::from_string(public_armored).unwrap();
    let sub = &public.public_subkeys[0];
    let mut builder = MessageBuilder::from_bytes("", key.to_vec())
        .seipd_v1(rand::thread_rng(), SymmetricKeyAlgorithm::AES256);
    builder.encrypt_to_key(rand::thread_rng(), &sub).unwrap();
    STANDARD.encode(builder.to_vec(rand::thread_rng()).unwrap())
}

async fn chat(s: &TestServer, c: &Client, body: Value) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(format!("{}/ai/v1/chat/completions", s.base))
        .header("x-pm-appversion", "web-lumo@1.0.0")
        .header("x-pm-uid", c.uid.clone().unwrap())
        .bearer_auth(c.access.clone().unwrap())
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap())
}

/// Lumo's U2L flow end to end against a mock model API.
#[tokio::test]
async fn assistant_chat_is_end_to_end_encrypted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let upstream = mock_upstream(seen.clone(), false).await;
    let s = server_with(|c| {
        c.set_section(
            "assistant",
            json!({ "base_url": upstream, "api_key": "k-123", "model": "mock-model", "system_prompt": "Be brief." }),
        )
    })
    .await;
    let c = Client::signup(&s, &unique("ai"), "pw").await;

    let public = reqwest::Client::new()
        .get(format!("{}/assistant/public-key", s.base))
        .header("x-pm-appversion", "web-lumo@1.0.0")
        .send()
        .await
        .unwrap();
    assert_eq!(public.status(), 200);
    let public = public.text().await.unwrap();
    assert!(public.contains("BEGIN PGP PUBLIC KEY BLOCK"));

    let key = [7u8; 32];
    let request_id = "11111111-2222-4333-8444-555555555555";
    let ad = format!("lumo.request.{request_id}.turn");
    let body = json!({
        "model": "lumo-lite",
        "stream": true,
        "messages": [
            { "role": "user", "content": aes_encrypt(&key, b"What is 2+2?", &ad), "encrypted": true },
            { "role": "lumo_tool_call", "content": "ignored" },
        ],
        "lumo": { "target": "message", "request_key": wrap_key(&public, &key), "request_id": request_id },
    });
    let (status, sse) = chat(&s, &c, body).await;
    assert_eq!(status, 200, "{sse}");

    // Upstream saw plaintext, our model and key, plus the system prompt.
    let req = seen.lock().unwrap()[0].clone();
    assert_eq!(req["model"], "mock-model");
    assert_eq!(req["auth"], "Bearer k-123");
    assert_eq!(req["messages"][0]["content"], "Be brief.");
    assert_eq!(
        req["messages"][1],
        json!({ "role": "user", "content": "What is 2+2?" })
    );
    assert_eq!(req["messages"].as_array().unwrap().len(), 2);

    // The client gets encrypted deltas that decrypt to the answer.
    let response_ad = format!("lumo.response.{request_id}.chunk");
    let mut answer = String::new();
    let mut finished = false;
    for line in sse.lines() {
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        if data == "[DONE]" {
            break;
        }
        let v: Value = serde_json::from_str(data).unwrap();
        let ch = &v["choices"][0];
        if let Some(ct) = ch["delta"]["content"].as_str() {
            assert_eq!(ch["delta"]["encrypted"], true);
            assert_eq!(ch["delta"]["target"], "message");
            assert_ne!(ct, "Hel");
            answer.push_str(&String::from_utf8(aes_decrypt(&key, ct, &response_ad)).unwrap());
        }
        finished |= ch["finish_reason"] == "stop";
    }
    assert_eq!(answer, "Hello there");
    assert!(finished);
    assert!(sse.trim_end().ends_with("data: [DONE]"));

    // A key wrapped for another server is refused.
    let (other_public, _) = {
        let (_, p) = gen_key("other");
        (p, ())
    };
    let bad = json!({
        "model": "lumo-lite", "stream": true,
        "messages": [{ "role": "user", "content": aes_encrypt(&key, b"x", &ad), "encrypted": true }],
        "lumo": { "request_key": wrap_key(&other_public, &key), "request_id": request_id },
    });
    assert_eq!(chat(&s, &c, bad).await.0, 400);

    // Lumo UI flags: guest mode off.
    let flags = c.get("feature/v2/frontend").await;
    assert!(
        flags["toggles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "LumoDeactivateGuestModeFrontend")
    );
}

#[tokio::test]
async fn assistant_passes_on_rate_limits() {
    let upstream = mock_upstream(Arc::new(Mutex::new(Vec::new())), true).await;
    let s = server_with(|c| c.set_section("assistant", json!({ "base_url": upstream }))).await;
    let c = Client::signup(&s, &unique("ai"), "pw").await;
    let (status, body) = chat(
        &s,
        &c,
        json!({ "model": "lumo-lite", "stream": true, "messages": [{ "role": "user", "content": "hi" }] }),
    )
    .await;
    assert_eq!(status, 429, "{body}");
    assert!(body.contains("rejected"));
}

/// Encrypted conversation storage and its event loop.
#[tokio::test]
async fn assistant_storage() {
    let s = server().await;
    let c = Client::signup(&s, &unique("ai"), "pw").await;
    assert!(
        c.get("lumo/v1/masterkeys").await["MasterKeys"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    c.post("lumo/v1/masterkeys", json!({ "MasterKey": "pgp-msg" }))
        .await;
    let mk = c.get("lumo/v1/masterkeys").await;
    assert_eq!(mk["MasterKeys"][0]["IsLatest"], true);
    assert_eq!(mk["Eligibility"], 0);

    let latest = c.get("lumo/v1/events/latest").await["EventID"]
        .as_str()
        .unwrap()
        .to_string();
    let space = c
        .post(
            "lumo/v1/spaces",
            json!({ "SpaceType": 0, "SpaceKey": "sk", "SpaceTag": "tag-s", "Encrypted": "enc-s" }),
        )
        .await["Space"]["ID"]
        .as_str()
        .unwrap()
        .to_string();
    let dup = c
        .req(
            "POST",
            "lumo/v1/spaces",
            Some(json!({ "SpaceKey": "sk", "SpaceTag": "tag-s" })),
        )
        .await;
    assert_eq!(dup.status, 409);
    let conv = c
        .post(
            &format!("lumo/v1/spaces/{space}/conversations"),
            json!({ "SpaceID": space, "IsStarred": false, "Encrypted": "enc-c", "ConversationTag": "tag-c" }),
        )
        .await["Conversation"]["ID"]
        .as_str()
        .unwrap()
        .to_string();
    let msg = c
        .post(
            &format!("lumo/v1/conversations/{conv}/messages"),
            json!({ "ConversationID": conv, "Role": 1, "ParentID": null, "Status": 2, "Encrypted": "enc-m", "MessageTag": "tag-m" }),
        )
        .await["Message"]["ID"]
        .as_str()
        .unwrap()
        .to_string();

    let spaces = c.get("lumo/v1/spaces?PageSize=10").await;
    let sp = &spaces["Spaces"][0];
    assert_eq!(sp["SpaceTag"], "tag-s");
    assert!(sp["CreateTime"].as_str().unwrap().ends_with('Z'));
    assert_eq!(sp["Conversations"][0]["ConversationTag"], "tag-c");
    let full = c.get(&format!("lumo/v1/conversations/{conv}")).await;
    assert_eq!(full["Conversation"]["Messages"][0]["MessageTag"], "tag-m");
    assert!(
        full["Conversation"]["Messages"][0]
            .get("Encrypted")
            .is_none()
    );
    assert_eq!(
        c.get(&format!("lumo/v1/messages/{msg}")).await["Message"]["Encrypted"],
        "enc-m"
    );

    c.put(
        &format!("lumo/v1/conversations/{conv}"),
        json!({ "ID": conv, "SpaceID": space, "IsStarred": true, "Encrypted": "enc-c2", "ConversationTag": "tag-c" }),
    )
    .await;
    c.post(
        "lumo/v1/settings",
        json!({ "UserSettingsTag": "st", "Encrypted": "e" }),
    )
    .await;
    assert_eq!(
        c.get("lumo/v1/settings").await["UserSettings"]["UserSettingsTag"],
        "st"
    );

    let ev = c.get(&format!("lumo/v1/events/{latest}")).await;
    assert_eq!(ev["LumoSpaces"][0], json!({ "ID": space, "Action": 1 }));
    assert_eq!(ev["LumoConversations"].as_array().unwrap().len(), 2);
    assert_eq!(ev["LumoMessages"][0]["Action"], 1);
    assert!(ev["LumoAssets"].is_null());

    c.delete(&format!("lumo/v1/spaces/{space}"), None).await;
    let r = c
        .req("GET", &format!("lumo/v1/conversations/{conv}"), None)
        .await;
    assert_eq!(r.body["Code"], 2501);
    assert!(
        c.get("lumo/v1/spaces").await["Spaces"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

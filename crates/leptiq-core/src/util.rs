use axum::Json;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Proton-style opaque ID (64 random bytes, URL-safe base64; 86 chars).
pub fn new_id() -> String {
    let mut buf = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Random lowercase alphanumeric token (like Proton's 32-char session tokens).
pub fn new_token(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[(rng.next_u32() as usize) % ALPHABET.len()] as char)
        .collect()
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

pub fn sha256_hex(data: &str) -> String {
    hex::encode(Sha256::digest(data.as_bytes()))
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Builds a success response: the serialized object with `"Code": 1000` added.
pub fn ok<T: Serialize>(value: T) -> Json<Value> {
    let mut map = match serde_json::to_value(value) {
        Ok(Value::Object(map)) => map,
        Ok(Value::Null) => Map::new(),
        Ok(other) => {
            let mut m = Map::new();
            m.insert("Data".into(), other);
            m
        }
        Err(e) => {
            tracing::error!("serialization failure: {e}");
            Map::new()
        }
    };
    map.insert("Code".into(), Value::from(1000));
    Json(Value::Object(map))
}

/// `{"Code": 1000}`.
pub fn ok_empty() -> Json<Value> {
    ok(Value::Null)
}

/// Converts 0/1 integer columns to bool.
pub fn b(v: i64) -> bool {
    v != 0
}

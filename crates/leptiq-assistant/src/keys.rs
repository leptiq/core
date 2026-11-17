//! The server's OpenPGP key for "U2L" (user-to-Lumo) encryption.
//!
//! Each chat request carries a fresh AES-256-GCM key, OpenPGP-encrypted to
//! this server key. The client build embeds the public half (the
//! `LUMO_PUB_KEY_PATH` build option of the Lumo web app); `leptiq admin
//! assistant-key` and `GET /assistant/public-key` print it.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use leptiq_core::db::Pool;
use pgp::{
    composed::{
        ArmorOptions, Deserializable, EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder,
        SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::ecc_curve::ECCCurve,
};
use rand::RngCore;

const KV_KEY: &str = "assistant_server_key";

#[derive(Clone)]
pub struct ServerKey {
    pub secret: SignedSecretKey,
    pub public_armored: String,
}

fn generate() -> anyhow::Result<SignedSecretKey> {
    let mut enc = SubkeyParamsBuilder::default();
    enc.key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false);
    let mut params = SecretKeyParamsBuilder::default();
    params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("Leptiq Assistant <assistant@leptiq.invalid>".into())
        .subkeys(vec![enc.build()?]);
    Ok(params.build()?.generate(rand::thread_rng())?)
}

/// Loads the key from `path` (armored private key) if set, else from the
/// database, generating and storing one on first start.
pub async fn load(db: &Pool, path: Option<&str>) -> anyhow::Result<ServerKey> {
    let armored = match path.filter(|p| !p.is_empty()) {
        Some(p) => std::fs::read_to_string(p)?,
        None => {
            let row: Option<(String,)> = sqlx::query_as("SELECT v FROM kv WHERE k = $1")
                .bind(KV_KEY)
                .fetch_optional(db)
                .await?;
            match row {
                Some((v,)) => v,
                None => {
                    let key = generate()?;
                    let armored = key.to_armored_string(ArmorOptions::default())?;
                    sqlx::query("INSERT INTO kv (k, v) VALUES ($1, $2) ON CONFLICT (k) DO NOTHING")
                        .bind(KV_KEY)
                        .bind(&armored)
                        .execute(db)
                        .await?;
                    // Another instance may have stored one first.
                    let (v,): (String,) = sqlx::query_as("SELECT v FROM kv WHERE k = $1")
                        .bind(KV_KEY)
                        .fetch_one(db)
                        .await?;
                    v
                }
            }
        }
    };
    let (secret, _) = SignedSecretKey::from_string(&armored)?;
    let public_armored = secret
        .to_public_key()
        .to_armored_string(ArmorOptions::default())?;
    Ok(ServerKey {
        secret,
        public_armored,
    })
}

impl ServerKey {
    /// Unwraps the per-request AES key (`lumo.request_key`: base64 of a
    /// binary OpenPGP message containing the 32 raw key bytes).
    pub fn request_key(&self, request_key_b64: &str) -> anyhow::Result<[u8; 32]> {
        let bytes = STANDARD.decode(request_key_b64.trim())?;
        let mut msg = Message::from_bytes(&bytes[..])?.decrypt(&"".into(), &self.secret)?;
        if msg.is_compressed() {
            msg = msg.decompress()?;
        }
        let data = msg.as_data_vec()?;
        data.try_into()
            .map_err(|_| anyhow::anyhow!("request key must be 32 bytes"))
    }
}

pub fn request_ad(request_id: &str) -> String {
    format!("lumo.request.{request_id}.turn")
}

pub fn response_ad(request_id: &str) -> String {
    format!("lumo.response.{request_id}.chunk")
}

/// Decrypts `base64(iv(12) || ciphertext || tag)`.
pub fn decrypt(key: &[u8; 32], b64: &str, ad: &str) -> anyhow::Result<Vec<u8>> {
    let raw = STANDARD.decode(b64)?;
    anyhow::ensure!(raw.len() >= 12 + 16, "ciphertext too short");
    let (iv, ct) = raw.split_at(12);
    Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: ct,
                aad: ad.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("decryption failed"))
}

/// Encrypts to `base64(iv(12) || ciphertext || tag)` with a fresh IV.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], ad: &str) -> String {
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    let ct = Aes256Gcm::new(key.into())
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: plaintext,
                aad: ad.as_bytes(),
            },
        )
        .expect("AES-GCM encryption cannot fail for in-memory data");
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    STANDARD.encode(out)
}

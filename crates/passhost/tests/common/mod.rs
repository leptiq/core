//! Test harness: spawns the server in-process and provides a small client
//! that behaves like an official Proton client (real SRP, real PGP keys).
#![allow(dead_code)]

use base64::{Engine, engine::general_purpose::STANDARD};
use pgp::composed::{
    ArmorOptions, EncryptionCaps, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use proton_srp::{RPGPVerifier, SRPAuth, SrpHashVersion};
use serde_json::{Value, json};

use passhost::{AppState, config::Config, db};

pub struct TestServer {
    pub base: String,
    pub state: AppState,
    _dir: tempfile::TempDir,
}

pub async fn server() -> TestServer {
    server_with(|_| {}).await
}

pub async fn server_with(f: impl FnOnce(&mut Config)) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let mut config = Config::default();
    config.database_url = std::env::var("PASSHOST_TEST_DATABASE_URL")
        .unwrap_or_else(|_| format!("sqlite://{}/test.db?mode=rwc", dir.path().display()));
    config.data_dir = dir.path().join("data").display().to_string();
    config.mail_domain = "example.test".into();
    f(&mut config);
    let pool = db::connect(&config.database_url).await.unwrap();
    let state = AppState::new(config, pool).await.unwrap();
    let router = passhost::build_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    TestServer {
        base: format!("http://{addr}/api"),
        state,
        _dir: dir,
    }
}

pub fn unique(prefix: &str) -> String {
    format!("{prefix}{}", passhost::util::new_token(8))
}

#[derive(Clone)]
pub struct Client {
    pub base: String,
    pub http: reqwest::Client,
    pub uid: Option<String>,
    pub access: Option<String>,
    pub refresh: Option<String>,
    pub user_id: Option<String>,
    pub username: String,
    pub password: String,
    pub address_id: Option<String>,
    pub key_armored: Option<String>,
}

pub struct Resp {
    pub status: u16,
    pub body: Value,
}

impl Resp {
    pub fn ok(self) -> Value {
        assert_eq!(
            self.body["Code"], 1000,
            "unexpected response {}: {}",
            self.status, self.body
        );
        self.body
    }
}

impl Client {
    pub fn new(server: &TestServer) -> Self {
        Self {
            base: server.base.clone(),
            http: reqwest::Client::new(),
            uid: None,
            access: None,
            refresh: None,
            user_id: None,
            username: String::new(),
            password: String::new(),
            address_id: None,
            key_armored: None,
        }
    }

    pub async fn req(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        let url = format!("{}/{}", self.base, path.trim_start_matches('/'));
        let mut rb = self
            .http
            .request(method.parse().unwrap(), url)
            .header("x-pm-appversion", "web-pass@1.30.0");
        if let (Some(uid), Some(access)) = (&self.uid, &self.access) {
            rb = rb.header("x-pm-uid", uid).bearer_auth(access);
        }
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        let body = serde_json::from_str(&text).unwrap_or(Value::String(text));
        Resp { status, body }
    }

    pub async fn get(&self, path: &str) -> Value {
        self.req("GET", path, None).await.ok()
    }
    pub async fn post(&self, path: &str, body: Value) -> Value {
        self.req("POST", path, Some(body)).await.ok()
    }
    pub async fn put(&self, path: &str, body: Value) -> Value {
        self.req("PUT", path, Some(body)).await.ok()
    }
    pub async fn delete(&self, path: &str, body: Option<Value>) -> Value {
        self.req("DELETE", path, body).await.ok()
    }

    /// Signs up, logs in and sets up keys + address, like the account app.
    pub async fn signup(server: &TestServer, username: &str, password: &str) -> Self {
        let mut c = Self::new(server);
        c.username = username.into();
        c.password = password.into();
        let m = c.get("core/v4/auth/modulus").await;
        let verifier = SRPAuth::generate_verifier(
            &RPGPVerifier::default(),
            password,
            None,
            m["Modulus"].as_str().unwrap(),
        )
        .unwrap();
        let v: proton_srp::SRPVerifierB64 = verifier.into();
        c.post(
            "core/v4/users",
            json!({
                "Username": username, "Type": 1,
                "Auth": { "Version": 4, "ModulusID": m["ModulusID"], "Salt": v.salt, "Verifier": v.verifier }
            }),
        )
        .await;
        c.login().await;
        let addr = c
            .post(
                "core/v4/addresses/setup",
                json!({ "Domain": "example.test", "DisplayName": username }),
            )
            .await;
        let address_id = addr["Address"]["ID"].as_str().unwrap().to_string();
        let (user_key, _) = gen_key(username);
        let (addr_key, _) = gen_key(username);
        c.post(
            "core/v4/keys/setup",
            json!({
                "PrimaryKey": user_key,
                "KeySalt": STANDARD.encode([7u8; 16]),
                "AddressKeys": [{
                    "AddressID": address_id, "PrivateKey": addr_key, "Token": "tok", "Signature": "sig",
                    "SignedKeyList": { "Data": "[]", "Signature": "skl-sig" }
                }]
            }),
        )
        .await;
        c.address_id = Some(address_id);
        c.key_armored = Some(addr_key);
        c
    }

    pub async fn login(&mut self) -> Value {
        let info = self
            .post("core/v4/auth/info", json!({ "Username": self.username }))
            .await;
        let auth = SRPAuth::new(
            &RPGPVerifier::default(),
            None,
            &self.password,
            SrpHashVersion::V4,
            info["Salt"].as_str().unwrap(),
            info["Modulus"].as_str().unwrap(),
            info["ServerEphemeral"].as_str().unwrap(),
        )
        .unwrap();
        let proofs: proton_srp::SRPProofB64 = auth.generate_proofs().unwrap().into();
        let resp = self
            .req(
                "POST",
                "core/v4/auth",
                Some(json!({
                    "Username": self.username,
                    "ClientEphemeral": proofs.client_ephemeral,
                    "ClientProof": proofs.client_proof,
                    "SRPSession": info["SRPSession"],
                })),
            )
            .await
            .ok();
        assert!(
            proofs.compare_server_proof(resp["ServerProof"].as_str().unwrap()),
            "bad server proof"
        );
        self.uid = Some(resp["UID"].as_str().unwrap().into());
        self.access = Some(resp["AccessToken"].as_str().unwrap().into());
        self.refresh = Some(resp["RefreshToken"].as_str().unwrap().into());
        self.user_id = Some(resp["UserID"].as_str().unwrap().into());
        resp
    }

    /// Re-proves the password to obtain the `password` scope.
    pub async fn unlock(&self) {
        let info = self
            .post("core/v4/auth/info", json!({ "Username": self.username }))
            .await;
        let auth = SRPAuth::new(
            &RPGPVerifier::default(),
            None,
            &self.password,
            SrpHashVersion::V4,
            info["Salt"].as_str().unwrap(),
            info["Modulus"].as_str().unwrap(),
            info["ServerEphemeral"].as_str().unwrap(),
        )
        .unwrap();
        let proofs: proton_srp::SRPProofB64 = auth.generate_proofs().unwrap().into();
        self.put(
            "core/v4/users/unlock",
            json!({ "ClientEphemeral": proofs.client_ephemeral, "ClientProof": proofs.client_proof, "SRPSession": info["SRPSession"] }),
        )
        .await;
    }
}

/// Generates an armored OpenPGP private key (unlocked; the server never
/// decrypts keys so the passphrase does not matter for tests).
pub fn gen_key(name: &str) -> (String, String) {
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
        .primary_user_id(format!("{name} <{name}@example.test>"))
        .subkeys(vec![enc.build().unwrap()]);
    let key = params
        .build()
        .unwrap()
        .generate(rand::thread_rng())
        .unwrap();
    let public = key.to_public_key();
    (
        key.to_armored_string(ArmorOptions::default()).unwrap(),
        public.to_armored_string(ArmorOptions::default()).unwrap(),
    )
}

/// AES-256-GCM encryption the way Pass clients do it: base64(iv || ct || tag),
/// with a tag string as associated data.
pub fn aes_encrypt(key: &[u8; 32], plaintext: &[u8], ad: &str) -> String {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    let cipher = Aes256Gcm::new(key.into());
    let iv = passhost::util::random_bytes(12);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: plaintext,
                aad: ad.as_bytes(),
            },
        )
        .unwrap();
    STANDARD.encode([iv, ct].concat())
}

pub fn aes_decrypt(key: &[u8; 32], b64: &str, ad: &str) -> Vec<u8> {
    use aes_gcm::{
        Aes256Gcm, Nonce,
        aead::{Aead, KeyInit, Payload},
    };
    let data = STANDARD.decode(b64).unwrap();
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(
            Nonce::from_slice(&data[..12]),
            Payload {
                msg: &data[12..],
                aad: ad.as_bytes(),
            },
        )
        .unwrap()
}

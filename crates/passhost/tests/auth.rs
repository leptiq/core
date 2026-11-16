mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn ping_and_app_version() {
    let s = server().await;
    let c = Client::new(&s);
    c.get("tests/ping").await;
    let r = reqwest::Client::new()
        .get(format!("{}/core/v4/auth/modulus", s.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["Code"], 5001);
}

#[tokio::test]
async fn signup_login_refresh_and_user() {
    let s = server().await;
    let name = unique("alice");
    let mut c = Client::signup(&s, &name, "correct horse").await;

    let user = c.get("core/v4/users").await;
    assert_eq!(user["User"]["Name"], name.as_str());
    assert_eq!(user["User"]["Keys"].as_array().unwrap().len(), 1);
    let key_id = user["User"]["Keys"][0]["ID"].clone();

    let salts = c.get("core/v4/keys/salts").await;
    assert_eq!(salts["KeySalts"][0]["ID"], key_id);

    let addrs = c.get("core/v4/addresses").await;
    let addr = &addrs["Addresses"][0];
    assert_eq!(addr["Email"], format!("{name}@example.test"));
    assert_eq!(addr["Keys"].as_array().unwrap().len(), 1);
    assert!(
        addr["Keys"][0]["PublicKey"]
            .as_str()
            .unwrap()
            .contains("PUBLIC KEY")
    );

    // Public key lookup (used for Pass invites).
    let keys = c
        .get(&format!("core/v4/keys/all?Email={name}@example.test"))
        .await;
    assert_eq!(keys["Address"]["Keys"].as_array().unwrap().len(), 1);

    // Refresh rotates tokens; old access token stops working.
    let old_access = c.access.clone();
    let r = c
        .post(
            "auth/v4/refresh",
            json!({ "UID": c.uid, "RefreshToken": c.refresh, "ResponseType": "token", "GrantType": "refresh_token", "RedirectURI": "https://proton.me" }),
        )
        .await;
    c.access = Some(r["AccessToken"].as_str().unwrap().into());
    c.refresh = Some(r["RefreshToken"].as_str().unwrap().into());
    c.get("core/v4/users").await;
    let mut stale = c.clone();
    stale.access = old_access;
    assert_eq!(stale.req("GET", "core/v4/users", None).await.status, 401);

    // Events: latest, then a settings change appears.
    let latest = c.get("core/v4/events/latest").await["EventID"]
        .as_str()
        .unwrap()
        .to_string();
    c.put("core/v4/settings/locale", json!({ "Locale": "fr_FR" }))
        .await;
    let ev = c.get(&format!("core/v4/events/{latest}")).await;
    assert_eq!(ev["UserSettings"]["Locale"], "fr_FR");

    // Logout.
    c.delete("core/v4/auth", None).await;
    assert_eq!(c.req("GET", "core/v4/users", None).await.status, 401);
}

#[tokio::test]
async fn wrong_password_and_unknown_user() {
    let s = server().await;
    let name = unique("bob");
    let _ = Client::signup(&s, &name, "pw1").await;
    let mut c = Client::new(&s);
    c.username = name.clone();
    c.password = "wrong".into();
    let info = c
        .post("core/v4/auth/info", json!({ "Username": name }))
        .await;
    let auth = proton_srp::SRPAuth::new(
        &proton_srp::RPGPVerifier::default(),
        None,
        "wrong",
        proton_srp::SrpHashVersion::V4,
        info["Salt"].as_str().unwrap(),
        info["Modulus"].as_str().unwrap(),
        info["ServerEphemeral"].as_str().unwrap(),
    )
    .unwrap();
    let p: proton_srp::SRPProofB64 = auth.generate_proofs().unwrap().into();
    let r = c.req("POST", "core/v4/auth", Some(json!({"Username": name, "ClientEphemeral": p.client_ephemeral, "ClientProof": p.client_proof, "SRPSession": info["SRPSession"]}))).await;
    assert_eq!(r.body["Code"], 8002);
    // Unknown users still get an SRP challenge (no enumeration).
    c.post("core/v4/auth/info", json!({ "Username": "nobody-here" }))
        .await;
}

#[tokio::test]
async fn session_fork() {
    let s = server().await;
    let name = unique("carol");
    let parent = Client::signup(&s, &name, "pw").await;
    let secret = "0123abcd";
    let challenge = hex_sha256(secret);
    let sel = parent
        .post("auth/v4/sessions/forks", json!({ "Payload": "blob", "ChildClientID": "web-pass", "Independent": 0, "ForkChallenge": challenge }))
        .await["Selector"]
        .as_str()
        .unwrap()
        .to_string();
    let anon = Client::new(&s);
    let bad = anon
        .req("GET", &format!("auth/v4/sessions/forks/{sel}"), None)
        .await;
    assert_ne!(bad.body["Code"], 1000);
    let r = anon
        .http
        .get(format!("{}/auth/v4/sessions/forks/{sel}", s.base))
        .header("x-pm-appversion", "web-pass@1.0.0")
        .header("x-pm-fork-secret", secret)
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    assert_eq!(r["Code"], 1000, "{r}");
    assert_eq!(r["Payload"], "blob");
    let mut child = Client::new(&s);
    child.uid = Some(r["UID"].as_str().unwrap().into());
    child.access = Some(r["AccessToken"].as_str().unwrap().into());
    assert_eq!(
        child.get("core/v4/users").await["User"]["Name"],
        name.as_str()
    );
}

#[tokio::test]
async fn cookie_session() {
    let s = server().await;
    let name = unique("dave");
    let c = Client::signup(&s, &name, "pw").await;
    let http = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let r = http
        .post(format!("{}/core/v4/auth/cookies", s.base))
        .header("x-pm-appversion", "web-pass@1.0.0")
        .header("x-pm-uid", c.uid.clone().unwrap())
        .bearer_auth(c.access.clone().unwrap())
        .json(&json!({ "UID": c.uid, "RefreshToken": c.refresh, "ResponseType": "token", "GrantType": "refresh_token", "RedirectURI": "https://x", "State": "st", "Persistent": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = http
        .get(format!("{}/core/v4/users", s.base))
        .header("x-pm-appversion", "web-pass@1.0.0")
        .header("x-pm-uid", c.uid.clone().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = http
        .post(format!("{}/auth/refresh", s.base))
        .header("x-pm-appversion", "web-pass@1.0.0")
        .header("x-pm-uid", c.uid.clone().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

fn hex_sha256(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

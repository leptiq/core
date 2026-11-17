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

/// The account app logs in from an unauthenticated cookie session and keeps
/// using that session afterwards: `auth` must upgrade it in place (same UID)
/// and refresh its cookies. Signup also creates the first address, which the
/// account app expects before calling `keys/setup`.
#[tokio::test]
async fn web_login_upgrades_cookie_session() {
    use proton_srp::{RPGPVerifier, SRPAuth, SrpHashVersion};

    let s = server().await;
    let name = unique("erin");
    let c = Client::signup(&s, &name, "pw").await;
    let addresses = c.get("core/v4/addresses").await;
    assert!(
        addresses["Addresses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["Email"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{name}@"))),
        "signup should create <username>@<mail_domain>: {addresses}"
    );

    let http = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap();
    let call = |method: reqwest::Method, path: &str, uid: &str| {
        http.request(method, format!("{}/{path}", s.base))
            .header("x-pm-appversion", "web-account@5.0.0")
            .header("x-pm-uid", uid.to_string())
    };

    // Unauthenticated session, converted to cookies.
    let unauth: serde_json::Value = call(reqwest::Method::POST, "auth/v4/sessions", "")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let uid = unauth["UID"].as_str().unwrap().to_string();
    let r = call(reqwest::Method::POST, "core/v4/auth/cookies", &uid)
        .json(&json!({ "UID": uid, "RefreshToken": unauth["RefreshToken"], "State": "s", "Persistent": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // SRP login over the cookie session (no bearer token).
    let info: serde_json::Value = call(reqwest::Method::POST, "core/v4/auth/info", &uid)
        .json(&json!({ "Username": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let auth = SRPAuth::new(
        &RPGPVerifier::default(),
        None,
        "pw",
        SrpHashVersion::V4,
        info["Salt"].as_str().unwrap(),
        info["Modulus"].as_str().unwrap(),
        info["ServerEphemeral"].as_str().unwrap(),
    )
    .unwrap();
    let proofs: proton_srp::SRPProofB64 = auth.generate_proofs().unwrap().into();
    let r = call(reqwest::Method::POST, "core/v4/auth", &uid)
        .json(&json!({
            "Username": name,
            "ClientEphemeral": proofs.client_ephemeral,
            "ClientProof": proofs.client_proof,
            "SRPSession": info["SRPSession"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with(&format!("AUTH-{uid}="))),
        "login over a cookie session must refresh its cookies"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["UID"], uid, "the session must be upgraded in place");

    // The same cookie session is now logged in.
    let r = call(reqwest::Method::GET, "core/v4/users", &uid)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let user: serde_json::Value = r.json().await.unwrap();
    assert_eq!(user["User"]["Name"], name);
}

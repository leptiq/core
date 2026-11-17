mod common;

use common::*;
use proton_srp::{RPGPVerifier, SRPAuth, SrpHashVersion};
use serde_json::json;

#[tokio::test]
async fn totp_two_factor_login() {
    let s = server().await;
    let name = unique("tfa");
    let c = Client::signup(&s, &name, "pw").await;
    let secret = totp_rs::Secret::generate_secret().to_encoded().to_string();
    let totp = leptiq_core::auth::twofa::totp_for(&secret).unwrap();

    // Enabling 2FA needs the password scope.
    let denied = c.req("POST", "core/v4/settings/2fa/totp", Some(json!({ "TOTPSharedSecret": secret, "TOTPConfirmation": totp.generate_current().unwrap() }))).await;
    assert_eq!(denied.status, 403);
    c.unlock().await;
    c.post(
        "core/v4/settings/2fa/totp",
        json!({ "TOTPSharedSecret": secret, "TOTPConfirmation": totp.generate_current().unwrap() }),
    )
    .await;
    assert_eq!(
        c.get("core/v4/settings").await["UserSettings"]["2FA"]["Enabled"],
        1
    );

    // New login: session is limited until the 2FA code is provided.
    let mut c2 = Client::new(&s);
    c2.username = name.clone();
    c2.password = "pw".into();
    let auth = c2.login().await;
    assert_eq!(auth["2FA"]["Enabled"], 1);
    assert_eq!(auth["Scopes"], json!(["twofactor"]));
    assert_ne!(
        c2.req("GET", "core/v4/users", None).await.body["Code"],
        1000
    );
    let bad = c2
        .req(
            "POST",
            "core/v4/auth/2fa",
            Some(json!({ "TwoFactorCode": "000000" })),
        )
        .await;
    assert_ne!(bad.body["Code"], 1000);
    c2.post(
        "core/v4/auth/2fa",
        json!({ "TwoFactorCode": totp.generate_current().unwrap() }),
    )
    .await;
    c2.get("core/v4/users").await;

    // FIDO2 registration options are served in Proton's format.
    let opts = c2.get("core/v4/settings/2fa/register").await;
    assert!(opts["RegistrationOptions"]["publicKey"]["challenge"].is_array());
}

#[tokio::test]
async fn session_pin_lock() {
    let s = server().await;
    let c = Client::signup(&s, &unique("pin"), "pw").await;
    c.get("pass/v1/share").await;
    let lock = c
        .post(
            "pass/v1/user/session/lock",
            json!({ "LockCode": "1234-hash", "UnlockedSecs": 600 }),
        )
        .await;
    let token = lock["LockData"]["StorageToken"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        c.get("pass/v1/user/session/lock/check").await["LockInfo"]["Exists"],
        true
    );

    c.post("pass/v1/user/session/lock/force_lock", json!({}))
        .await;
    assert_eq!(
        c.req("GET", "pass/v1/share", None).await.body["Code"],
        300008
    );
    let wrong = c
        .req(
            "POST",
            "pass/v1/user/session/lock/unlock",
            Some(json!({ "LockCode": "nope" })),
        )
        .await;
    assert_ne!(wrong.body["Code"], 1000);
    let un = c
        .post(
            "pass/v1/user/session/lock/unlock",
            json!({ "LockCode": "1234-hash" }),
        )
        .await;
    assert_eq!(un["LockData"]["StorageToken"], token.as_str());
    c.get("pass/v1/share").await;

    // Three wrong attempts close the session.
    c.post("pass/v1/user/session/lock/force_lock", json!({}))
        .await;
    for _ in 0..3 {
        let _ = c
            .req(
                "POST",
                "pass/v1/user/session/lock/unlock",
                Some(json!({ "LockCode": "bad" })),
            )
            .await;
    }
    assert_eq!(c.req("GET", "core/v4/users", None).await.status, 401);
}

#[tokio::test]
async fn pass_extra_password() {
    let s = server().await;
    let name = unique("xpw");
    let c = Client::signup(&s, &name, "pw").await;
    let m = c.get("core/v4/auth/modulus").await;
    let v: proton_srp::SRPVerifierB64 = SRPAuth::generate_verifier(
        &RPGPVerifier::default(),
        "extra-secret",
        None,
        m["Modulus"].as_str().unwrap(),
    )
    .unwrap()
    .into();
    c.unlock().await;
    c.post(
        "pass/v1/user/srp",
        json!({ "SrpModulusID": m["ModulusID"], "SrpVerifier": v.verifier, "SrpSalt": v.salt }),
    )
    .await;
    assert_eq!(c.get("pass/v1/user/srp").await["HasSRP"], true);

    // A new session can't use Pass until it proves the extra password.
    let mut c2 = Client::new(&s);
    c2.username = name;
    c2.password = "pw".into();
    c2.login().await;
    assert_eq!(
        c2.req("GET", "pass/v1/share", None).await.body["Code"],
        9108
    );
    let info = c2.get("pass/v1/user/srp/info").await["SRPData"].clone();
    let auth = SRPAuth::new(
        &RPGPVerifier::default(),
        None,
        "extra-secret",
        SrpHashVersion::V4,
        info["SrpSalt"].as_str().unwrap(),
        info["Modulus"].as_str().unwrap(),
        info["ServerEphemeral"].as_str().unwrap(),
    )
    .unwrap();
    let p: proton_srp::SRPProofB64 = auth.generate_proofs().unwrap().into();
    let r = c2
        .post("pass/v1/user/srp/auth", json!({ "ClientEphemeral": p.client_ephemeral, "ClientProof": p.client_proof, "SrpSessionID": info["SrpSessionID"] }))
        .await;
    assert!(p.compare_server_proof(r["ServerProof"].as_str().unwrap()));
    c2.get("pass/v1/share").await;
}

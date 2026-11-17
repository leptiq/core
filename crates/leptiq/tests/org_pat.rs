mod common;

use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use serde_json::json;

#[tokio::test]
async fn organization_policies() {
    let s = server().await;
    // On a fresh instance the first user becomes admin.
    let admin = Client::signup(&s, &unique("adm"), "pw").await;
    let member = Client::signup(&s, &unique("mem"), "pw").await;
    let org = admin.get("pass/v1/organization").await;
    let can_update = org["Organization"]["CanUpdate"].as_bool().unwrap();
    let mem_org = member.get("pass/v1/organization").await;
    assert_eq!(mem_org["Organization"]["CanUpdate"], false);
    if can_update {
        let u = admin
            .put(
                "pass/v1/organization/settings",
                json!({ "ExportMode": 1, "ForceLockSeconds": 300 }),
            )
            .await;
        assert_eq!(u["Organization"]["Settings"]["ExportMode"], 1);
        assert_eq!(
            member.get("pass/v1/organization").await["Organization"]["Settings"]["ForceLockSeconds"],
            300
        );
        admin
            .put("pass/v1/organization/settings/password_policy", json!({ "RandomPasswordAllowed": true, "RandomPasswordMinLength": 20, "MemorablePasswordAllowed": false }))
            .await;
        let e = admin
            .post(
                "pass/v1/organization/urlpause",
                json!({ "Url": "bank.test", "Values": { "AutofillEnabled": false } }),
            )
            .await;
        assert_eq!(e["Entry"]["Url"], "bank.test");
    }
    let denied = member
        .req(
            "PUT",
            "pass/v1/organization/settings",
            Some(json!({ "ExportMode": 0 })),
        )
        .await;
    assert_eq!(denied.status, 403);
    member.post("pass/v1/organization/report/client_data", json!({ "ReusedPasswords": 1, "Inactive2FA": 0, "ExcludedItems": 0, "WeakPasswords": 2 })).await;
    assert_eq!(
        member.get("pass/v1/breach").await["Breaches"]["IsEligible"],
        false
    );
}

#[tokio::test]
async fn personal_access_token_flow() {
    let s = server().await;
    let owner = Client::signup(&s, &unique("own"), "pw").await;
    let v = owner.create_vault("CI secrets").await;
    let (item_id, item_key, _) = owner.create_item(&v, "deploy key").await;

    owner.unlock().await;
    let (user_key, _) = gen_key("pat");
    let (addr_key, _) = gen_key("pat");
    let pat = owner
        .post(
            "account/v4/personal-access-token",
            json!({ "Name": "ci", "UserKey": { "PrivateKey": user_key }, "AddressKey": { "PrivateKey": addr_key } }),
        )
        .await["PersonalAccessToken"]
        .clone();
    let token = pat["Token"].as_str().unwrap().to_string();
    let pat_id = pat["ID"].as_str().unwrap().to_string();
    assert!(token.starts_with("pst_"));
    assert_eq!(
        owner.get("account/v4/personal-access-token").await["Total"],
        1
    );

    // PAT login (the CLI sends `pst_...::<key>`; only the token part is checked).
    let anon = Client::new(&s);
    let sess = anon
        .post(
            "account/v4/personal-access-token/session",
            json!({ "Token": format!("{token}::a2V5") }),
        )
        .await["Session"]
        .clone();
    let mut pc = Client::new(&s);
    pc.uid = Some(sess["SessionUID"].as_str().unwrap().into());
    pc.access = Some(sess["AccessToken"].as_str().unwrap().into());
    assert_eq!(
        pc.get("pass/v1/share").await["Shares"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Grant read access to the vault.
    owner
        .post(
            &format!("pass/v1/personal-access-token/{pat_id}/access"),
            json!({ "ShareID": v.share_id, "TargetType": 1, "ShareRoleID": "3", "Keys": [{ "KeyRotation": 1, "Key": STANDARD.encode(v.key) }] }),
        )
        .await;
    let shares = pc.get("pass/v1/share").await;
    let pat_share = shares["Shares"][0]["ShareID"].as_str().unwrap().to_string();
    let item = pc
        .get(&format!("pass/v1/share/{pat_share}/item/{item_id}"))
        .await;
    assert_eq!(
        aes_decrypt(&v.key, item["Item"]["ItemKey"].as_str().unwrap(), "itemkey"),
        item_key
    );

    pc.post("pass/v1/pat/monitor", json!({ "Records": [{ "VaultID": v.vault_id, "ObjectID": item_id, "Action": 1, "Payload": "read" }] })).await;
    let log = owner.get(&format!("pass/v1/pat/monitor/{pat_id}")).await;
    assert_eq!(log["Actions"]["Records"].as_array().unwrap().len(), 1);

    // Revoke, then delete the token entirely.
    owner
        .delete(
            &format!(
                "pass/v1/personal-access-token/{pat_id}/access/{}",
                v.share_id
            ),
            None,
        )
        .await;
    assert_eq!(
        pc.get("pass/v1/share").await["Shares"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    owner
        .delete(&format!("account/v4/personal-access-token/{pat_id}"), None)
        .await;
    assert_eq!(pc.req("GET", "pass/v1/share", None).await.status, 401);
    assert_ne!(
        anon.req(
            "POST",
            "account/v4/personal-access-token/session",
            Some(json!({ "Token": token }))
        )
        .await
        .body["Code"],
        1000
    );
}

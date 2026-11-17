mod common;

use common::*;
use serde_json::{Value, json};

fn ids(page: &Value) -> Vec<String> {
    page["Entries"]["Entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["EntryID"].as_str().unwrap().to_string())
        .collect()
}

/// Keys, entry CRUD with revisions, ordering and pagination, the way the
/// official Proton Authenticator app syncs.
#[tokio::test]
async fn authenticator_sync() {
    let s = server().await;
    let c = Client::signup(&s, &unique("auth"), "pw").await;
    let other = Client::signup(&s, &unique("other"), "pw").await;

    // No keys yet; the client uploads one encrypted with its primary user key.
    let keys = c.get("authenticator/v1/key").await;
    assert_eq!(keys["Keys"]["Keys"].as_array().unwrap().len(), 0);
    let key = c
        .post(
            "authenticator/v1/key",
            json!({ "Key": "ZW5jcnlwdGVkLWtleQ==" }),
        )
        .await;
    let key_id = key["Key"]["KeyID"].as_str().unwrap().to_string();
    let user = c.get("core/v4/users").await;
    let primary_key = user["User"]["Keys"][0]["ID"].clone();
    assert_eq!(key["Key"]["UserKeyID"], primary_key);
    assert_eq!(
        c.get("authenticator/v1/key").await["Keys"]["Keys"][0]["KeyID"],
        key_id
    );

    // Bulk create keeps the given order.
    let entries: Vec<Value> = (0..3)
        .map(|i| json!({ "AuthenticatorKeyID": key_id, "Content": format!("c{i}"), "ContentFormatVersion": 1 }))
        .collect();
    let created = c
        .post("authenticator/v1/entry/bulk", json!({ "Entries": entries }))
        .await;
    let created: Vec<String> = created["Entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["EntryID"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids(&c.get("authenticator/v1/entry").await), created);

    // Another user's key cannot be used, and their entries are separate.
    let r = other
        .req(
            "POST",
            "authenticator/v1/entry",
            Some(
                json!({ "AuthenticatorKeyID": key_id, "Content": "x", "ContentFormatVersion": 1 }),
            ),
        )
        .await;
    assert_ne!(r.body["Code"], 1000);
    assert!(ids(&other.get("authenticator/v1/entry").await).is_empty());

    // Update needs the latest revision.
    let upd = |rev: i64| {
        json!({ "Entries": [{ "EntryID": created[0], "AuthenticatorKeyID": key_id,
                              "Content": "new", "ContentFormatVersion": 1, "LastRevision": rev }] })
    };
    let r = c.put("authenticator/v1/entry/bulk", upd(1)).await;
    assert_eq!(r["Entries"][0]["Revision"], 2);
    assert_eq!(r["Entries"][0]["Content"], "new");
    let stale = c
        .req("PUT", "authenticator/v1/entry/bulk", Some(upd(1)))
        .await;
    assert_eq!(stale.status, 409, "{}", stale.body);

    // Move the last entry to the top, then the first after the second.
    c.put(
        &format!("authenticator/v1/entry/{}/order", created[2]),
        json!({ "AfterID": null }),
    )
    .await;
    assert_eq!(
        ids(&c.get("authenticator/v1/entry").await),
        vec![created[2].clone(), created[0].clone(), created[1].clone()]
    );
    c.put(
        "authenticator/v1/entry/order",
        json!({ "StartingPosition": 0, "Entries": [created[0], created[1], created[2]] }),
    )
    .await;
    assert_eq!(ids(&c.get("authenticator/v1/entry").await), created);

    // Delete in bulk.
    c.delete(
        "authenticator/v1/entry/bulk",
        Some(json!({ "EntryIDs": [created[1]] })),
    )
    .await;
    assert_eq!(
        ids(&c.get("authenticator/v1/entry").await),
        vec![created[0].clone(), created[2].clone()]
    );

    // Pagination: 100 per page, `Since` = previous `LastID`, null at the end.
    let many: Vec<Value> = (0..150)
        .map(|i| json!({ "AuthenticatorKeyID": key_id, "Content": format!("m{i}"), "ContentFormatVersion": 1 }))
        .collect();
    c.post("authenticator/v1/entry/bulk", json!({ "Entries": many }))
        .await;
    let p1 = c.get("authenticator/v1/entry").await;
    assert_eq!(p1["Entries"]["Total"], 152);
    assert_eq!(ids(&p1).len(), 100);
    let last = p1["Entries"]["LastID"].as_str().unwrap().to_string();
    let p2 = c.get(&format!("authenticator/v1/entry?Since={last}")).await;
    assert_eq!(ids(&p2).len(), 52);
    assert!(p2["Entries"]["LastID"].is_null());

    // The server lists authenticator among its apps.
    let apps = c.get("core/v4/users/apps").await;
    assert!(
        apps["Apps"]
            .as_array()
            .unwrap()
            .contains(&json!("authenticator"))
    );
}

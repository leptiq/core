mod common;

use common::*;
use serde_json::json;

#[tokio::test]
async fn vault_and_item_lifecycle() {
    let s = server().await;
    let c = Client::signup(&s, &unique("pat"), "pw").await;

    let access = c.get("pass/v1/user/access").await;
    assert_eq!(access["Access"]["Plan"]["Type"], "plus");

    let v = c.create_vault("Personal").await;
    let shares = c.get("pass/v1/share").await;
    assert_eq!(shares["Shares"].as_array().unwrap().len(), 1);
    let sh = &shares["Shares"][0];
    assert_eq!(sh["Owner"], true);
    assert_eq!(sh["Primary"], true);
    assert_eq!(sh["TargetType"], 1);
    assert_eq!(
        String::from_utf8(aes_decrypt(
            &v.key,
            sh["Content"].as_str().unwrap(),
            "vaultcontent"
        ))
        .unwrap(),
        "Personal"
    );
    let keys = c.get(&format!("pass/v1/share/{}/key", v.share_id)).await;
    assert_eq!(keys["ShareKeys"]["Keys"][0]["KeyRotation"], 1);

    // Create & read an item, decrypting like a client would.
    let (item_id, item_key, item) = c.create_item(&v, "login: hunter2").await;
    assert_eq!(item["Revision"], 1);
    let got = c
        .get(&format!("pass/v1/share/{}/item/{item_id}", v.share_id))
        .await["Item"]
        .clone();
    let k = aes_decrypt(&v.key, got["ItemKey"].as_str().unwrap(), "itemkey");
    assert_eq!(k, item_key);
    let pt = aes_decrypt(&item_key, got["Content"].as_str().unwrap(), "itemcontent");
    assert_eq!(pt, b"login: hunter2");

    // Update, then a stale update conflicts.
    let upd = |rev: i64, text: &str| {
        json!({ "KeyRotation": 1, "LastRevision": rev, "ContentFormatVersion": 8,
                "Content": aes_encrypt(&item_key, text.as_bytes(), "itemcontent") })
    };
    let u = c
        .put(
            &format!("pass/v1/share/{}/item/{item_id}", v.share_id),
            upd(1, "v2"),
        )
        .await;
    assert_eq!(u["Item"]["Revision"], 2);
    let conflict = c
        .req(
            "PUT",
            &format!("pass/v1/share/{}/item/{item_id}", v.share_id),
            Some(upd(1, "v3")),
        )
        .await;
    assert_eq!(conflict.status, 409);

    let revs = c
        .get(&format!(
            "pass/v1/share/{}/item/{item_id}/revision",
            v.share_id
        ))
        .await;
    assert_eq!(
        revs["Revisions"]["RevisionsData"].as_array().unwrap().len(),
        2
    );
    assert_eq!(revs["Revisions"]["RevisionsData"][0]["Revision"], 2);

    // Pin / flags / last use.
    let p = c
        .post(
            &format!("pass/v1/share/{}/item/{item_id}/pin", v.share_id),
            json!({}),
        )
        .await;
    assert_eq!(p["Item"]["Pinned"], true);
    let f = c
        .put(
            &format!("pass/v1/share/{}/item/{item_id}/flags", v.share_id),
            json!({ "SkipHealthCheck": true }),
        )
        .await;
    assert_eq!(f["Item"]["Flags"], 1);
    c.put(
        &format!("pass/v1/share/{}/item/{item_id}/lastuse", v.share_id),
        json!({}),
    )
    .await;

    // Trash → delete.
    let t = c
        .post(
            &format!("pass/v1/share/{}/item/trash", v.share_id),
            json!({ "Items": [{ "ItemID": item_id, "Revision": 2 }] }),
        )
        .await;
    assert_eq!(t["Items"][0]["State"], 2);
    c.post(
        &format!("pass/v1/share/{}/item/untrash", v.share_id),
        json!({ "Items": [{ "ItemID": item_id, "Revision": 2 }] }),
    )
    .await;
    let bad = c
        .req(
            "DELETE",
            &format!("pass/v1/share/{}/item", v.share_id),
            Some(json!({ "Items": [{ "ItemID": item_id, "Revision": 2 }] })),
        )
        .await;
    assert_ne!(bad.body["Code"], 1000);
    c.delete(
        &format!("pass/v1/share/{}/item", v.share_id),
        Some(json!({ "Items": [{ "ItemID": item_id, "Revision": 2 }], "SkipTrash": true })),
    )
    .await;
    let gone = c
        .req(
            "GET",
            &format!("pass/v1/share/{}/item/{item_id}", v.share_id),
            None,
        )
        .await;
    assert_ne!(gone.body["Code"], 1000);
}

#[tokio::test]
async fn pagination_and_import() {
    let s = server().await;
    let c = Client::signup(&s, &unique("pag"), "pw").await;
    let v = c.create_vault("Bulk").await;
    let item_key = [9u8; 32];
    let items: Vec<_> = (0..25)
        .map(|i| {
            json!({ "Item": {
            "KeyRotation": 1, "ContentFormatVersion": 8,
            "Content": aes_encrypt(&item_key, format!("item {i}").as_bytes(), "itemcontent"),
            "ItemKey": aes_encrypt(&v.key, &item_key, "itemkey") }, "Trashed": i == 0 })
        })
        .collect();
    let r = c
        .post(
            &format!("pass/v1/share/{}/item/import/batch", v.share_id),
            json!({ "Items": items }),
        )
        .await;
    assert_eq!(
        r["Revisions"]["RevisionsData"].as_array().unwrap().len(),
        25
    );

    let mut seen = 0;
    let mut since = String::new();
    loop {
        let page = c
            .get(&format!(
                "pass/v1/share/{}/item?PageSize=10&Since={since}",
                v.share_id
            ))
            .await;
        seen += page["Items"]["RevisionsData"].as_array().unwrap().len();
        assert_eq!(page["Items"]["Total"], 25);
        match page["Items"]["LastToken"].as_str() {
            Some(t) => since = t.to_string(),
            None => break,
        }
    }
    assert_eq!(seen, 25);
}

#[tokio::test]
async fn sync_events_and_folders() {
    let s = server().await;
    let c = Client::signup(&s, &unique("syn"), "pw").await;
    let start = c.get("pass/v1/user/sync_event").await["EventID"]
        .as_str()
        .unwrap()
        .to_string();
    let v = c.create_vault("Work").await;
    let (item_id, item_key, _) = c.create_item(&v, "secret").await;

    let ev = c.get(&format!("pass/v1/user/sync_event/{start}")).await["Events"].clone();
    assert_eq!(ev["SharesCreated"][0]["ShareID"], v.share_id.as_str());
    assert_eq!(ev["ItemsUpdated"][0]["ItemID"], item_id.as_str());
    assert_eq!(ev["FullRefresh"], false);
    let next = ev["LastEventID"].as_str().unwrap().to_string();

    // Folder with the item moved into it.
    let folder_key = [3u8; 32];
    let f = c
        .post(
            &format!("pass/v1/share/{}/folder", v.share_id),
            json!({ "ContentFormatVersion": 1, "Content": aes_encrypt(&folder_key, b"Dev", "foldercontent"),
                    "KeyRotation": 1, "FolderKey": aes_encrypt(&v.key, &folder_key, "folderkey") }),
        )
        .await;
    let folder_id = f["Folder"]["FolderID"].as_str().unwrap().to_string();
    let moved = c
        .put(
            &format!("pass/v1/share/{}/item/folder", v.share_id),
            json!({ "FolderID": folder_id, "Items": [{ "ItemID": item_id, "ItemKeys": [{ "KeyRotation": 1, "Key": aes_encrypt(&folder_key, &item_key, "itemkey") }] }] }),
        )
        .await;
    assert_eq!(moved["Items"][0]["FolderID"], folder_id.as_str());
    let ev = c.get(&format!("pass/v1/user/sync_event/{next}")).await["Events"].clone();
    assert_eq!(ev["FoldersUpdated"][0]["FolderID"], folder_id.as_str());
    assert_eq!(ev["ItemsUpdated"][0]["ItemID"], item_id.as_str());

    // Legacy per-share events.
    let share_ev = c
        .get(&format!("pass/v1/share/{}/event/{next}", v.share_id))
        .await["Events"]
        .clone();
    assert_eq!(share_ev["UpdatedItems"][0]["ItemID"], item_id.as_str());

    // Deleting the folder deletes its content.
    c.delete(
        &format!("pass/v1/share/{}/folder", v.share_id),
        Some(json!({ "FolderIDs": [folder_id] })),
    )
    .await;
    let list = c.get(&format!("pass/v1/share/{}/item", v.share_id)).await;
    assert_eq!(list["Items"]["Total"], 0);

    // Unknown event IDs ask for a full refresh.
    let ev = c.get("pass/v1/user/sync_event/bogus").await;
    assert_eq!(ev["Events"]["FullRefresh"], true);
}

#[tokio::test]
async fn move_items_between_vaults_and_delete_vault() {
    let s = server().await;
    let c = Client::signup(&s, &unique("mov"), "pw").await;
    let a = c.create_vault("A").await;
    let b = c.create_vault("B").await;
    let (item_id, item_key, _) = c.create_item(&a, "x").await;
    let r = c
        .put(
            &format!("pass/v1/share/{}/item/share", a.share_id),
            json!({ "ShareID": b.share_id, "Items": [{ "ItemID": item_id, "ItemKeys": [{ "KeyRotation": 1, "Key": aes_encrypt(&b.key, &item_key, "itemkey") }] }] }),
        )
        .await;
    assert_eq!(r["Items"][0]["ItemID"], item_id.as_str());
    let in_b = c
        .get(&format!("pass/v1/share/{}/item/{item_id}", b.share_id))
        .await;
    assert_eq!(
        aes_decrypt(&b.key, in_b["Item"]["ItemKey"].as_str().unwrap(), "itemkey"),
        item_key
    );

    c.put(&format!("pass/v1/vault/{}/primary", b.share_id), json!({}))
        .await;
    let shares = c.get("pass/v1/share").await;
    let primary: Vec<_> = shares["Shares"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["Primary"] == true)
        .collect();
    assert_eq!(primary.len(), 1);
    assert_eq!(primary[0]["ShareID"], b.share_id.as_str());

    c.delete(&format!("pass/v1/vault/{}", a.share_id), None)
        .await;
    assert_eq!(
        c.get("pass/v1/share").await["Shares"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

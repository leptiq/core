mod common;

use common::*;
use serde_json::json;

async fn upload_chunk(c: &Client, file_id: &str, index: i64, data: Vec<u8>) -> u16 {
    let form = reqwest::multipart::Form::new()
        .text("ChunkIndex", index.to_string())
        .part(
            "ChunkData",
            reqwest::multipart::Part::bytes(data).file_name("blob"),
        );
    c.http
        .post(format!("{}/pass/v1/file/{file_id}/chunk", c.base))
        .header("x-pm-appversion", "web-pass@1.0.0")
        .header("x-pm-uid", c.uid.clone().unwrap())
        .bearer_auth(c.access.clone().unwrap())
        .multipart(form)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn attachment_lifecycle() {
    let s = server().await;
    let c = Client::signup(&s, &unique("fil"), "pw").await;
    let v = c.create_vault("Docs").await;
    let (item_id, item_key, _) = c.create_item(&v, "passport").await;

    let file_key = [5u8; 32];
    let f = c
        .post(
            "pass/v1/file",
            json!({ "Metadata": "enc-meta", "ChunkCount": 2, "EncryptionVersion": 2 }),
        )
        .await;
    let file_id = f["File"]["FileID"].as_str().unwrap().to_string();
    let chunk0 = aes_encrypt(&file_key, b"hello ", "filedata").into_bytes();
    let chunk1 = aes_encrypt(&file_key, b"world", "filedata").into_bytes();

    // Linking before the upload is complete fails.
    assert_eq!(upload_chunk(&c, &file_id, 0, chunk0.clone()).await, 200);
    let early = c
        .req("POST", &format!("pass/v1/share/{}/item/{item_id}/link_files", v.share_id),
            Some(json!({ "ItemRevision": 1, "FilesToAdd": [{ "FileID": file_id, "FileKey": "k" }], "FilesToRemove": [] })))
        .await;
    assert_ne!(early.body["Code"], 1000);
    assert_eq!(upload_chunk(&c, &file_id, 1, chunk1.clone()).await, 200);

    let wrapped_key = aes_encrypt(&item_key, &file_key, "filekey");
    let linked = c
        .post(
            &format!("pass/v1/share/{}/item/{item_id}/link_files", v.share_id),
            json!({ "ItemRevision": 1, "FilesToAdd": [{ "FileID": file_id, "FileKey": wrapped_key }], "FilesToRemove": [] }),
        )
        .await;
    assert_eq!(linked["Item"]["Revision"], 2);
    assert_eq!(linked["Item"]["Flags"].as_i64().unwrap() & 8, 8);

    let files = c
        .get(&format!(
            "pass/v1/share/{}/item/{item_id}/files",
            v.share_id
        ))
        .await;
    let file = &files["Files"]["Files"][0];
    assert_eq!(file["Chunks"].as_array().unwrap().len(), 2);
    assert_eq!(file["RevisionAdded"], 2);

    // Download and decrypt both chunks.
    let mut plain = vec![];
    for ch in file["Chunks"].as_array().unwrap() {
        let bytes = c
            .http
            .get(format!(
                "{}/pass/v1/share/{}/item/{item_id}/file/{file_id}/chunk/{}",
                c.base,
                v.share_id,
                ch["ChunkID"].as_str().unwrap()
            ))
            .header("x-pm-appversion", "web-pass@1.0.0")
            .header("x-pm-uid", c.uid.clone().unwrap())
            .bearer_auth(c.access.clone().unwrap())
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        plain.extend(aes_decrypt(
            &file_key,
            std::str::from_utf8(&bytes).unwrap(),
            "filedata",
        ));
    }
    assert_eq!(plain, b"hello world");

    let user = c.get("core/v4/users").await;
    assert_eq!(
        user["User"]["UsedSpace"].as_i64().unwrap(),
        (chunk0.len() + chunk1.len()) as i64
    );

    // Remove, then restore.
    let removed = c
        .post(
            &format!("pass/v1/share/{}/item/{item_id}/link_files", v.share_id),
            json!({ "ItemRevision": 2, "FilesToAdd": [], "FilesToRemove": [file_id] }),
        )
        .await;
    assert_eq!(removed["Item"]["Flags"].as_i64().unwrap() & 8, 0);
    assert_eq!(
        c.get(&format!(
            "pass/v1/share/{}/item/{item_id}/files",
            v.share_id
        ))
        .await["Files"]["Total"],
        0
    );
    assert_eq!(
        c.get(&format!(
            "pass/v1/share/{}/item/{item_id}/revisions/files",
            v.share_id
        ))
        .await["Files"]["Total"],
        1
    );
    let restored = c
        .post(
            &format!(
                "pass/v1/share/{}/item/{item_id}/file/{file_id}/restore",
                v.share_id
            ),
            json!({ "FileKey": wrapped_key, "ItemKeyRotation": 1 }),
        )
        .await;
    assert_eq!(
        restored["Result"]["File"]["RevisionRemoved"],
        serde_json::Value::Null
    );

    let usage = c.get(&format!("pass/v1/vault/usage/{}", v.share_id)).await;
    assert!(usage["VaultFileStorageInfo"]["TotalSize"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn quota_is_enforced() {
    let s = server_with(|c| c.storage_quota_bytes = 100).await;
    let c = Client::signup(&s, &unique("quo"), "pw").await;
    let f = c
        .post("pass/v1/file", json!({ "Metadata": "m", "ChunkCount": 1 }))
        .await;
    let file_id = f["File"]["FileID"].as_str().unwrap().to_string();
    assert_ne!(upload_chunk(&c, &file_id, 0, vec![0u8; 200]).await, 200);
    assert_eq!(upload_chunk(&c, &file_id, 0, vec![0u8; 50]).await, 200);
}

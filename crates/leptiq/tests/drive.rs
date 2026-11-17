mod common;

use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use serde_json::{Value, json};
use sha2::Digest;

async fn upload_block(s: &TestServer, url: &str, token: &str, bytes: Vec<u8>) -> u16 {
    // BareURLs are relative to the web app origin, whose /api is this server.
    let root = s.base.trim_end_matches("/api");
    let form = reqwest::multipart::Form::new().part(
        "Block",
        reqwest::multipart::Part::bytes(bytes).file_name("blob"),
    );
    reqwest::Client::new()
        .post(format!("{root}{url}"))
        .header("pm-storage-token", token)
        .multipart(form)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn download(s: &TestServer, url: &str, token: &str) -> Vec<u8> {
    let root = s.base.trim_end_matches("/api");
    reqwest::Client::new()
        .get(format!("{root}{url}"))
        .header("pm-storage-token", token)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec()
}

fn ids(v: &Value) -> Vec<String> {
    v["LinkIDs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

/// The Drive SDK's flow: first-run volume, folders, chunked upload through
/// storage URLs, commit, download, rename/move/trash/delete and events.
#[tokio::test]
async fn drive_flow() {
    let s = server().await;
    let c = Client::signup(&s, &unique("drv"), "pw").await;
    let addresses = c.get("core/v4/addresses").await;
    let address = &addresses["Addresses"][0];
    let address_id = address["ID"].as_str().unwrap();
    let address_key_id = address["Keys"][0]["ID"].as_str().unwrap();

    // No volume yet: 422/2501, then the client creates one.
    let r = c.req("GET", "drive/v2/shares/my-files", None).await;
    assert_eq!((r.status, r.body["Code"].clone()), (422, json!(2501)));
    let vol = c
        .post(
            "drive/volumes",
            json!({
                "AddressID": address_id, "AddressKeyID": address_key_id,
                "ShareKey": "sk", "SharePassphrase": "sp", "SharePassphraseSignature": "sps",
                "FolderName": "root-name", "FolderKey": "fk", "FolderPassphrase": "fp",
                "FolderPassphraseSignature": "fps", "FolderHashKey": "fhk",
            }),
        )
        .await;
    let volume_id = vol["Volume"]["ID"].as_str().unwrap().to_string();
    let root_id = vol["Volume"]["Share"]["LinkID"]
        .as_str()
        .unwrap()
        .to_string();
    let share_id = vol["Volume"]["Share"]["ShareID"]
        .as_str()
        .unwrap()
        .to_string();

    let mine = c.get("drive/v2/shares/my-files").await;
    assert_eq!(mine["Volume"]["VolumeID"], volume_id);
    assert_eq!(mine["Share"]["Key"], "sk");
    assert_eq!(mine["Link"]["Link"]["LinkID"], root_id);
    assert_eq!(mine["Link"]["Sharing"]["ShareID"], share_id);
    assert_eq!(mine["Link"]["Folder"]["NodeHashKey"], "fhk");
    assert_eq!(
        c.get(&format!("drive/shares/{share_id}")).await["LinkID"],
        root_id
    );

    // Photos volume is separate.
    let r = c.req("GET", "drive/v2/shares/photos", None).await;
    assert_eq!(r.body["Code"], 2501);
    c.post(
        "drive/photos/volumes",
        json!({
            "Share": { "AddressID": address_id, "AddressKeyID": address_key_id, "Key": "k", "Passphrase": "p", "PassphraseSignature": "s" },
            "Link": { "Name": "n", "NodeKey": "nk", "NodePassphrase": "np", "NodePassphraseSignature": "nps", "NodeHashKey": "nhk" },
        }),
    )
    .await;
    assert_eq!(c.get("drive/v2/shares/photos").await["Code"], 1000);

    let latest = c
        .get(&format!("drive/volumes/{volume_id}/events/latest"))
        .await["EventID"]
        .as_str()
        .unwrap()
        .to_string();

    // Folder, then a name conflict.
    let folder = |hash: &str| {
        json!({
            "ParentLinkID": root_id, "NodeKey": "k", "NodeHashKey": "hk", "NodePassphrase": "p",
            "NodePassphraseSignature": "ps", "SignatureEmail": address["Email"], "Name": "enc-name", "Hash": hash,
        })
    };
    let docs = c
        .post(
            &format!("drive/v2/volumes/{volume_id}/folders"),
            folder("h-docs"),
        )
        .await["Folder"]["ID"]
        .as_str()
        .unwrap()
        .to_string();
    let dup = c
        .req(
            "POST",
            &format!("drive/v2/volumes/{volume_id}/folders"),
            Some(folder("h-docs")),
        )
        .await;
    assert_eq!(dup.body["Code"], 2500, "{}", dup.body);
    assert_eq!(dup.body["Details"]["ConflictLinkID"], docs);

    // Upload a two-block file into the folder.
    let file = c
        .post(
            &format!("drive/v2/volumes/{volume_id}/files"),
            json!({
                "ParentLinkID": docs, "Name": "enc-file", "Hash": "h-file", "MIMEType": "text/plain",
                "ClientUID": "uid-1", "IntendedUploadSize": 10, "NodeKey": "k", "NodePassphrase": "p",
                "NodePassphraseSignature": "ps", "ContentKeyPacket": "ckp", "ContentKeyPacketSignature": "ckps",
                "SignatureAddress": address["Email"],
            }),
        )
        .await;
    let file_id = file["File"]["ID"].as_str().unwrap().to_string();
    let rev_id = file["File"]["RevisionID"].as_str().unwrap().to_string();
    // A draft is not listed yet.
    assert!(
        ids(&c
            .get(&format!(
                "drive/v2/volumes/{volume_id}/folders/{docs}/children"
            ))
            .await)
        .is_empty()
    );
    let ver = c
        .get(&format!(
            "drive/v2/volumes/{volume_id}/links/{file_id}/revisions/{rev_id}/verification"
        ))
        .await;
    assert_eq!(
        STANDARD
            .decode(ver["VerificationCode"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(ver["ContentKeyPacket"], "ckp");

    let links = c
        .post(
            "drive/blocks",
            json!({
                "AddressID": address_id, "VolumeID": volume_id, "LinkID": file_id, "RevisionID": rev_id,
                "BlockList": [
                    { "Index": 1, "EncSignature": "sig1", "Verifier": { "Token": "t" } },
                    { "Index": 2, "EncSignature": "sig2", "Verifier": { "Token": "t" } },
                ],
                "ThumbnailList": [{ "Type": 1 }],
            }),
        )
        .await;
    let blocks: Vec<Vec<u8>> = vec![vec![1u8; 5000], vec![2u8; 300]];
    for (i, b) in blocks.iter().enumerate() {
        let l = &links["UploadLinks"][i];
        let st = upload_block(
            &s,
            l["BareURL"].as_str().unwrap(),
            l["Token"].as_str().unwrap(),
            b.clone(),
        )
        .await;
        assert!(st < 400, "block upload failed: {st}");
    }
    let t = &links["ThumbnailLinks"][0];
    upload_block(
        &s,
        t["BareURL"].as_str().unwrap(),
        t["Token"].as_str().unwrap(),
        vec![9u8; 64],
    )
    .await;
    // A wrong token is rejected.
    assert!(upload_block(&s, "/api/drive/storage/nope", "nope", vec![0]).await >= 400);

    c.put(
        &format!("drive/v2/volumes/{volume_id}/files/{file_id}/revisions/{rev_id}"),
        json!({ "ManifestSignature": "ms", "SignatureAddress": address["Email"], "XAttr": "xa", "ChecksumVerified": true, "Photo": null }),
    )
    .await;
    assert_eq!(
        ids(&c
            .get(&format!(
                "drive/v2/volumes/{volume_id}/folders/{docs}/children"
            ))
            .await),
        vec![file_id.clone()]
    );
    let details = c
        .post(
            &format!("drive/v2/volumes/{volume_id}/links"),
            json!({ "LinkIDs": [file_id, "unknown"] }),
        )
        .await;
    assert_eq!(details["Links"].as_array().unwrap().len(), 1);
    let f = &details["Links"][0]["File"];
    assert_eq!(f["ActiveRevision"]["RevisionID"], rev_id);
    assert_eq!(f["TotalEncryptedSize"], 5000 + 300 + 64);
    assert_eq!(f["ActiveRevision"]["Thumbnails"][0]["Type"], 1);

    // Download: blocks paged from FromBlockIndex, bytes match their hashes.
    let rev = c
        .get(&format!("drive/v2/volumes/{volume_id}/files/{file_id}/revisions/{rev_id}?PageSize=1&FromBlockIndex=1"))
        .await;
    assert_eq!(rev["Revision"]["Blocks"].as_array().unwrap().len(), 1);
    let rev = c
        .get(&format!(
            "drive/v2/volumes/{volume_id}/files/{file_id}/revisions/{rev_id}?FromBlockIndex=1"
        ))
        .await;
    let got = rev["Revision"]["Blocks"].as_array().unwrap();
    assert_eq!(got.len(), 2);
    for (i, b) in got.iter().enumerate() {
        let bytes = download(
            &s,
            b["BareURL"].as_str().unwrap(),
            b["Token"].as_str().unwrap(),
        )
        .await;
        assert_eq!(bytes, blocks[i]);
        assert_eq!(b["Hash"], STANDARD.encode(sha2::Sha256::digest(&bytes)));
        assert_eq!(b["EncSignature"], format!("sig{}", i + 1));
    }
    let after = c
        .get(&format!(
            "drive/v2/volumes/{volume_id}/files/{file_id}/revisions/{rev_id}?FromBlockIndex=3"
        ))
        .await;
    assert!(after["Revision"]["Blocks"].as_array().unwrap().is_empty());
    let thumb_id = f["ActiveRevision"]["Thumbnails"][0]["ThumbnailID"].clone();
    let th = c
        .post(
            &format!("drive/volumes/{volume_id}/thumbnails"),
            json!({ "ThumbnailIDs": [thumb_id] }),
        )
        .await;
    let th = &th["Thumbnails"][0];
    assert_eq!(
        download(
            &s,
            th["BareURL"].as_str().unwrap(),
            th["Token"].as_str().unwrap()
        )
        .await,
        vec![9u8; 64]
    );

    // Rename needs the current OriginalHash; move to the root.
    let stale = c
        .req(
            "PUT",
            &format!("drive/v2/volumes/{volume_id}/links/{file_id}/rename"),
            Some(json!({ "Name": "n2", "Hash": "h-file2", "OriginalHash": "wrong" })),
        )
        .await;
    assert_eq!(stale.body["Code"], 2000);
    c.put(
        &format!("drive/v2/volumes/{volume_id}/links/{file_id}/rename"),
        json!({ "Name": "n2", "Hash": "h-file2", "OriginalHash": "h-file" }),
    )
    .await;
    c.put(
        &format!("drive/v2/volumes/{volume_id}/links/{file_id}/move"),
        json!({ "ParentLinkID": root_id, "NodePassphrase": "p2", "Name": "n3", "Hash": "h-file3", "OriginalHash": "h-file2", "ContentHash": null }),
    )
    .await;
    let root_kids = ids(&c
        .get(&format!(
            "drive/v2/volumes/{volume_id}/folders/{root_id}/children"
        ))
        .await);
    assert!(root_kids.contains(&file_id) && root_kids.contains(&docs));
    // A folder cannot move into itself.
    let r = c
        .req(
            "PUT",
            &format!("drive/v2/volumes/{volume_id}/links/{docs}/move"),
            Some(json!({ "ParentLinkID": docs, "NodePassphrase": "p", "Name": "n", "Hash": "x", "OriginalHash": "h-docs" })),
        )
        .await;
    assert_ne!(r.body["Code"], 1000);

    // Trash, list trash (paged until empty), restore, trash, delete.
    let r = c
        .req(
            "POST",
            &format!("drive/v2/volumes/{volume_id}/trash_multiple"),
            Some(json!({ "LinkIDs": [file_id] })),
        )
        .await;
    assert_eq!(r.body["Code"], 1001);
    assert_eq!(r.body["Responses"][0]["Response"]["Code"], 1000);
    let t0 = c
        .get(&format!("drive/volumes/{volume_id}/trash?Page=0"))
        .await;
    assert_eq!(t0["Trash"][0]["LinkIDs"], json!([file_id]));
    let t1 = c
        .get(&format!("drive/volumes/{volume_id}/trash?Page=1"))
        .await;
    assert!(t1["Trash"].as_array().unwrap().is_empty());
    c.req(
        "PUT",
        &format!("drive/v2/volumes/{volume_id}/trash/restore_multiple"),
        Some(json!({ "LinkIDs": [file_id] })),
    )
    .await;
    assert!(
        ids(&c
            .get(&format!(
                "drive/v2/volumes/{volume_id}/folders/{root_id}/children"
            ))
            .await)
        .contains(&file_id)
    );
    c.req(
        "POST",
        &format!("drive/v2/volumes/{volume_id}/trash_multiple"),
        Some(json!({ "LinkIDs": [file_id] })),
    )
    .await;
    let r = c
        .req(
            "POST",
            &format!("drive/v2/volumes/{volume_id}/trash/delete_multiple"),
            Some(json!({ "LinkIDs": [file_id] })),
        )
        .await;
    assert_eq!(
        r.body["Responses"][0]["Response"]["Code"], 1000,
        "{}",
        r.body
    );
    let d = c
        .post(
            &format!("drive/v2/volumes/{volume_id}/links"),
            json!({ "LinkIDs": [file_id] }),
        )
        .await;
    assert!(d["Links"].as_array().unwrap().is_empty());
    assert_eq!(
        c.get(&format!("drive/volumes/{volume_id}")).await["Volume"]["UsedSpace"],
        0
    );

    // Events since the start: folder created, file created, updates, delete.
    let ev = c
        .get(&format!("drive/v2/volumes/{volume_id}/events/{latest}"))
        .await;
    let types: Vec<i64> = ev["Events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["EventType"].as_i64().unwrap())
        .collect();
    assert_eq!(types.first(), Some(&1));
    assert_eq!(types.last(), Some(&0));
    let again = c
        .get(&format!(
            "drive/v2/volumes/{volume_id}/events/{}",
            ev["EventID"].as_str().unwrap()
        ))
        .await;
    assert!(again["Events"].as_array().unwrap().is_empty());

    // Another user cannot see the volume.
    let other = Client::signup(&s, &unique("drv2"), "pw").await;
    let r = other
        .req("GET", &format!("drive/volumes/{volume_id}"), None)
        .await;
    assert_ne!(r.body["Code"], 1000);

    // Settings round-trip.
    c.put("drive/me/settings", json!({ "Layout": 1 })).await;
    assert_eq!(
        c.get("drive/me/settings").await["UserSettings"]["Layout"],
        1
    );
}

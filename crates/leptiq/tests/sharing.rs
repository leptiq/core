mod common;

use base64::{Engine, engine::general_purpose::STANDARD};
use common::*;
use serde_json::json;

#[tokio::test]
async fn invite_accept_roles_rotation_and_leave() {
    let s = server().await;
    let alice = Client::signup(&s, &unique("alice"), "pw").await;
    let bob_name = unique("bob");
    let bob = Client::signup(&s, &bob_name, "pw").await;
    let v = alice.create_vault("Family").await;
    let (item_id, item_key, _) = alice.create_item(&v, "wifi password").await;

    // Alice invites Bob read-only (keys "encrypted to Bob's address key").
    alice
        .post(
            &format!("pass/v1/share/{}/invite", v.share_id),
            json!({ "Keys": [{ "KeyRotation": 1, "Key": STANDARD.encode(v.key) }], "Email": format!("{bob_name}@example.test"),
                    "TargetType": 1, "ShareRoleID": "3" }),
        )
        .await;
    let pending = alice
        .get(&format!("pass/v1/share/{}/invite", v.share_id))
        .await;
    assert_eq!(pending["Invites"].as_array().unwrap().len(), 1);
    let sh = alice.get(&format!("pass/v1/share/{}", v.share_id)).await;
    assert_eq!(sh["Share"]["PendingInvites"], 1);
    assert_eq!(sh["Share"]["Shared"], true);

    let invites = bob.get("pass/v1/invite").await;
    let inv = &invites["Invites"][0];
    assert_eq!(inv["VaultData"]["ItemCount"], 1);
    let token = inv["InviteToken"].as_str().unwrap().to_string();
    let accepted = bob
        .post(
            &format!("pass/v1/invite/{token}"),
            json!({ "Keys": [{ "KeyRotation": 1, "Key": STANDARD.encode(v.key) }] }),
        )
        .await;
    let bob_share = accepted["Share"]["ShareID"].as_str().unwrap().to_string();
    assert_eq!(accepted["Share"]["Owner"], false);

    // Bob reads the item with the vault key.
    let item = bob
        .get(&format!("pass/v1/share/{bob_share}/item/{item_id}"))
        .await;
    let k = aes_decrypt(&v.key, item["Item"]["ItemKey"].as_str().unwrap(), "itemkey");
    assert_eq!(k, item_key);

    // Read-only: cannot create.
    let denied = bob
        .req("POST", &format!("pass/v1/share/{bob_share}/item"), Some(json!({ "KeyRotation": 1, "ContentFormatVersion": 8, "Content": "x", "ItemKey": "y" })))
        .await;
    assert_eq!(denied.status, 403);

    // Members, then upgrade Bob to writer.
    let members = alice
        .get(&format!("pass/v1/share/{}/user", v.share_id))
        .await;
    assert_eq!(members["Shares"].as_array().unwrap().len(), 2);
    alice
        .put(
            &format!("pass/v1/share/{}/user/{bob_share}", v.share_id),
            json!({ "ShareRoleID": "2" }),
        )
        .await;
    let bv = Vault {
        share_id: bob_share.clone(),
        vault_id: v.vault_id.clone(),
        key: v.key,
    };
    bob.create_item(&bv, "bob's item").await;

    // Key rotation: Alice re-encrypts everything; Bob gets a pending key.
    let new_key = [42u8; 32];
    let all = alice
        .get(&format!("pass/v1/share/{}/item", v.share_id))
        .await;
    let item_keys: Vec<_> = all["Items"]["RevisionsData"]
        .as_array()
        .unwrap()
        .iter()
        .map(|it| {
            let ik = aes_decrypt(&v.key, it["ItemKey"].as_str().unwrap(), "itemkey");
            json!({ "ItemID": it["ItemID"], "ItemKey": aes_encrypt(&new_key, &ik, "itemkey") })
        })
        .collect();
    let r = alice
        .post(
            &format!("pass/v1/share/{}/key", v.share_id),
            json!({ "CurrentKeyRotation": 1, "VaultKey": STANDARD.encode(new_key), "ItemKeys": item_keys,
                    "VaultKeyForShares": [{ "ShareID": bob_share, "AddressID": bob.address_id, "EncryptedKeyForAddress": STANDARD.encode(new_key) }],
                    "ItemKeysForShares": [] }),
        )
        .await;
    assert_eq!(r["ShareKey"]["KeyRotation"], 2);
    let p = bob
        .get(&format!("pass/v1/share/{bob_share}/key/pending"))
        .await;
    assert_eq!(p["PendingShareKeys"]["Pending"][0]["KeyRotation"], 2);
    let promoted = bob
        .post(
            &format!("pass/v1/share/{bob_share}/key/pending"),
            json!({ "Keys": [{ "KeyRotation": 2, "EncryptedKey": STANDARD.encode(new_key) }] }),
        )
        .await;
    assert_eq!(promoted["ShareKeys"]["Total"], 2);
    let item = bob
        .get(&format!("pass/v1/share/{bob_share}/item/{item_id}"))
        .await;
    assert_eq!(item["Item"]["KeyRotation"], 2);
    assert_eq!(
        aes_decrypt(
            &new_key,
            item["Item"]["ItemKey"].as_str().unwrap(),
            "itemkey"
        ),
        item_key
    );

    // Bob leaves; Alice sees one member again.
    bob.delete(&format!("pass/v1/share/{bob_share}"), None)
        .await;
    let members = alice
        .get(&format!("pass/v1/share/{}/user", v.share_id))
        .await;
    assert_eq!(members["Shares"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn new_user_invite_flow() {
    let s = server().await;
    let alice = Client::signup(&s, &unique("alice"), "pw").await;
    let v = alice.create_vault("Team").await;
    let carol_name = unique("carol");
    let email = format!("{carol_name}@example.test");
    alice
        .post(
            &format!("pass/v1/share/{}/invite/new_user", v.share_id),
            json!({ "Email": email, "TargetType": 1, "Signature": "sig", "ShareRoleID": "2" }),
        )
        .await;
    let list = alice
        .get(&format!("pass/v1/share/{}/invite", v.share_id))
        .await;
    assert_eq!(list["NewUserInvites"][0]["State"], 1);
    let nui = list["NewUserInvites"][0]["NewUserInviteID"]
        .as_str()
        .unwrap()
        .to_string();

    let carol = Client::signup(&s, &carol_name, "pw").await;
    let list = alice
        .get(&format!("pass/v1/share/{}/invite", v.share_id))
        .await;
    assert_eq!(list["NewUserInvites"][0]["State"], 2);
    assert_eq!(
        alice.get("pass/v1/user/access").await["Access"]["WaitingNewUserInvites"],
        1
    );

    alice
        .post(
            &format!("pass/v1/share/{}/invite/new_user/{nui}/keys", v.share_id),
            json!({ "Keys": [{ "KeyRotation": 1, "Key": "k" }] }),
        )
        .await;
    let invites = carol.get("pass/v1/invite").await;
    assert_eq!(invites["Invites"][0]["FromNewUser"], true);
}

#[tokio::test]
async fn item_share_and_public_link() {
    let s = server().await;
    let alice = Client::signup(&s, &unique("alice"), "pw").await;
    let bob_name = unique("bob");
    let bob = Client::signup(&s, &bob_name, "pw").await;
    let v = alice.create_vault("Private").await;
    let (item_id, _, item) = alice.create_item(&v, "one item").await;
    let (_other, _, _) = alice.create_item(&v, "not shared").await;

    alice
        .post(
            &format!("pass/v1/share/{}/invite", v.share_id),
            json!({ "Keys": [{ "KeyRotation": 1, "Key": "itemkey-for-bob" }], "Email": format!("{bob_name}@example.test"),
                    "TargetType": 2, "ItemID": item_id, "ShareRoleID": "3" }),
        )
        .await;
    let token = bob.get("pass/v1/invite").await["Invites"][0]["InviteToken"]
        .as_str()
        .unwrap()
        .to_string();
    let share = bob
        .post(
            &format!("pass/v1/invite/{token}"),
            json!({ "Keys": [{ "KeyRotation": 1, "Key": "k" }] }),
        )
        .await;
    let bob_share = share["Share"]["ShareID"].as_str().unwrap().to_string();
    assert_eq!(share["Share"]["TargetType"], 2);
    let list = bob.get(&format!("pass/v1/share/{bob_share}/item")).await;
    assert_eq!(list["Items"]["RevisionsData"].as_array().unwrap().len(), 1);
    assert_eq!(
        list["Items"]["RevisionsData"][0]["ItemKey"],
        serde_json::Value::Null
    );
    let owner_view = alice
        .get(&format!("pass/v1/share/{}/item/{item_id}", v.share_id))
        .await;
    assert_eq!(owner_view["Item"]["ShareCount"], 1);

    // Public link.
    let link = alice
        .post(
            &format!("pass/v1/share/{}/item/{item_id}/public_link", v.share_id),
            json!({ "Revision": 1, "ExpirationTime": 3600, "MaxReadCount": 1, "EncryptedItemKey": "eik",
                    "EncryptedLinkKey": "elk", "LinkKeyShareKeyRotation": 1 }),
        )
        .await;
    let url = link["PublicLink"]["Url"].as_str().unwrap().to_string();
    let tok = url.rsplit('/').next().unwrap();
    let anon = Client::new(&s);
    let content = anon
        .get(&format!("pass/v1/public_link/content/{tok}"))
        .await;
    assert_eq!(content["PublicLinkContent"]["Contents"], item["Content"]);
    // Max reads reached.
    assert_ne!(
        anon.req("GET", &format!("pass/v1/public_link/content/{tok}"), None)
            .await
            .body["Code"],
        1000
    );
    assert_eq!(
        alice.get("pass/v1/public_link").await["PublicLinks"][0]["Active"],
        false
    );
}

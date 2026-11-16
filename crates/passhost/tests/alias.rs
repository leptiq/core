mod common;

use std::sync::{Arc, Mutex};

use common::*;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A fake outbound relay that records (rcpt, data) of every message.
async fn smtp_sink() -> (u16, Arc<Mutex<Vec<(String, String)>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let store = Arc::new(Mutex::new(vec![]));
    let st = store.clone();
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let st = st.clone();
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut r = BufReader::new(r);
                w.write_all(b"220 sink\r\n").await.unwrap();
                let mut rcpt = String::new();
                let mut line = String::new();
                loop {
                    line.clear();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let up = line.to_ascii_uppercase();
                    if up.starts_with("EHLO") {
                        w.write_all(b"250-sink\r\n250 8BITMIME\r\n").await.unwrap();
                    } else if up.starts_with("RCPT TO:") {
                        rcpt = line[8..]
                            .trim()
                            .trim_matches(|c| c == '<' || c == '>')
                            .to_string();
                        w.write_all(b"250 OK\r\n").await.unwrap();
                    } else if up.starts_with("DATA") {
                        w.write_all(b"354 go\r\n").await.unwrap();
                        let mut data = String::new();
                        loop {
                            line.clear();
                            r.read_line(&mut line).await.unwrap();
                            if line == ".\r\n" {
                                break;
                            }
                            data.push_str(&line);
                        }
                        st.lock().unwrap().push((rcpt.clone(), data));
                        w.write_all(b"250 OK\r\n").await.unwrap();
                    } else if up.starts_with("QUIT") {
                        w.write_all(b"221 bye\r\n").await.unwrap();
                        return;
                    } else {
                        w.write_all(b"250 OK\r\n").await.unwrap();
                    }
                }
            });
        }
    });
    (port, store)
}

async fn smtp_send(port: u16, from: &str, to: &str, body: &str) -> String {
    let sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (r, mut w) = sock.into_split();
    let mut r = BufReader::new(r);
    let mut line = String::new();
    let mut last = String::new();
    r.read_line(&mut line).await.unwrap();
    for cmd in [
        "HELO test".to_string(),
        format!("MAIL FROM:<{from}>"),
        format!("RCPT TO:<{to}>"),
        "DATA".into(),
    ] {
        w.write_all(format!("{cmd}\r\n").as_bytes()).await.unwrap();
        line.clear();
        r.read_line(&mut line).await.unwrap();
        last = line.clone();
        if !line.starts_with('2') && !line.starts_with('3') {
            return last;
        }
    }
    w.write_all(format!("{body}\r\n.\r\n").as_bytes())
        .await
        .unwrap();
    line.clear();
    r.read_line(&mut line).await.unwrap();
    last = line.clone();
    w.write_all(b"QUIT\r\n").await.unwrap();
    last
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn alias_api_and_forwarding() {
    let (sink_port, sink) = smtp_sink().await;
    let smtp_port = free_port();
    let s = server_with(|c| {
        c.alias.enabled = true;
        c.alias.domains = vec!["alias.test".into()];
        c.alias.smtp_listen = format!("127.0.0.1:{smtp_port}");
        c.smtp.host = "127.0.0.1".into();
        c.smtp.port = sink_port;
        c.smtp.security = "none".into();
    })
    .await;
    passhost::pass::alias::smtp::spawn(s.state.clone());
    let c = Client::signup(&s, &unique("ali"), "pw").await;
    let v = c.create_vault("Aliases").await;

    let opts = c
        .get(&format!("pass/v1/share/{}/alias/options", v.share_id))
        .await["Options"]
        .clone();
    assert_eq!(opts["CanCreateAlias"], true);
    let suffix = opts["Suffixes"][0].clone();
    let mailbox_id = opts["Mailboxes"][0]["ID"].as_i64().unwrap();
    let item_key = [1u8; 32];
    let item = json!({ "KeyRotation": 1, "ContentFormatVersion": 8,
        "Content": aes_encrypt(&item_key, b"alias item", "itemcontent"), "ItemKey": aes_encrypt(&v.key, &item_key, "itemkey") });

    // Tampered suffix signatures are rejected.
    let bad = c
        .req("POST", &format!("pass/v1/share/{}/alias/custom", v.share_id),
            Some(json!({ "Prefix": "shop", "SignedSuffix": "@evil.test.0000", "MailboxIDs": [mailbox_id], "Item": item })))
        .await;
    assert_ne!(bad.body["Code"], 1000);

    let created = c
        .post(
            &format!("pass/v1/share/{}/alias/custom", v.share_id),
            json!({ "Prefix": "shop", "SignedSuffix": suffix["SignedSuffix"], "MailboxIDs": [mailbox_id], "AliasName": "Shop", "Item": item }),
        )
        .await;
    let alias_email = created["Item"]["AliasEmail"].as_str().unwrap().to_string();
    assert!(alias_email.starts_with("shop.") && alias_email.ends_with("@alias.test"));
    assert_eq!(created["Item"]["AliasOwner"], true);
    let alias_item = created["Item"]["ItemID"].as_str().unwrap().to_string();

    let random = c
        .post(
            &format!("pass/v1/share/{}/alias/random", v.share_id),
            item.clone(),
        )
        .await;
    assert!(
        random["Item"]["AliasEmail"]
            .as_str()
            .unwrap()
            .ends_with("@alias.test")
    );
    assert_eq!(
        c.get("pass/v1/user/alias/count").await["AliasCount"]["Total"],
        2
    );

    // A second mailbox, verified with the code.
    let mb = c
        .post(
            "pass/v1/user/alias/mailbox",
            json!({ "Email": "second@inbox.test" }),
        )
        .await;
    let mb_id = mb["Mailbox"]["MailboxID"].as_i64().unwrap();
    assert_eq!(mb["Mailbox"]["Verified"], false);
    let (code,): (String,) =
        sqlx::query_as("SELECT verification_code FROM alias_mailboxes WHERE id = $1")
            .bind(mb_id)
            .fetch_one(&s.state.db)
            .await
            .unwrap();
    c.post(
        &format!("pass/v1/user/alias/mailbox/{mb_id}/verify"),
        json!({ "Code": code }),
    )
    .await;
    c.post(
        &format!("pass/v1/share/{}/alias/{alias_item}/mailbox", v.share_id),
        json!({ "MailboxIDs": [mailbox_id, mb_id] }),
    )
    .await;
    let details = c
        .get(&format!("pass/v1/share/{}/alias/{alias_item}", v.share_id))
        .await["Alias"]
        .clone();
    assert_eq!(details["Mailboxes"].as_array().unwrap().len(), 2);
    assert_eq!(details["Name"], "Shop");

    // Inbound mail is forwarded to both mailboxes through a reverse alias.
    let reply = smtp_send(
        smtp_port,
        "news@store.test",
        &alias_email,
        "From: Store <news@store.test>\r\nSubject: Hi\r\n\r\nSale!",
    )
    .await;
    assert!(reply.starts_with("250"), "{reply}");
    let delivered: Vec<_> = sink
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, d)| d.contains("Sale!"))
        .cloned()
        .collect();
    assert_eq!(delivered.len(), 2);
    assert!(
        sink.lock()
            .unwrap()
            .iter()
            .any(|(to, d)| to == "second@inbox.test" && d.contains("verification code"))
    );
    let contacts = c
        .get(&format!(
            "pass/v1/share/{}/alias/{alias_item}/contact",
            v.share_id
        ))
        .await;
    let reverse = contacts["Contacts"][0]["ReverseAlias"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(delivered[0].1.contains(&reverse));
    assert_eq!(contacts["Contacts"][0]["ForwardedEmails"], 1);

    // Reply from the mailbox via the reverse alias goes out as the alias.
    let reply = smtp_send(
        smtp_port,
        "second@inbox.test",
        &reverse,
        "From: me <second@inbox.test>\r\nSubject: Re: Hi\r\n\r\nThanks",
    )
    .await;
    assert!(reply.starts_with("250"), "{reply}");
    let delivered = sink.lock().unwrap().clone();
    let last = delivered.last().unwrap();
    assert_eq!(last.0, "news@store.test");
    assert!(last.1.contains(&format!("<{alias_email}>")));
    assert!(!last.1.contains("second@inbox.test"));

    // Unknown recipients are refused; disabled aliases drop mail.
    assert!(
        smtp_send(smtp_port, "x@y.test", "nobody@alias.test", "x")
            .await
            .starts_with("550")
    );
    let st = c
        .put(
            &format!("pass/v1/share/{}/alias/{alias_item}/status", v.share_id),
            json!({ "Enable": false }),
        )
        .await;
    assert_eq!(st["Item"]["Flags"].as_i64().unwrap() & 4, 4);
    let before = sink.lock().unwrap().len();
    smtp_send(
        smtp_port,
        "news@store.test",
        &alias_email,
        "Subject: again\r\n\r\nx",
    )
    .await;
    assert_eq!(sink.lock().unwrap().len(), before);

    // Note changes produce sync events.
    let ev = c.get("pass/v1/user/sync_event").await["EventID"]
        .as_str()
        .unwrap()
        .to_string();
    c.put(
        &format!("pass/v1/share/{}/alias/{alias_item}/note", v.share_id),
        json!({ "Note": "for shopping" }),
    )
    .await;
    let evs = c.get(&format!("pass/v1/user/sync_event/{ev}")).await;
    assert_eq!(
        evs["Events"]["AliasNoteChanged"][0]["ItemID"],
        alias_item.as_str()
    );
}

#[tokio::test]
async fn aliases_disabled_by_default() {
    let s = server().await;
    let c = Client::signup(&s, &unique("noa"), "pw").await;
    let v = c.create_vault("V").await;
    let opts = c
        .get(&format!("pass/v1/share/{}/alias/options", v.share_id))
        .await;
    assert_eq!(opts["Options"]["CanCreateAlias"], false);
}

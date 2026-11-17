//! Minimal inbound SMTP server for alias forwarding.
//!
//! Intended to sit behind a regular MTA (e.g. Postfix) that handles TLS,
//! spam filtering and relaying; it accepts mail for aliases and reverse
//! aliases only and forwards it through the configured outbound relay.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use super::{ensure_contact, mail};
use crate::{app::AppState, error::ApiResult, util::now};

pub const MAX_MESSAGE: usize = 25 * 1024 * 1024;

pub fn spawn(state: AppState) {
    let addr = state.ext::<crate::PassConfig>().alias.smtp_listen.clone();
    if addr.is_empty() || !state.ext::<crate::PassConfig>().alias.enabled {
        return;
    }
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("alias SMTP: cannot listen on {addr}: {e}");
                return;
            }
        };
        tracing::info!("alias SMTP listening on {addr}");
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                continue;
            };
            let st = state.clone();
            tokio::spawn(async move {
                if let Err(e) = session(st, sock).await {
                    tracing::debug!("smtp session ended: {e}");
                }
            });
        }
    });
}

/// Where a recipient address leads.
#[derive(Debug, PartialEq)]
pub enum Recipient {
    /// Mail to an alias, forwarded to its mailboxes.
    Alias(String),
    /// A reply through a reverse alias, sent to the contact.
    Reverse {
        contact_id: i64,
        alias: String,
        contact_email: String,
    },
}

pub async fn resolve(state: &AppState, rcpt: &str) -> ApiResult<Option<Recipient>> {
    let rcpt = rcpt.trim().to_lowercase();
    let alias: Option<(String,)> = sqlx::query_as("SELECT email FROM aliases WHERE email = $1")
        .bind(&rcpt)
        .fetch_optional(&state.db)
        .await?;
    if let Some((email,)) = alias {
        return Ok(Some(Recipient::Alias(email)));
    }
    let reverse: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT id, alias_email, email FROM alias_contacts WHERE reverse_alias = $1",
    )
    .bind(&rcpt)
    .fetch_optional(&state.db)
    .await?;
    if let Some((contact_id, alias, contact_email)) = reverse {
        return Ok(Some(Recipient::Reverse {
            contact_id,
            alias,
            contact_email,
        }));
    }
    // Catch-all on a verified custom domain: create the alias on the fly
    // (it shows up as a "missing alias" for the client to create an item).
    let domain = rcpt.rsplit('@').next().unwrap_or_default();
    let catch_all: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, user_id FROM custom_domains WHERE domain = $1 AND catch_all = 1 AND ownership_verified = 1",
    )
    .bind(domain)
    .fetch_optional(&state.db)
    .await?;
    if let Some((domain_id, user_id)) = catch_all {
        let mut tx = state.db.begin().await?;
        sqlx::query("INSERT INTO aliases (email, user_id, enabled, created) VALUES ($1,$2,1,$3)")
            .bind(&rcpt)
            .bind(&user_id)
            .bind(now())
            .execute(&mut *tx)
            .await?;
        let mut mailboxes: Vec<(i64,)> =
            sqlx::query_as("SELECT mailbox_id FROM custom_domain_mailboxes WHERE domain_id = $1")
                .bind(domain_id)
                .fetch_all(&mut *tx)
                .await?;
        if mailboxes.is_empty() {
            mailboxes.push((super::mailboxes::default_id_conn(&mut tx, &user_id).await?,));
        }
        for (m,) in mailboxes {
            sqlx::query(
                "INSERT INTO alias_mailbox_links (alias_email, mailbox_id) VALUES ($1, $2)",
            )
            .bind(&rcpt)
            .bind(m)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(Some(Recipient::Alias(rcpt)));
    }
    Ok(None)
}

/// Delivers one message to one resolved recipient.
pub async fn deliver(
    state: &AppState,
    mail_from: &str,
    rcpt: &Recipient,
    data: &[u8],
) -> ApiResult<()> {
    let (headers, _) = mail::split(data);
    match rcpt {
        Recipient::Alias(alias) => {
            let (enabled, alias_name): (i64, Option<String>) =
                sqlx::query_as("SELECT enabled, name FROM aliases WHERE email = $1")
                    .bind(alias)
                    .fetch_one(&state.db)
                    .await?;
            let _ = alias_name;
            let (sender_name, sender) = mail::header(&headers, "From")
                .map(mail::parse_address)
                .unwrap_or((None, mail_from.to_lowercase()));
            if enabled == 0 {
                sqlx::query("UPDATE aliases SET blocked = blocked + 1 WHERE email = $1")
                    .bind(alias)
                    .execute(&state.db)
                    .await?;
                return Ok(());
            }
            let mut tx = state.db.begin().await?;
            let contact_id =
                ensure_contact(&mut tx, alias, &sender, sender_name.as_deref()).await?;
            tx.commit().await?;
            let (reverse, blocked): (String, i64) =
                sqlx::query_as("SELECT reverse_alias, blocked FROM alias_contacts WHERE id = $1")
                    .bind(contact_id)
                    .fetch_one(&state.db)
                    .await?;
            if blocked != 0 {
                sqlx::query(
                    "UPDATE alias_contacts SET blocked_count = blocked_count + 1 WHERE id = $1",
                )
                .bind(contact_id)
                .execute(&state.db)
                .await?;
                sqlx::query("UPDATE aliases SET blocked = blocked + 1 WHERE email = $1")
                    .bind(alias)
                    .execute(&state.db)
                    .await?;
                return Ok(());
            }
            let label = match &sender_name {
                Some(n) => format!("{n} - {}", sender.replace('@', " at ")),
                None => sender.replace('@', " at "),
            };
            let rewritten = mail::rewrite(data, &mail::display(&label, &reverse), None);
            let mailboxes: Vec<(String,)> = sqlx::query_as(
                "SELECT m.email FROM alias_mailboxes m JOIN alias_mailbox_links l ON l.mailbox_id = m.id \
                 WHERE l.alias_email = $1 AND m.verified = 1",
            )
            .bind(alias)
            .fetch_all(&state.db)
            .await?;
            for (to,) in mailboxes {
                mail::send_raw(state, &reverse, &to, &rewritten).await;
            }
            sqlx::query("UPDATE aliases SET forwarded = forwarded + 1 WHERE email = $1")
                .bind(alias)
                .execute(&state.db)
                .await?;
            sqlx::query("UPDATE alias_contacts SET forwarded = forwarded + 1 WHERE id = $1")
                .bind(contact_id)
                .execute(&state.db)
                .await?;
        }
        Recipient::Reverse {
            contact_id,
            alias,
            contact_email,
        } => {
            // Only the alias's own mailboxes may reply through it.
            let allowed: Option<(i64,)> = sqlx::query_as(
                "SELECT m.id FROM alias_mailboxes m JOIN alias_mailbox_links l ON l.mailbox_id = m.id \
                 WHERE l.alias_email = $1 AND m.email = $2",
            )
            .bind(alias)
            .bind(mail_from.to_lowercase())
            .fetch_optional(&state.db)
            .await?;
            if allowed.is_none() {
                tracing::info!(
                    "rejecting reply via reverse alias from unauthorized sender {mail_from}"
                );
                return Ok(());
            }
            let (name,): (Option<String>,) =
                sqlx::query_as("SELECT name FROM aliases WHERE email = $1")
                    .bind(alias)
                    .fetch_one(&state.db)
                    .await?;
            let from = match name {
                Some(n) if !n.is_empty() => mail::display(&n, alias),
                _ => alias.clone(),
            };
            let rewritten = mail::rewrite(data, &from, None);
            mail::send_raw(state, alias, contact_email, &rewritten).await;
            sqlx::query("UPDATE aliases SET replied = replied + 1 WHERE email = $1")
                .bind(alias)
                .execute(&state.db)
                .await?;
            sqlx::query("UPDATE alias_contacts SET replied = replied + 1 WHERE id = $1")
                .bind(contact_id)
                .execute(&state.db)
                .await?;
        }
    }
    Ok(())
}

fn angle(arg: &str) -> String {
    let arg = arg.trim();
    let inner = match (arg.find('<'), arg.find('>')) {
        (Some(l), Some(r)) if l < r => &arg[l + 1..r],
        _ => arg.split_whitespace().next().unwrap_or(""),
    };
    inner.to_string()
}

async fn session(state: AppState, sock: TcpStream) -> std::io::Result<()> {
    let (r, mut w) = sock.into_split();
    let mut reader = BufReader::new(r);
    let host = state
        .ext::<crate::PassConfig>()
        .alias
        .domains
        .first()
        .cloned()
        .unwrap_or_else(|| "localhost".into());
    w.write_all(format!("220 {host} ESMTP passhost\r\n").as_bytes())
        .await?;
    let mut mail_from: Option<String> = None;
    let mut rcpts: Vec<Recipient> = vec![];
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        if line.len() > 2048 {
            w.write_all(b"500 Line too long\r\n").await?;
            continue;
        }
        let cmd = line.trim_end().to_string();
        let upper = cmd.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            w.write_all(
                format!("250-{host}\r\n250-SIZE {MAX_MESSAGE}\r\n250 8BITMIME\r\n").as_bytes(),
            )
            .await?;
        } else if upper.starts_with("HELO") {
            w.write_all(format!("250 {host}\r\n").as_bytes()).await?;
        } else if upper.starts_with("MAIL FROM:") {
            mail_from = Some(angle(&cmd[10..]));
            rcpts.clear();
            w.write_all(b"250 OK\r\n").await?;
        } else if upper.starts_with("RCPT TO:") {
            if mail_from.is_none() {
                w.write_all(b"503 MAIL first\r\n").await?;
                continue;
            }
            match resolve(&state, &angle(&cmd[8..])).await {
                Ok(Some(r)) if rcpts.len() < 50 => {
                    rcpts.push(r);
                    w.write_all(b"250 OK\r\n").await?;
                }
                Ok(Some(_)) => w.write_all(b"452 Too many recipients\r\n").await?,
                Ok(None) => w.write_all(b"550 No such user\r\n").await?,
                Err(_) => w.write_all(b"451 Temporary failure\r\n").await?,
            }
        } else if upper == "DATA" {
            if rcpts.is_empty() {
                w.write_all(b"503 RCPT first\r\n").await?;
                continue;
            }
            w.write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                .await?;
            let mut data = Vec::new();
            let mut too_big = false;
            loop {
                line.clear();
                if reader.read_line(&mut line).await? == 0 {
                    return Ok(());
                }
                if line == ".\r\n" || line == ".\n" {
                    break;
                }
                let content = line.strip_prefix('.').unwrap_or(&line);
                if data.len() + content.len() > MAX_MESSAGE {
                    too_big = true;
                } else {
                    data.extend_from_slice(content.as_bytes());
                }
            }
            if too_big {
                w.write_all(b"552 Message too large\r\n").await?;
            } else {
                let from = mail_from.clone().unwrap_or_default();
                let mut failed = false;
                for r in &rcpts {
                    if let Err(e) = deliver(&state, &from, r, &data).await {
                        tracing::warn!("alias delivery failed: {e:?}");
                        failed = true;
                    }
                }
                w.write_all(if failed {
                    b"451 Delivery failed\r\n"
                } else {
                    b"250 Queued\r\n"
                })
                .await?;
            }
            mail_from = None;
            rcpts.clear();
        } else if upper == "RSET" {
            mail_from = None;
            rcpts.clear();
            w.write_all(b"250 OK\r\n").await?;
        } else if upper == "NOOP" {
            w.write_all(b"250 OK\r\n").await?;
        } else if upper == "QUIT" {
            w.write_all(b"221 Bye\r\n").await?;
            return Ok(());
        } else {
            w.write_all(b"502 Command not implemented\r\n").await?;
        }
    }
}

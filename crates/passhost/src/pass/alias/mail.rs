//! Outbound mail (verification codes, forwarded alias mail) and the header
//! rewriting used when forwarding.

use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, address::Envelope,
    message::header::ContentType, transport::smtp::authentication::Credentials,
};

use crate::app::AppState;

fn transport(state: &AppState) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
    let c = &state.config.smtp;
    if c.host.is_empty() {
        return None;
    }
    let builder = match c.security.as_str() {
        "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&c.host).ok()?,
        "none" => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&c.host),
        _ => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&c.host).ok()?,
    };
    let builder = builder.port(c.port);
    let builder = if c.username.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(c.username.clone(), c.password.clone()))
    };
    Some(builder.build())
}

/// Sends a mailbox verification code (or logs it when no relay is configured).
pub async fn send_code(state: &AppState, to: &str, code: &str) {
    let Some(t) = transport(state) else {
        tracing::info!("verification code for {to}: {code} (no SMTP relay configured)");
        return;
    };
    let msg = Message::builder()
        .from(match state.config.smtp.from.parse() {
            Ok(f) => f,
            Err(_) => return,
        })
        .to(match to.parse() {
            Ok(t) => t,
            Err(_) => return,
        })
        .subject("Your mailbox verification code")
        .header(ContentType::TEXT_PLAIN)
        .body(format!(
            "Your verification code is: {code}\n\nIf you did not request this, ignore this email.\n"
        ));
    if let Ok(m) = msg
        && let Err(e) = t.send(m).await
    {
        tracing::warn!("failed to send verification code: {e}");
    }
}

/// Sends an already-built raw message.
pub async fn send_raw(state: &AppState, from: &str, to: &str, raw: &[u8]) -> bool {
    let Some(t) = transport(state) else {
        tracing::warn!("dropping forwarded mail to {to}: no SMTP relay configured");
        return false;
    };
    let (Ok(f), Ok(r)) = (from.parse::<Address>(), to.parse::<Address>()) else {
        return false;
    };
    let Ok(env) = Envelope::new(Some(f), vec![r]) else {
        return false;
    };
    match t.send_raw(&env, raw).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("forwarding to {to} failed: {e}");
            false
        }
    }
}

/// Splits a message into unfolded headers and the raw body.
pub fn split(raw: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
    let text = String::from_utf8_lossy(raw);
    let (head, body_start) = match text.find("\r\n\r\n") {
        Some(i) => (&text[..i], i + 4),
        None => match text.find("\n\n") {
            Some(i) => (&text[..i], i + 2),
            None => (&text[..], text.len()),
        },
    };
    let mut headers: Vec<(String, String)> = vec![];
    for line in head.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = headers.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    let body = raw
        .get(body_start.min(raw.len())..)
        .unwrap_or_default()
        .to_vec();
    (headers, body)
}

/// Extracts (display name, address) from a header value like `"Name" <a@b>`.
pub fn parse_address(value: &str) -> (Option<String>, String) {
    if let (Some(l), Some(r)) = (value.rfind('<'), value.rfind('>'))
        && l < r
    {
        let name = value[..l].trim().trim_matches('"').trim();
        return (
            (!name.is_empty()).then(|| name.to_string()),
            value[l + 1..r].trim().to_lowercase(),
        );
    }
    (None, value.trim().to_lowercase())
}

pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Rebuilds a message with a new From (and optional Reply-To), dropping
/// headers that would break or leak through forwarding.
pub fn rewrite(raw: &[u8], from: &str, reply_to: Option<&str>) -> Vec<u8> {
    const DROP: &[&str] = &[
        "from",
        "sender",
        "reply-to",
        "return-path",
        "dkim-signature",
        "arc-seal",
        "arc-message-signature",
        "arc-authentication-results",
        "authentication-results",
    ];
    let (headers, body) = split(raw);
    let mut out = String::new();
    for (k, v) in &headers {
        if DROP.contains(&k.to_ascii_lowercase().as_str()) {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("From: {from}\r\n"));
    if let Some(r) = reply_to {
        out.push_str(&format!("Reply-To: {r}\r\n"));
    }
    out.push_str("X-Passhost-Forwarded: yes\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    bytes
}

/// Quotes a display name for a header.
pub fn display(name: &str, email: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| *c != '"' && *c != '\r' && *c != '\n')
        .collect();
    format!("\"{clean}\" <{email}>")
}

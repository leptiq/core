//! Custom alias domains with DNS verification.

use axum::{
    Json,
    extract::{Path, State},
};
use hickory_resolver::TokioResolver;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    util::{new_token, now, ok, ok_empty},
};

pub const TXT_PREFIX: &str = "passhost-verification=";

async fn domain_json(state: &AppState, user_id: &str, id: i64) -> ApiResult<Value> {
    let row: Option<(i64, String, String, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT id, domain, verification_token, ownership_verified, mx_verified, dkim_verified, spf_verified, dmarc_verified, created \
         FROM custom_domains WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let (id, domain, token, own, mx, dkim, spf, dmarc, created) =
        row.ok_or_else(|| ApiError::not_found("Domain"))?;
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM aliases WHERE email LIKE $1")
        .bind(format!("%@{domain}"))
        .fetch_one(&state.db)
        .await?;
    Ok(json!({
        "ID": id, "Domain": domain, "VerificationRecord": format!("{TXT_PREFIX}{token}"),
        "OwnershipVerified": own != 0, "MxVerified": mx != 0, "DkimVerified": dkim != 0,
        "SpfVerified": spf != 0, "DmarcVerified": dmarc != 0, "AliasCount": count, "CreateTime": created,
    }))
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let ids: Vec<(i64,)> =
        sqlx::query_as("SELECT id FROM custom_domains WHERE user_id = $1 ORDER BY id")
            .bind(&user.user_id)
            .fetch_all(&state.db)
            .await?;
    let mut out = vec![];
    for (id,) in &ids {
        out.push(domain_json(&state, &user.user_id, *id).await?);
    }
    Ok(ok(
        json!({ "CustomDomains": { "Domains": out, "LastID": ids.last().map(|i| i.0), "Total": ids.len() } }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateReq {
    pub domain: String,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    super::require_enabled(&state)?;
    let domain = req.domain.trim().trim_end_matches('.').to_lowercase();
    if !domain.contains('.')
        || domain
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(ApiError::bad_request("Invalid domain"));
    }
    if state
        .config
        .alias
        .domains
        .iter()
        .any(|d| d.eq_ignore_ascii_case(&domain))
        || domain == state.config.mail_domain
    {
        return Err(ApiError::conflict("Domain is reserved"));
    }
    let mut tx = state.db.begin().await?;
    let dup: Option<(i64,)> = sqlx::query_as("SELECT id FROM custom_domains WHERE domain = $1")
        .bind(&domain)
        .fetch_optional(&mut *tx)
        .await?;
    if dup.is_some() {
        return Err(ApiError::conflict("Domain already registered"));
    }
    let id = crate::db::next_counter(&mut *tx, "custom_domains").await?;
    sqlx::query("INSERT INTO custom_domains (id, user_id, domain, verification_token, created) VALUES ($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(&user.user_id)
        .bind(&domain)
        .bind(new_token(32))
        .bind(now())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "CustomDomain": domain_json(&state, &user.user_id, id).await? }),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "CustomDomain": domain_json(&state, &user.user_id, id).await? }),
    ))
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    sqlx::query("DELETE FROM custom_domains WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

async fn txt(resolver: &TokioResolver, name: &str) -> Vec<String> {
    match resolver.txt_lookup(name).await {
        Ok(r) => r.iter().map(|t| t.to_string()).collect(),
        Err(_) => vec![],
    }
}

/// `POST user/alias/custom_domain/{id}`: re-check DNS records.
pub async fn verify(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT domain, verification_token FROM custom_domains WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let (domain, token) = row.ok_or_else(|| ApiError::not_found("Domain"))?;
    let resolver = TokioResolver::builder_tokio()
        .map_err(ApiError::internal)?
        .build();
    let root_txt = txt(&resolver, &format!("{domain}.")).await;
    let own = root_txt
        .iter()
        .any(|t| t.contains(&format!("{TXT_PREFIX}{token}")));
    let spf = root_txt.iter().any(|t| t.starts_with("v=spf1"));
    let dmarc = txt(&resolver, &format!("_dmarc.{domain}."))
        .await
        .iter()
        .any(|t| t.starts_with("v=DMARC1"));
    let mx_hosts: Vec<String> = match resolver.mx_lookup(format!("{domain}.")).await {
        Ok(r) => r
            .iter()
            .map(|m| {
                m.exchange()
                    .to_string()
                    .trim_end_matches('.')
                    .to_lowercase()
            })
            .collect(),
        Err(_) => vec![],
    };
    let expected = state.config.alias.mx_host.to_lowercase();
    let mx =
        !mx_hosts.is_empty() && (expected.is_empty() || mx_hosts.iter().any(|h| *h == expected));
    // Forwarded mail is not DKIM-signed by passhost, so DKIM is not required.
    let dkim = true;
    sqlx::query(
        "UPDATE custom_domains SET ownership_verified = $1, mx_verified = $2, spf_verified = $3, dkim_verified = $4, dmarc_verified = $5 \
         WHERE id = $6",
    )
    .bind(own as i64)
    .bind(mx as i64)
    .bind(spf as i64)
    .bind(dkim as i64)
    .bind(dmarc as i64)
    .bind(id)
    .execute(&state.db)
    .await?;
    let err = |ok: bool, msg: &str| {
        if ok {
            Vec::<String>::new()
        } else {
            vec![msg.to_string()]
        }
    };
    Ok(ok(json!({ "CustomDomainValidation": {
        "OwnershipVerified": own, "MxVerified": mx, "MxErrors": err(mx, "MX record not found"),
        "SpfVerified": spf, "SpfErrors": err(spf, "SPF record not found"),
        "DkimVerified": dkim, "DkimErrors": [],
        "DmarcVerified": dmarc, "DmarcErrors": err(dmarc, "DMARC record not found"),
        "VerificationErrors": err(own, &format!("TXT record {TXT_PREFIX}{token} not found")),
    }})))
}

async fn settings_json(state: &AppState, user_id: &str, id: i64) -> ApiResult<Value> {
    let row: Option<(i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT catch_all, random_prefix, default_display_name FROM custom_domains WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let (catch_all, random_prefix, name) = row.ok_or_else(|| ApiError::not_found("Domain"))?;
    let mailboxes: Vec<(i64, String)> = sqlx::query_as(
        "SELECT m.id, m.email FROM alias_mailboxes m JOIN custom_domain_mailboxes d ON d.mailbox_id = m.id WHERE d.domain_id = $1",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    let mailboxes: Vec<Value> = mailboxes
        .into_iter()
        .map(|(i, e)| json!({ "ID": i, "Email": e }))
        .collect();
    Ok(
        json!({ "ID": id, "CatchAll": catch_all != 0, "Mailboxes": mailboxes, "DefaultDisplayName": name,
               "RandomPrefixGeneration": random_prefix != 0 }),
    )
}

pub async fn get_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id, id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CatchAllReq {
    pub catch_all: bool,
}

pub async fn set_catch_all(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<CatchAllReq>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE custom_domains SET catch_all = $1 WHERE id = $2 AND user_id = $3")
        .bind(req.catch_all as i64)
        .bind(id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id, id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RandomPrefixReq {
    pub random_prefix_generation: bool,
}

pub async fn set_random_prefix(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<RandomPrefixReq>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE custom_domains SET random_prefix = $1 WHERE id = $2 AND user_id = $3")
        .bind(req.random_prefix_generation as i64)
        .bind(id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id, id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NameReq {
    pub name: Option<String>,
}

pub async fn set_name(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<NameReq>,
) -> ApiResult<Json<Value>> {
    sqlx::query(
        "UPDATE custom_domains SET default_display_name = $1 WHERE id = $2 AND user_id = $3",
    )
    .bind(&req.name)
    .bind(id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id, id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MailboxesReq {
    #[serde(rename = "MailboxIDs")]
    pub mailbox_ids: Vec<i64>,
}

pub async fn set_mailboxes(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<MailboxesReq>,
) -> ApiResult<Json<Value>> {
    let mut tx = state.db.begin().await?;
    let owned: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM custom_domains WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(&user.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    owned.ok_or_else(|| ApiError::not_found("Domain"))?;
    for m in &req.mailbox_ids {
        super::mailboxes::check_owned_verified(&mut tx, &user.user_id, *m).await?;
    }
    sqlx::query("DELETE FROM custom_domain_mailboxes WHERE domain_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    for m in &req.mailbox_ids {
        sqlx::query("INSERT INTO custom_domain_mailboxes (domain_id, mailbox_id) VALUES ($1, $2)")
            .bind(id)
            .bind(m)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id, id).await? }),
    ))
}

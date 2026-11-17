//! Email aliases: SimpleLogin-style forwarding addresses tied to alias items.

pub mod domains;
pub mod mail;
pub mod mailboxes;
pub mod smtp;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{
    items::{self, CreateReq, FLAG_ALIAS_DISABLED, NewItemOpts},
    shares::{self, Share},
};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    events::{self, kind},
    util::{new_token, now, ok, ok_empty},
};

/// Whether `email` is an alias owned by `user_id`.
pub async fn is_owner(conn: &mut AnyConnection, user_id: &str, email: &str) -> ApiResult<bool> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT email FROM aliases WHERE email = $1 AND user_id = $2")
            .bind(email.to_lowercase())
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(row.is_some())
}

pub fn require_enabled(state: &AppState) -> ApiResult<()> {
    if state.config.alias.enabled && !state.config.alias.domains.is_empty() {
        Ok(())
    } else {
        Err(ApiError::disabled("Aliases"))
    }
}

fn sign_suffix(state: &AppState, user_id: &str, suffix: &str) -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&state.secret).expect("hmac");
    mac.update(user_id.as_bytes());
    mac.update(b"|");
    mac.update(suffix.as_bytes());
    let sig = hex::encode(&mac.finalize().into_bytes()[..12]);
    format!("{suffix}.{sig}")
}

/// Verifies a signed suffix and returns the plain suffix.
fn verify_suffix(state: &AppState, user_id: &str, signed: &str) -> ApiResult<String> {
    let (suffix, _) = signed
        .rsplit_once('.')
        .ok_or_else(|| ApiError::bad_request("Invalid suffix"))?;
    if sign_suffix(state, user_id, suffix) == signed {
        Ok(suffix.to_string())
    } else {
        Err(ApiError::bad_request("Invalid suffix signature"))
    }
}

/// Domains the user can create aliases on: (domain, is_custom).
pub async fn user_domains(state: &AppState, user_id: &str) -> ApiResult<Vec<(String, bool)>> {
    let mut out: Vec<(String, bool)> = state
        .config
        .alias
        .domains
        .iter()
        .map(|d| (d.to_lowercase(), false))
        .collect();
    let custom: Vec<(String,)> =
        sqlx::query_as("SELECT domain FROM custom_domains WHERE user_id = $1 AND ownership_verified = 1 ORDER BY id")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    out.extend(custom.into_iter().map(|(d,)| (d, true)));
    Ok(out)
}

fn valid_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && prefix.len() <= 40
        && prefix.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-'
        })
        && !prefix.starts_with('.')
        && !prefix.ends_with('.')
}

pub async fn options(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    shares::load(&state, &user.user_id, &share_id).await?;
    let enabled = require_enabled(&state).is_ok();
    let mut suffixes = vec![];
    if enabled {
        for (domain, custom) in user_domains(&state, &user.user_id).await? {
            let suffix = if custom {
                format!("@{domain}")
            } else {
                format!(".{}@{domain}", new_token(4))
            };
            suffixes.push(json!({
                "Suffix": suffix, "SignedSuffix": sign_suffix(&state, &user.user_id, &suffix),
                "IsCustom": custom, "IsPremium": false, "Domain": domain,
            }));
        }
    }
    let mailboxes = mailboxes::verified(&state, &user.user_id).await?;
    let mailboxes: Vec<Value> = mailboxes
        .into_iter()
        .map(|(id, email)| json!({ "ID": id, "Email": email }))
        .collect();
    Ok(ok(
        json!({ "Options": { "Suffixes": suffixes, "Mailboxes": mailboxes, "CanCreateAlias": enabled } }),
    ))
}

async fn check_limit(conn: &mut AnyConnection, state: &AppState, user_id: &str) -> ApiResult<()> {
    if state.config.alias.max_aliases > 0 {
        let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM aliases WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await?;
        if n >= state.config.alias.max_aliases {
            return Err(ApiError::new(
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                crate::error::code::QUOTA_EXCEEDED,
                "Alias limit reached",
            ));
        }
    }
    Ok(())
}

/// Registers a new alias address and creates its item.
async fn create_alias(
    conn: &mut AnyConnection,
    state: &AppState,
    share: &Share,
    email: &str,
    mailbox_ids: &[i64],
    name: Option<&str>,
    item: &CreateReq,
) -> ApiResult<items::Item> {
    check_limit(conn, state, &share.user_id).await?;
    let email = email.to_lowercase();
    let taken: Option<(String,)> = sqlx::query_as("SELECT email FROM aliases WHERE email = $1")
        .bind(&email)
        .fetch_optional(&mut *conn)
        .await?;
    let addr_taken: Option<(String,)> = sqlx::query_as("SELECT id FROM addresses WHERE email = $1")
        .bind(&email)
        .fetch_optional(&mut *conn)
        .await?;
    if taken.is_some() || addr_taken.is_some() {
        return Err(ApiError::conflict("Alias already exists"));
    }
    let mailbox_ids = if mailbox_ids.is_empty() {
        vec![mailboxes::default_id_conn(conn, &share.user_id).await?]
    } else {
        mailbox_ids.to_vec()
    };
    for m in &mailbox_ids {
        mailboxes::check_owned_verified(conn, &share.user_id, *m).await?;
    }
    let opts = NewItemOpts {
        alias_email: Some(email.clone()),
        ..Default::default()
    };
    let created = items::insert_item(conn, share, item, opts).await?;
    sqlx::query("INSERT INTO aliases (email, user_id, item_id, enabled, name, created) VALUES ($1,$2,$3,1,$4,$5)")
        .bind(&email)
        .bind(&share.user_id)
        .bind(&created.id)
        .bind(name)
        .bind(now())
        .execute(&mut *conn)
        .await?;
    for m in mailbox_ids {
        sqlx::query("INSERT INTO alias_mailbox_links (alias_email, mailbox_id) VALUES ($1, $2)")
            .bind(&email)
            .bind(m)
            .execute(&mut *conn)
            .await?;
    }
    Ok(created)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CustomReq {
    pub prefix: String,
    pub signed_suffix: String,
    #[serde(rename = "MailboxIDs", default)]
    pub mailbox_ids: Vec<i64>,
    pub alias_name: Option<String>,
    pub item: CreateReq,
}

async fn custom_email(
    state: &AppState,
    user_id: &str,
    prefix: &str,
    signed_suffix: &str,
) -> ApiResult<String> {
    let prefix = prefix.trim().to_lowercase();
    if !valid_prefix(&prefix) {
        return Err(ApiError::bad_request("Invalid alias prefix"));
    }
    let suffix = verify_suffix(state, user_id, signed_suffix)?;
    let domain = suffix.rsplit('@').next().unwrap_or_default().to_string();
    if !user_domains(state, user_id)
        .await?
        .iter()
        .any(|(d, _)| *d == domain)
    {
        return Err(ApiError::bad_request("Domain not available"));
    }
    Ok(format!("{prefix}{suffix}"))
}

pub async fn create_custom(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<CustomReq>,
) -> ApiResult<Json<Value>> {
    require_enabled(&state)?;
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let email = custom_email(&state, &user.user_id, &req.prefix, &req.signed_suffix).await?;
    let mut tx = state.db.begin().await?;
    let item = create_alias(
        &mut tx,
        &state,
        &share,
        &email,
        &req.mailbox_ids,
        req.alias_name.as_deref(),
        &req.item,
    )
    .await?;
    let out = items::item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

pub async fn create_random(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<CreateReq>,
) -> ApiResult<Json<Value>> {
    require_enabled(&state)?;
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let domain = settings_domain(&state, &user.user_id).await?;
    let email = format!("{}.{}@{domain}", random_word(), new_token(6));
    let mut tx = state.db.begin().await?;
    let item = create_alias(&mut tx, &state, &share, &email, &[], None, &req).await?;
    let out = items::item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

fn random_word() -> &'static str {
    const WORDS: &[&str] = &[
        "amber", "breeze", "cedar", "delta", "ember", "fjord", "grove", "harbor", "iris",
        "juniper", "koala", "lumen", "maple", "nova", "orbit", "pebble", "quartz", "river",
        "sable", "tundra", "umber", "violet", "willow", "zephyr",
    ];
    WORDS[(rand::random::<u32>() as usize) % WORDS.len()]
}

async fn settings_domain(state: &AppState, user_id: &str) -> ApiResult<String> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT default_domain FROM alias_settings WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    let domains = user_domains(state, user_id).await?;
    if let Some(d) = row.and_then(|r| r.0)
        && domains.iter().any(|(x, _)| *x == d)
    {
        return Ok(d);
    }
    domains
        .first()
        .map(|d| d.0.clone())
        .ok_or_else(|| ApiError::disabled("Aliases"))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WithAliasReq {
    pub alias: CustomReq,
    pub item: CreateReq,
}

/// `POST share/{}/item/with_alias`: a login item plus a new alias in one go.
pub async fn create_with_item(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<WithAliasReq>,
) -> ApiResult<Json<Value>> {
    require_enabled(&state)?;
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let email = custom_email(
        &state,
        &user.user_id,
        &req.alias.prefix,
        &req.alias.signed_suffix,
    )
    .await?;
    let mut tx = state.db.begin().await?;
    let alias = create_alias(
        &mut tx,
        &state,
        &share,
        &email,
        &req.alias.mailbox_ids,
        req.alias.alias_name.as_deref(),
        &req.alias.item,
    )
    .await?;
    let item = items::insert_item(&mut tx, &share, &req.item, NewItemOpts::default()).await?;
    let alias_out = items::item_json(&mut tx, &share, &alias).await?;
    let item_out = items::item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "Bundle": { "Alias": alias_out, "Item": item_out } }),
    ))
}

/// Loads the alias behind an item the user can see.
async fn alias_for_item(
    state: &AppState,
    user: &AuthUser,
    share_id: &str,
    item_id: &str,
) -> ApiResult<(Share, items::Item, String)> {
    let share = shares::load(state, &user.user_id, share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = items::load(&mut conn, &share, item_id).await?;
    let email = item
        .alias_email
        .clone()
        .ok_or_else(|| ApiError::not_found("Alias"))?;
    Ok((share, item, email))
}

async fn details_json(state: &AppState, user_id: &str, email: &str) -> ApiResult<Value> {
    let row: Option<(String, Option<String>, Option<String>, i64, i64, i64)> = sqlx::query_as(
        "SELECT user_id, name, note, forwarded, replied, blocked FROM aliases WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await?;
    let Some((owner, name, note, fwd, rep, blk)) = row else {
        return Err(ApiError::not_found("Alias"));
    };
    let modify = owner == user_id;
    let linked: Vec<(i64, String)> = sqlx::query_as(
        "SELECT m.id, m.email FROM alias_mailboxes m JOIN alias_mailbox_links l ON l.mailbox_id = m.id \
         WHERE l.alias_email = $1 ORDER BY m.id",
    )
    .bind(email)
    .fetch_all(&state.db)
    .await?;
    let available = if modify {
        mailboxes::verified(state, user_id).await?
    } else {
        vec![]
    };
    let (contacts,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM alias_contacts WHERE alias_email = $1")
            .bind(email)
            .fetch_one(&state.db)
            .await?;
    let mb = |v: Vec<(i64, String)>| -> Vec<Value> {
        v.into_iter()
            .map(|(id, e)| json!({ "ID": id, "Email": e }))
            .collect()
    };
    Ok(json!({
        "Email": email,
        "Modify": modify,
        "Mailboxes": mb(linked),
        "AvailableMailboxes": mb(available),
        "Note": note,
        "Name": name,
        "DisplayName": name.clone().unwrap_or_default(),
        "Stats": { "ForwardedEmails": fwd, "RepliedEmails": rep, "BlockedEmails": blk },
        "ContactCount": contacts,
    }))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    Ok(ok(
        json!({ "Alias": details_json(&state, &user.user_id, &email).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BulkReq {
    #[serde(rename = "ItemIDs")]
    pub item_ids: Vec<String>,
}

pub async fn bulk_get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
    Json(req): Json<BulkReq>,
) -> ApiResult<Json<Value>> {
    let mut out = vec![];
    for id in req.item_ids.iter().take(100) {
        if let Ok((_, _, email)) = alias_for_item(&state, &user, &share_id, id).await {
            out.push(details_json(&state, &user.user_id, &email).await?);
        }
    }
    Ok(ok(json!({ "Aliases": out })))
}

async fn require_owner(state: &AppState, user_id: &str, email: &str) -> ApiResult<()> {
    let mut conn = state.db.acquire().await?;
    if is_owner(&mut conn, user_id, email).await? {
        Ok(())
    } else {
        Err(ApiError::forbidden("Not your alias"))
    }
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
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<MailboxesReq>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    if req.mailbox_ids.is_empty() {
        return Err(ApiError::bad_request("At least one mailbox is required"));
    }
    let mut tx = state.db.begin().await?;
    for m in &req.mailbox_ids {
        mailboxes::check_owned_verified(&mut tx, &user.user_id, *m).await?;
    }
    sqlx::query("DELETE FROM alias_mailbox_links WHERE alias_email = $1")
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    for m in &req.mailbox_ids {
        sqlx::query("INSERT INTO alias_mailbox_links (alias_email, mailbox_id) VALUES ($1, $2)")
            .bind(&email)
            .bind(m)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(ok(
        json!({ "Item": details_json(&state, &user.user_id, &email).await? }),
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
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<NameReq>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    sqlx::query("UPDATE aliases SET name = $1 WHERE email = $2")
        .bind(&req.name)
        .bind(&email)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NoteReq {
    pub note: Option<String>,
}

pub async fn set_note(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<NoteReq>,
) -> ApiResult<Json<Value>> {
    let (_, item, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE aliases SET note = $1 WHERE email = $2")
        .bind(&req.note)
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ALIAS_NOTE).await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StatusReq {
    pub enable: bool,
}

pub async fn set_status(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<StatusReq>,
) -> ApiResult<Json<Value>> {
    let (share, item, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE aliases SET enabled = $1 WHERE email = $2")
        .bind(req.enable as i64)
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    let flags = if req.enable {
        item.flags & !FLAG_ALIAS_DISABLED
    } else {
        item.flags | FLAG_ALIAS_DISABLED
    };
    sqlx::query("UPDATE items SET flags = $1 WHERE id = $2")
        .bind(flags)
        .bind(&item.id)
        .execute(&mut *tx)
        .await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let item = items::load(&mut tx, &share, &item.id).await?;
    let out = items::item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

// ---- Contacts (reverse aliases) ----

fn contact_json(row: &(i64, Option<String>, i64, String, String, i64, i64, i64, i64)) -> Value {
    let (id, name, blocked, reverse, email, created, fwd, rep, blk) = row;
    json!({
        "ID": id, "Name": name, "Blocked": *blocked != 0, "ReverseAlias": reverse, "Email": email,
        "CreateTime": created, "ForwardedEmails": fwd, "RepliedEmails": rep, "BlockedEmails": blk,
    })
}

const CONTACT_COLS: &str =
    "id, name, blocked, reverse_alias, email, created, forwarded, replied, blocked_count";

/// Finds or creates the contact (and its reverse alias) for a correspondent.
pub async fn ensure_contact(
    conn: &mut AnyConnection,
    alias_email: &str,
    email: &str,
    name: Option<&str>,
) -> ApiResult<i64> {
    let email = email.trim().to_lowercase();
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM alias_contacts WHERE alias_email = $1 AND email = $2")
            .bind(alias_email)
            .bind(&email)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some((id,)) = row {
        return Ok(id);
    }
    let id = crate::db::next_counter(&mut *conn, "alias_contacts").await?;
    let domain = alias_email.rsplit('@').next().unwrap_or_default();
    let local: String = email
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(30)
        .collect();
    let reverse = format!("ra+{local}+{}@{domain}", new_token(10));
    sqlx::query(
        "INSERT INTO alias_contacts (id, alias_email, email, name, reverse_alias, created) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(alias_email)
    .bind(&email)
    .bind(name)
    .bind(&reverse)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContactListQuery {
    #[serde(rename = "LastID")]
    pub last_id: Option<i64>,
    pub blocked: Option<String>,
}

pub async fn list_contacts(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Query(q): Query<ContactListQuery>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    let blocked_filter = match q.blocked.as_deref() {
        Some("1") | Some("true") => " AND blocked = 1",
        Some("0") | Some("false") => " AND blocked = 0",
        _ => "",
    };
    let rows: Vec<(i64, Option<String>, i64, String, String, i64, i64, i64, i64)> = sqlx::query_as(crate::sql!(
        "SELECT {CONTACT_COLS} FROM alias_contacts WHERE alias_email = $1 AND id > $2{blocked_filter} ORDER BY id LIMIT 100"
    ))
    .bind(&email)
    .bind(q.last_id.unwrap_or(0))
    .fetch_all(&state.db)
    .await?;
    let (total,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM alias_contacts WHERE alias_email = $1")
            .bind(&email)
            .fetch_one(&state.db)
            .await?;
    let last = rows.last().map(|r| r.0).unwrap_or(0);
    let contacts: Vec<Value> = rows.iter().map(contact_json).collect();
    Ok(ok(
        json!({ "Contacts": contacts, "Total": total, "LastID": last }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContactCreateReq {
    pub email: String,
    pub name: Option<String>,
}

async fn load_contact(state: &AppState, email: &str, id: i64) -> ApiResult<Value> {
    let row: Option<(i64, Option<String>, i64, String, String, i64, i64, i64, i64)> =
        sqlx::query_as(crate::sql!(
            "SELECT {CONTACT_COLS} FROM alias_contacts WHERE alias_email = $1 AND id = $2"
        ))
        .bind(email)
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    row.map(|r| contact_json(&r))
        .ok_or_else(|| ApiError::not_found("Contact"))
}

pub async fn create_contact(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<ContactCreateReq>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    if !req.email.contains('@') {
        return Err(ApiError::bad_request("Invalid email"));
    }
    let mut tx = state.db.begin().await?;
    let id = ensure_contact(&mut tx, &email, &req.email, req.name.as_deref()).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "Contact": load_contact(&state, &email, id).await? }),
    ))
}

pub async fn get_contact(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id, contact_id)): Path<(String, String, i64)>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    Ok(ok(
        json!({ "Contact": load_contact(&state, &email, contact_id).await? }),
    ))
}

pub async fn delete_contact(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id, contact_id)): Path<(String, String, i64)>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    sqlx::query("DELETE FROM alias_contacts WHERE alias_email = $1 AND id = $2")
        .bind(&email)
        .bind(contact_id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockReq {
    pub blocked: bool,
}

pub async fn block_contact(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id, contact_id)): Path<(String, String, i64)>,
    Json(req): Json<BlockReq>,
) -> ApiResult<Json<Value>> {
    let (_, _, email) = alias_for_item(&state, &user, &share_id, &item_id).await?;
    require_owner(&state, &user.user_id, &email).await?;
    sqlx::query("UPDATE alias_contacts SET blocked = $1 WHERE alias_email = $2 AND id = $3")
        .bind(req.blocked as i64)
        .bind(&email)
        .bind(contact_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Contact": load_contact(&state, &email, contact_id).await? }),
    ))
}

/// Breach monitoring has no data source on a self-hosted server.
pub async fn breaches(_user: AuthUser, Path(_p): Path<(String, String)>) -> Json<Value> {
    ok(json!({ "Breaches": { "IsEligible": false, "Count": 0, "Breaches": [], "Samples": [] } }))
}

pub async fn breaches_resolved(_user: AuthUser, Path(_p): Path<(String, String)>) -> Json<Value> {
    ok_empty()
}

pub async fn breach_resolve(
    _user: AuthUser,
    Path(_p): Path<(String, String, String)>,
) -> Json<Value> {
    ok_empty()
}

// ---- User-level alias settings ----

pub async fn settings_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    let row: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT default_domain, default_mailbox_id FROM alias_settings WHERE user_id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let (domain, mailbox) = row.unwrap_or((None, None));
    let mailbox = match mailbox {
        Some(m) => m,
        None => mailboxes::default_id(state, user_id).await?,
    };
    Ok(json!({ "DefaultAliasDomain": domain, "DefaultMailboxID": mailbox }))
}

pub async fn get_settings(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id).await? }),
    ))
}

async fn ensure_settings(state: &AppState, user_id: &str) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO alias_settings (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING",
    )
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DefaultDomainReq {
    pub default_alias_domain: Option<String>,
}

pub async fn set_default_domain(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<DefaultDomainReq>,
) -> ApiResult<Json<Value>> {
    if let Some(d) = &req.default_alias_domain
        && !user_domains(&state, &user.user_id)
            .await?
            .iter()
            .any(|(x, _)| x == d)
    {
        return Err(ApiError::bad_request("Unknown domain"));
    }
    ensure_settings(&state, &user.user_id).await?;
    sqlx::query("UPDATE alias_settings SET default_domain = $1 WHERE user_id = $2")
        .bind(&req.default_alias_domain)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DefaultMailboxReq {
    #[serde(rename = "DefaultMailboxID")]
    pub default_mailbox_id: i64,
}

pub async fn set_default_mailbox(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<DefaultMailboxReq>,
) -> ApiResult<Json<Value>> {
    {
        let mut conn = state.db.acquire().await?;
        mailboxes::check_owned_verified(&mut conn, &user.user_id, req.default_mailbox_id).await?;
    }
    ensure_settings(&state, &user.user_id).await?;
    sqlx::query("UPDATE alias_settings SET default_mailbox_id = $1 WHERE user_id = $2")
        .bind(req.default_mailbox_id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    sqlx::query("UPDATE alias_mailboxes SET is_default = CASE WHEN id = $1 THEN 1 ELSE 0 END WHERE user_id = $2")
        .bind(req.default_mailbox_id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Settings": settings_json(&state, &user.user_id).await? }),
    ))
}

pub async fn list_domains(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let default = settings_domain(&state, &user.user_id).await.ok();
    let domains: Vec<Value> = user_domains(&state, &user.user_id)
        .await?
        .into_iter()
        .map(|(d, custom)| {
            json!({ "Domain": d, "IsCustom": custom, "IsPremium": false, "MXVerified": true,
                    "IsDefault": Some(&d) == default.as_ref() })
        })
        .collect();
    Ok(ok(json!({ "Domains": domains })))
}

pub async fn count(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM aliases WHERE user_id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    Ok(ok(json!({ "AliasCount": { "Total": n } })))
}

/// Aliases owned by the user whose item no longer exists.
pub async fn missing(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT email, note FROM aliases WHERE user_id = $1 AND (item_id IS NULL OR item_id NOT IN (SELECT id FROM items))",
    )
    .bind(&user.user_id)
    .fetch_all(&state.db)
    .await?;
    let missing: Vec<Value> = rows
        .into_iter()
        .map(|(e, n)| json!({ "Email": e, "Note": n.unwrap_or_default() }))
        .collect();
    Ok(ok(json!({ "MissingAlias": missing })))
}

/// SimpleLogin account sync does not apply to a self-hosted server.
pub async fn sl_pending(_user: AuthUser) -> Json<Value> {
    ok(json!({ "PendingAliases": { "Aliases": [], "Total": 0, "LastToken": null } }))
}

pub async fn sl_status(_user: AuthUser) -> Json<Value> {
    ok(json!({ "SyncStatus": { "Enabled": false, "PendingAliasCount": 0 } }))
}

pub async fn sl_disabled(_user: AuthUser) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("SimpleLogin sync"))
}

pub async fn sl_disabled_share(_user: AuthUser, Path(_s): Path<String>) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("SimpleLogin sync"))
}

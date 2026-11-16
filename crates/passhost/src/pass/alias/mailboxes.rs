//! Alias mailboxes: the real inboxes aliases forward to.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    util::{now, ok, ok_empty},
};

async fn next_id(conn: &mut AnyConnection) -> ApiResult<i64> {
    Ok(crate::db::next_counter(&mut *conn, "alias_mailboxes").await?)
}

/// Ensures the user's primary address exists as a verified default mailbox.
async fn ensure_default(conn: &mut AnyConnection, user_id: &str) -> ApiResult<i64> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM alias_mailboxes WHERE user_id = $1 ORDER BY is_default DESC, id LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((id,)) = row {
        return Ok(id);
    }
    let (email,): (String,) = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;
    let id = next_id(conn).await?;
    sqlx::query("INSERT INTO alias_mailboxes (id, user_id, email, verified, is_default, created) VALUES ($1,$2,$3,1,1,$4)")
        .bind(id)
        .bind(user_id)
        .bind(&email)
        .bind(now())
        .execute(&mut *conn)
        .await?;
    Ok(id)
}

pub async fn default_id_conn(conn: &mut AnyConnection, user_id: &str) -> ApiResult<i64> {
    ensure_default(conn, user_id).await
}

pub async fn default_id(state: &AppState, user_id: &str) -> ApiResult<i64> {
    let mut conn = state.db.acquire().await?;
    ensure_default(&mut conn, user_id).await
}

pub async fn verified(state: &AppState, user_id: &str) -> ApiResult<Vec<(i64, String)>> {
    let mut conn = state.db.acquire().await?;
    ensure_default(&mut conn, user_id).await?;
    Ok(sqlx::query_as(
        "SELECT id, email FROM alias_mailboxes WHERE user_id = $1 AND verified = 1 ORDER BY id",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?)
}

pub async fn check_owned_verified(
    conn: &mut AnyConnection,
    user_id: &str,
    id: i64,
) -> ApiResult<()> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT verified FROM alias_mailboxes WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await?;
    match row {
        Some((1,)) => Ok(()),
        Some(_) => Err(ApiError::bad_request("Mailbox is not verified")),
        None => Err(ApiError::not_found("Mailbox")),
    }
}

async fn mailbox_json(state: &AppState, user_id: &str, id: i64) -> ApiResult<Value> {
    let row: Option<(i64, String, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT id, email, pending_email, verified, is_default FROM alias_mailboxes WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    let (id, email, pending, verified, is_default) =
        row.ok_or_else(|| ApiError::not_found("Mailbox"))?;
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM alias_mailbox_links WHERE mailbox_id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    Ok(json!({
        "MailboxID": id, "Email": email, "PendingEmail": pending, "Verified": verified != 0,
        "IsDefault": is_default != 0, "AliasCount": count, "CanBeEdited": is_default == 0,
    }))
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    default_id(&state, &user.user_id).await?;
    let ids: Vec<(i64,)> =
        sqlx::query_as("SELECT id FROM alias_mailboxes WHERE user_id = $1 ORDER BY id")
            .bind(&user.user_id)
            .fetch_all(&state.db)
            .await?;
    let mut out = vec![];
    for (id,) in ids {
        out.push(mailbox_json(&state, &user.user_id, id).await?);
    }
    Ok(ok(json!({ "Mailboxes": out })))
}

fn code() -> String {
    format!("{:06}", rand::random::<u32>() % 1_000_000)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct EmailReq {
    pub email: String,
}

pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<EmailReq>,
) -> ApiResult<Json<Value>> {
    let email = req.email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(ApiError::bad_request("Invalid email"));
    }
    let mut conn = state.db.acquire().await?;
    ensure_default(&mut conn, &user.user_id).await?;
    let dup: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM alias_mailboxes WHERE user_id = $1 AND email = $2")
            .bind(&user.user_id)
            .bind(&email)
            .fetch_optional(&mut *conn)
            .await?;
    if dup.is_some() {
        return Err(ApiError::conflict("Mailbox already exists"));
    }
    let id = next_id(&mut conn).await?;
    let c = code();
    sqlx::query("INSERT INTO alias_mailboxes (id, user_id, email, verification_code, created) VALUES ($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(&user.user_id)
        .bind(&email)
        .bind(&c)
        .bind(now())
        .execute(&mut *conn)
        .await?;
    drop(conn);
    super::mail::send_code(&state, &email, &c).await;
    Ok(ok(
        json!({ "Mailbox": mailbox_json(&state, &user.user_id, id).await? }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct VerifyReq {
    pub code: String,
}

pub async fn verify(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<VerifyReq>,
) -> ApiResult<Json<Value>> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT verification_code, pending_email FROM alias_mailboxes WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(&user.user_id)
            .fetch_optional(&state.db)
            .await?;
    let (stored, pending) = row.ok_or_else(|| ApiError::not_found("Mailbox"))?;
    if stored.as_deref() != Some(req.code.trim()) {
        return Err(ApiError::bad_request("Invalid verification code"));
    }
    match pending {
        Some(p) => {
            sqlx::query("UPDATE alias_mailboxes SET email = $1, pending_email = NULL, verification_code = NULL, verified = 1 WHERE id = $2")
                .bind(&p)
                .bind(id)
                .execute(&state.db)
                .await?;
        }
        None => {
            sqlx::query(
                "UPDATE alias_mailboxes SET verified = 1, verification_code = NULL WHERE id = $1",
            )
            .bind(id)
            .execute(&state.db)
            .await?;
        }
    }
    Ok(ok(
        json!({ "Mailbox": mailbox_json(&state, &user.user_id, id).await? }),
    ))
}

/// `GET user/alias/mailbox/{id}/verify`: resend the code.
pub async fn resend(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT email, pending_email FROM alias_mailboxes WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await?;
    let (email, pending) = row.ok_or_else(|| ApiError::not_found("Mailbox"))?;
    let c = code();
    sqlx::query("UPDATE alias_mailboxes SET verification_code = $1 WHERE id = $2")
        .bind(&c)
        .bind(id)
        .execute(&state.db)
        .await?;
    super::mail::send_code(&state, pending.as_deref().unwrap_or(&email), &c).await;
    Ok(ok_empty())
}

pub async fn change_email(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    Json(req): Json<EmailReq>,
) -> ApiResult<Json<Value>> {
    let email = req.email.trim().to_lowercase();
    let c = code();
    let r = sqlx::query("UPDATE alias_mailboxes SET pending_email = $1, verification_code = $2 WHERE id = $3 AND user_id = $4 AND is_default = 0")
        .bind(&email)
        .bind(&c)
        .bind(id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("Mailbox"));
    }
    super::mail::send_code(&state, &email, &c).await;
    Ok(ok(
        json!({ "Mailbox": mailbox_json(&state, &user.user_id, id).await? }),
    ))
}

pub async fn cancel_email_change(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    sqlx::query("UPDATE alias_mailboxes SET pending_email = NULL WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(&user.user_id)
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Mailbox": mailbox_json(&state, &user.user_id, id).await? }),
    ))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DeleteReq {
    #[serde(rename = "TransferMailboxID")]
    pub transfer_mailbox_id: Option<i64>,
}

pub async fn delete(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
    body: Option<Json<DeleteReq>>,
) -> ApiResult<Json<Value>> {
    let req = body.map(|b| b.0).unwrap_or_default();
    let mut tx = state.db.begin().await?;
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT is_default FROM alias_mailboxes WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(&user.user_id)
            .fetch_optional(&mut *tx)
            .await?;
    match row {
        None => return Err(ApiError::not_found("Mailbox")),
        Some((1,)) => {
            return Err(ApiError::bad_request(
                "The default mailbox cannot be deleted",
            ));
        }
        _ => {}
    }
    let target = match req.transfer_mailbox_id {
        Some(t) => {
            check_owned_verified(&mut tx, &user.user_id, t).await?;
            t
        }
        None => ensure_default(&mut tx, &user.user_id).await?,
    };
    // Aliases that only had this mailbox move to the transfer target.
    sqlx::query(
        "INSERT INTO alias_mailbox_links (alias_email, mailbox_id) SELECT alias_email, $1 FROM alias_mailbox_links l \
         WHERE l.mailbox_id = $2 AND NOT EXISTS (SELECT 1 FROM alias_mailbox_links o WHERE o.alias_email = l.alias_email AND o.mailbox_id <> $2)",
    )
    .bind(target)
    .bind(id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM alias_mailboxes WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(ok_empty())
}

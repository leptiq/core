//! The instance-wide organization: policies that clients enforce (sharing,
//! exports, password generator rules...). Instance admins can update them.

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Map, Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    util::{new_id, now, ok, ok_empty},
};

fn default_settings() -> Value {
    json!({
        "ShareMode": 0,
        "ShareAcceptMode": 0,
        "ItemShareMode": 1,
        "PublicLinkMode": 1,
        "ForceLockSeconds": 0,
        "ExportMode": 0,
        "PasswordPolicy": null,
        "VaultCreateMode": 0,
        "AliasCreateMode": 0,
        "CanStoreTotp": 0,
        "CanStorePasskey": 0,
    })
}

pub async fn settings(state: &AppState) -> ApiResult<Value> {
    let row: Option<(String,)> = sqlx::query_as("SELECT v FROM kv WHERE k = 'org_settings'")
        .fetch_optional(&state.db)
        .await?;
    let mut base = default_settings();
    if let Some((v,)) = row {
        if let Ok(Value::Object(stored)) = serde_json::from_str::<Value>(&v) {
            for (k, v) in stored {
                base[k] = v;
            }
        }
    }
    Ok(base)
}

async fn save(state: &AppState, settings: &Value) -> ApiResult<()> {
    sqlx::query(
        "INSERT INTO kv (k, v) VALUES ('org_settings', $1) ON CONFLICT (k) DO UPDATE SET v = $1",
    )
    .bind(settings.to_string())
    .execute(&state.db)
    .await?;
    Ok(())
}

async fn is_admin(state: &AppState, user_id: &str) -> ApiResult<bool> {
    let (admin,): (i64,) = sqlx::query_as("SELECT is_admin FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.db)
        .await?;
    Ok(admin != 0)
}

async fn require_admin(state: &AppState, user_id: &str) -> ApiResult<()> {
    if is_admin(state, user_id).await? {
        Ok(())
    } else {
        Err(ApiError::forbidden("Only instance admins can do this"))
    }
}

async fn org_json(state: &AppState, user_id: &str) -> ApiResult<Value> {
    Ok(json!({ "CanUpdate": is_admin(state, user_id).await?, "Settings": settings(state).await? }))
}

pub async fn get(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "Organization": org_json(&state, &user.user_id).await? }),
    ))
}

pub async fn update(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<Map<String, Value>>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    let mut s = settings(&state).await?;
    let allowed = default_settings();
    for (k, v) in req {
        if allowed.get(&k).is_some() && k != "PasswordPolicy" && !v.is_null() {
            s[k] = v;
        }
    }
    save(&state, &s).await?;
    Ok(ok(
        json!({ "Organization": org_json(&state, &user.user_id).await? }),
    ))
}

pub async fn update_password_policy(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<Value>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    let mut s = settings(&state).await?;
    s["PasswordPolicy"] = req;
    save(&state, &s).await?;
    Ok(ok(
        json!({ "Organization": org_json(&state, &user.user_id).await? }),
    ))
}

/// `POST organization/report/client_data`: a member's own health report.
pub async fn store_report(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<Value>,
) -> ApiResult<Json<Value>> {
    sqlx::query(
        "INSERT INTO org_reports (user_id, report, updated) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id) DO UPDATE SET report = $2, updated = $3",
    )
    .bind(&user.user_id)
    .bind(req.to_string())
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(ok_empty())
}

pub async fn reports(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    let rows: Vec<(String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT u.email, r.report, r.updated FROM users u LEFT JOIN org_reports r ON r.user_id = u.id \
         WHERE u.pat_owner_id IS NULL ORDER BY u.created",
    )
    .fetch_all(&state.db)
    .await?;
    let reports: Vec<Value> = rows
        .into_iter()
        .map(|(email, report, updated)| {
            json!({
                "PrimaryEmail": email,
                "CustomEmailBreachCount": { "Count": 0, "Total": 0 },
                "AddressBreachCount": { "Count": 0, "Total": 0 },
                "ItemsReport": { "VaultCount": 0, "ItemCount": 0 },
                "MonitorReport": report.and_then(|r| serde_json::from_str::<Value>(&r).ok()),
                "LastActivityTime": updated,
            })
        })
        .collect();
    Ok(ok(
        json!({ "Report": { "MemberReports": reports, "TotalMemberCount": reports.len() } }),
    ))
}

pub async fn user_shares_report(
    State(state): State<AppState>,
    user: AuthUser,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    Ok(ok(json!({ "Report": { "Users": [], "Total": 0 } })))
}

async fn pause_entries(state: &AppState) -> ApiResult<Vec<Value>> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id, url, vals FROM org_url_pauses ORDER BY created")
            .fetch_all(&state.db)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, url, vals)| {
            json!({ "EntryID": id, "Url": url, "Values": serde_json::from_str::<Value>(&vals).unwrap_or(Value::Null) })
        })
        .collect())
}

pub async fn list_pauses(State(state): State<AppState>, _user: AuthUser) -> ApiResult<Json<Value>> {
    let entries = pause_entries(&state).await?;
    Ok(ok(
        json!({ "Entries": { "Entries": entries, "Total": entries.len() } }),
    ))
}

pub async fn create_pause(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<Value>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    let url = req["Url"]
        .as_str()
        .ok_or_else(|| ApiError::bad_request("Url required"))?
        .to_string();
    let id = new_id();
    sqlx::query("INSERT INTO org_url_pauses (id, url, vals, created) VALUES ($1,$2,$3,$4)")
        .bind(&id)
        .bind(&url)
        .bind(req["Values"].to_string())
        .bind(now())
        .execute(&state.db)
        .await?;
    Ok(ok(
        json!({ "Entry": { "EntryID": id, "Url": url, "Values": req["Values"] } }),
    ))
}

pub async fn update_pause(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<Value>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    sqlx::query("UPDATE org_url_pauses SET vals = $1 WHERE id = $2")
        .bind(req.to_string())
        .bind(&id)
        .execute(&state.db)
        .await?;
    let (url,): (String,) = sqlx::query_as("SELECT url FROM org_url_pauses WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok(ok(
        json!({ "Entry": { "EntryID": id, "Url": url, "Values": req } }),
    ))
}

pub async fn delete_pause(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&state, &user.user_id).await?;
    sqlx::query("DELETE FROM org_url_pauses WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(ok_empty())
}

/// Breach monitoring has no data source on a self-hosted server.
pub async fn breaches(_user: AuthUser) -> Json<Value> {
    ok(json!({ "Breaches": {
        "IsEligible": false, "Count": 0, "Breaches": [], "Samples": [],
        "Addresses": [], "CustomEmails": [], "HasCustomDomains": false,
    }}))
}

pub async fn breach_noop(_user: AuthUser) -> Json<Value> {
    ok_empty()
}

pub async fn breach_unavailable(_user: AuthUser) -> ApiResult<Json<Value>> {
    Err(ApiError::disabled("Breach monitoring"))
}

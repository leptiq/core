//! `core/v4/events`: the core event loop (user, settings, addresses).

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::{
    app::AppState,
    auth::AuthUser,
    error::ApiResult,
    events::{self, kind},
    util::ok,
};

pub async fn latest(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "EventID": events::latest_id(&state.db, &user.user_id).await? }),
    ))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let latest = events::latest_seq(&state.db, &user.user_id).await?;
    let Some(since) = events::decode_id(&id).filter(|s| *s <= latest) else {
        // Unknown event ID: ask the client to refresh everything.
        return Ok(ok(
            json!({ "EventID": events::encode_id(latest), "Refresh": 255, "More": 0 }),
        ));
    };
    let (evs, more) = events::since(&state.db, &user.user_id, since).await?;
    let last = evs.last().map(|e| e.seq).unwrap_or(since);
    let mut out = json!({ "EventID": events::encode_id(last), "Refresh": 0, "More": more as i64 });
    let mut user_changed = false;
    let mut settings_changed = false;
    let mut addresses = std::collections::BTreeMap::new();
    for e in &evs {
        match e.kind.as_str() {
            kind::USER => user_changed = true,
            kind::USER_SETTINGS => settings_changed = true,
            kind::ADDRESS => {
                if let Some(t) = &e.target_id {
                    addresses.insert(t.clone(), true);
                }
            }
            kind::ADDRESS_DELETED => {
                if let Some(t) = &e.target_id {
                    addresses.insert(t.clone(), false);
                }
            }
            _ => {}
        }
    }
    if user_changed {
        out["User"] = super::users::user_json(&state, &user.user_id).await?;
    }
    if settings_changed {
        out["UserSettings"] = super::settings::settings_json(&state, &user.user_id).await?;
    }
    if !addresses.is_empty() {
        let mut list = vec![];
        for (id, exists) in addresses {
            let addr = if exists {
                super::addresses::address_json(&state, &id).await.ok()
            } else {
                None
            };
            match addr {
                Some(a) => list.push(json!({ "ID": id, "Action": 2, "Address": a })),
                None => list.push(json!({ "ID": id, "Action": 0 })),
            }
        }
        out["Addresses"] = Value::Array(list);
    }
    // Let Pass clients know something Pass-related changed.
    if evs
        .iter()
        .any(|e| e.share_id.is_some() || e.kind == kind::INVITES || e.kind == kind::REFRESH_USER)
    {
        out["PassEvents"] = json!(1);
    }
    Ok(ok(out))
}

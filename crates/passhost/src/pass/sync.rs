//! Pass event streams: legacy per-share events and user-wide sync events (v2).

use std::collections::BTreeSet;

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use super::{items, shares};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::ApiResult,
    events::{self, kind},
    util::ok,
};

/// `GET share/{id}/event` → latest event ID.
pub async fn share_latest(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    shares::load(&state, &user.user_id, &share_id).await?;
    Ok(ok(
        json!({ "EventID": events::latest_id(&state.db, &user.user_id).await? }),
    ))
}

/// `GET share/{id}/event/{eventId}` → changes in one share.
pub async fn share_events(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, event_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let latest = events::latest_seq(&state.db, &user.user_id).await?;
    let since_opt = events::decode_id(&event_id).filter(|s| *s <= latest);
    let (evs, more) = match since_opt {
        Some(since) => events::since(&state.db, &user.user_id, since).await?,
        None => (vec![], false),
    };
    let mut conn = state.db.acquire().await?;
    let share_json = shares::share_json_conn(&mut conn, &share).await?;
    let Some(since) = since_opt else {
        return Ok(ok(json!({ "Events": {
            "UpdatedShare": share_json, "UpdatedItems": [], "DeletedItemIDs": [], "AliasNoteChangedItemsIDs": [],
            "LastUseItems": [], "NewKeyRotation": null, "LatestEventID": events::encode_id(latest),
            "EventsPending": false, "FullRefresh": true,
        }})));
    };
    let last = evs.last().map(|e| e.seq).unwrap_or(since);
    let mut updated = BTreeSet::new();
    let mut deleted = BTreeSet::new();
    let mut alias_notes = BTreeSet::new();
    let mut last_use = BTreeSet::new();
    let mut new_rotation = None;
    for e in evs
        .iter()
        .filter(|e| e.share_id.as_deref() == Some(&share.id))
    {
        let target = e.target_id.clone().unwrap_or_default();
        match e.kind.as_str() {
            kind::ITEM_UPDATED => {
                deleted.remove(&target);
                updated.insert(target);
            }
            kind::ITEM_DELETED => {
                updated.remove(&target);
                deleted.insert(target);
            }
            kind::ALIAS_NOTE => {
                alias_notes.insert(target);
            }
            kind::ITEM_LAST_USE => {
                last_use.insert(target);
            }
            kind::SHARE_KEY => {
                new_rotation = e.data.as_ref().and_then(|d| d.parse::<i64>().ok());
            }
            _ => {}
        }
    }
    let mut updated_items = vec![];
    for id in &updated {
        if let Ok(item) = items::load(&mut conn, &share, id).await {
            updated_items.push(items::item_json(&mut conn, &share, &item).await?);
        }
    }
    let mut last_use_items = vec![];
    for id in &last_use {
        if let Ok(item) = items::load(&mut conn, &share, id).await {
            last_use_items.push(json!({ "ItemID": item.id, "LastUseTime": item.last_use_time }));
        }
    }
    Ok(ok(json!({ "Events": {
        "UpdatedShare": share_json,
        "UpdatedItems": updated_items,
        "DeletedItemIDs": deleted,
        "AliasNoteChangedItemsIDs": alias_notes,
        "LastUseItems": last_use_items,
        "NewKeyRotation": new_rotation,
        "LatestEventID": events::encode_id(last),
        "EventsPending": more,
        "FullRefresh": false,
    }})))
}

/// `GET user/sync_event` → latest event ID.
pub async fn latest(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    Ok(ok(
        json!({ "EventID": events::latest_id(&state.db, &user.user_id).await? }),
    ))
}

/// `GET user/sync_event/{id}` → everything that changed for this user.
pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(event_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let latest = events::latest_seq(&state.db, &user.user_id).await?;
    let empty = |last: i64, full: bool, pending: bool| {
        json!({
            "LastEventID": events::encode_id(last),
            "ItemsUpdated": [], "ItemsDeleted": [], "AliasNoteChanged": [],
            "SharesCreated": [], "SharesUpdated": [], "SharesDeleted": [],
            "FoldersUpdated": [], "FoldersDeleted": [],
            "InvitesChanged": null, "GroupInvitesChanged": null, "PendingAliasToCreateChanged": null,
            "BreachUpdate": null, "OrganizationInfoChanged": null,
            "SharesWithInvitesToCreate": [], "RefreshUser": false,
            "EventsPending": pending, "FullRefresh": full,
        })
    };
    let Some(since) = events::decode_id(&event_id).filter(|s| *s <= latest) else {
        return Ok(ok(json!({ "Events": empty(latest, true, false) })));
    };
    let (evs, more) = events::since(&state.db, &user.user_id, since).await?;
    let last = evs.last().map(|e| e.seq).unwrap_or(since);
    let mut out = empty(last, false, more);
    // Deduplicate per (share, target) keeping the latest event of each kind group.
    let mut items_updated: Vec<(String, String, i64)> = vec![];
    let mut items_deleted: Vec<(String, String, i64)> = vec![];
    let mut alias_notes: Vec<(String, String, i64)> = vec![];
    let mut folders_updated: Vec<(String, String, i64)> = vec![];
    let mut folders_deleted: Vec<(String, String, i64)> = vec![];
    let mut shares_created: Vec<(String, i64)> = vec![];
    let mut shares_updated: Vec<(String, i64)> = vec![];
    let mut shares_deleted: Vec<(String, i64)> = vec![];
    let mut invites = None;
    let mut refresh_user = false;
    fn upsert3(v: &mut Vec<(String, String, i64)>, s: &str, t: &str, seq: i64) {
        v.retain(|(a, b, _)| !(a == s && b == t));
        v.push((s.to_string(), t.to_string(), seq));
    }
    fn upsert2(v: &mut Vec<(String, i64)>, s: &str, seq: i64) {
        v.retain(|(a, _)| a != s);
        v.push((s.to_string(), seq));
    }
    for e in &evs {
        let s = e.share_id.clone().unwrap_or_default();
        let t = e.target_id.clone().unwrap_or_default();
        match e.kind.as_str() {
            kind::ITEM_UPDATED | kind::ITEM_LAST_USE => {
                items_deleted.retain(|(a, b, _)| !(a == &s && b == &t));
                upsert3(&mut items_updated, &s, &t, e.seq);
            }
            kind::ITEM_DELETED => {
                items_updated.retain(|(a, b, _)| !(a == &s && b == &t));
                upsert3(&mut items_deleted, &s, &t, e.seq);
            }
            kind::ALIAS_NOTE => upsert3(&mut alias_notes, &s, &t, e.seq),
            kind::FOLDER_UPDATED => {
                folders_deleted.retain(|(a, b, _)| !(a == &s && b == &t));
                upsert3(&mut folders_updated, &s, &t, e.seq);
            }
            kind::FOLDER_DELETED => {
                folders_updated.retain(|(a, b, _)| !(a == &s && b == &t));
                upsert3(&mut folders_deleted, &s, &t, e.seq);
            }
            kind::SHARE_CREATED => upsert2(&mut shares_created, &s, e.seq),
            kind::SHARE_UPDATED | kind::SHARE_KEY => {
                if !shares_created.iter().any(|(a, _)| a == &s) {
                    upsert2(&mut shares_updated, &s, e.seq);
                }
            }
            kind::SHARE_DELETED => {
                shares_created.retain(|(a, _)| a != &s);
                shares_updated.retain(|(a, _)| a != &s);
                items_updated.retain(|(a, _, _)| a != &s);
                folders_updated.retain(|(a, _, _)| a != &s);
                upsert2(&mut shares_deleted, &s, e.seq);
            }
            kind::INVITES => invites = Some(e.seq),
            kind::REFRESH_USER | kind::USER => refresh_user = true,
            _ => {}
        }
    }
    let map3 = |v: Vec<(String, String, i64)>, field: &str| -> Vec<Value> {
        v.into_iter()
            .filter(|(s, _, _)| !s.is_empty())
            .map(|(s, t, seq)| json!({ "ShareID": s, field: t, "EventToken": events::encode_id(seq) }))
            .collect()
    };
    let map2 = |v: Vec<(String, i64)>| -> Vec<Value> {
        v.into_iter()
            .filter(|(s, _)| !s.is_empty())
            .map(|(s, seq)| json!({ "ShareID": s, "EventToken": events::encode_id(seq) }))
            .collect()
    };
    out["ItemsUpdated"] = json!(map3(items_updated, "ItemID"));
    out["ItemsDeleted"] = json!(map3(items_deleted, "ItemID"));
    out["AliasNoteChanged"] = json!(map3(alias_notes, "ItemID"));
    out["FoldersUpdated"] = json!(map3(folders_updated, "FolderID"));
    out["FoldersDeleted"] = json!(map3(folders_deleted, "FolderID"));
    out["SharesCreated"] = json!(map2(shares_created));
    out["SharesUpdated"] = json!(map2(shares_updated));
    out["SharesDeleted"] = json!(map2(shares_deleted));
    out["InvitesChanged"] = invites
        .map(|s| json!({ "EventToken": events::encode_id(s) }))
        .unwrap_or(Value::Null);
    out["RefreshUser"] = json!(refresh_user);
    Ok(ok(json!({ "Events": out })))
}

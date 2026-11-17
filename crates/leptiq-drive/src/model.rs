//! Database rows and the JSON shapes the Drive SDK expects.

use axum::http::StatusCode;
use leptiq_core::{
    AppState,
    error::{ApiError, ApiResult, code},
    util::now,
};
use serde_json::{Value, json};
use sqlx::AnyConnection;

pub const FOLDER: i64 = 1;
pub const FILE: i64 = 2;

pub const DRAFT: i64 = 0;
pub const ACTIVE: i64 = 1;
pub const TRASHED: i64 = 2;

pub const REV_DRAFT: i64 = 0;
pub const REV_ACTIVE: i64 = 1;
pub const REV_OBSOLETE: i64 = 2;

pub const VOLUME_REGULAR: i64 = 1;
pub const VOLUME_PHOTOS: i64 = 2;

pub const EVENT_DELETE: i64 = 0;
pub const EVENT_CREATE: i64 = 1;
pub const EVENT_UPDATE: i64 = 2;

/// Error the SDK maps to "invalid requirements" (e.g. stale `OriginalHash`).
pub fn invalid_requirements(msg: &str) -> ApiError {
    ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, 2000, msg)
}

pub fn no_permission() -> ApiError {
    ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code::NOT_ALLOWED,
        "No permission",
    )
}

#[derive(sqlx::FromRow, Clone)]
pub struct Volume {
    pub id: String,
    pub user_id: String,
    pub volume_type: i64,
    pub share_id: String,
    pub root_link_id: String,
    pub used_space: i64,
    pub created: i64,
    pub modified: i64,
}

/// A volume of the calling user.
pub async fn volume(state: &AppState, user_id: &str, id: &str) -> ApiResult<Volume> {
    let v: Option<Volume> = sqlx::query_as(
        "SELECT id, user_id, volume_type, share_id, root_link_id, used_space, created, modified \
         FROM drive_volumes WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;
    match v {
        Some(v) if v.user_id == user_id => Ok(v),
        Some(_) => Err(no_permission()),
        None => Err(ApiError::not_found("Volume")),
    }
}

pub async fn user_volume(
    state: &AppState,
    user_id: &str,
    volume_type: i64,
) -> ApiResult<Option<Volume>> {
    Ok(sqlx::query_as(
        "SELECT id, user_id, volume_type, share_id, root_link_id, used_space, created, modified \
         FROM drive_volumes WHERE user_id = $1 AND volume_type = $2",
    )
    .bind(user_id)
    .bind(volume_type)
    .fetch_optional(&state.db)
    .await?)
}

#[derive(sqlx::FromRow, Clone)]
pub struct Share {
    pub id: String,
    pub volume_id: String,
    pub share_type: i64,
    pub link_id: String,
    pub address_id: String,
    pub address_key_id: String,
    pub creator_email: String,
    pub share_key: String,
    pub passphrase: String,
    pub passphrase_signature: String,
    pub created: i64,
    pub modified: i64,
}

pub async fn share(state: &AppState, id: &str) -> ApiResult<Share> {
    sqlx::query_as(
        "SELECT id, volume_id, share_type, link_id, address_id, address_key_id, creator_email, \
         share_key, passphrase, passphrase_signature, created, modified FROM drive_shares WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("Share"))
}

#[derive(sqlx::FromRow, Clone)]
#[allow(dead_code)] // full row, some columns only used in SQL
pub struct Link {
    pub id: String,
    pub volume_id: String,
    pub parent_id: Option<String>,
    pub link_type: i64,
    pub state: i64,
    pub name: String,
    pub name_hash: Option<String>,
    pub node_key: String,
    pub node_passphrase: String,
    pub node_passphrase_signature: String,
    pub node_hash_key: Option<String>,
    pub xattr: Option<String>,
    pub signature_email: Option<String>,
    pub name_signature_email: Option<String>,
    pub mime_type: Option<String>,
    pub content_key_packet: Option<String>,
    pub content_key_packet_signature: Option<String>,
    pub active_revision_id: Option<String>,
    pub client_uid: Option<String>,
    pub created: i64,
    pub modified: i64,
    pub trash_time: Option<i64>,
}

pub const LINK_COLS: &str = "id, volume_id, parent_id, link_type, state, name, name_hash, node_key, \
    node_passphrase, node_passphrase_signature, node_hash_key, xattr, signature_email, \
    name_signature_email, mime_type, content_key_packet, content_key_packet_signature, \
    active_revision_id, client_uid, created, modified, trash_time";

pub async fn find_link(state: &AppState, volume_id: &str, id: &str) -> ApiResult<Option<Link>> {
    Ok(sqlx::query_as(leptiq_core::sql!(
        "SELECT {LINK_COLS} FROM drive_links WHERE id = $1 AND volume_id = $2"
    ))
    .bind(id)
    .bind(volume_id)
    .fetch_optional(&state.db)
    .await?)
}

pub async fn link(state: &AppState, volume_id: &str, id: &str) -> ApiResult<Link> {
    find_link(state, volume_id, id)
        .await?
        .ok_or_else(|| ApiError::not_found("Link"))
}

/// The parent must be an active folder of the volume.
pub async fn active_folder(state: &AppState, volume_id: &str, id: &str) -> ApiResult<Link> {
    let l = link(state, volume_id, id).await?;
    if l.link_type != FOLDER || l.state != ACTIVE {
        return Err(ApiError::not_found("Parent folder"));
    }
    Ok(l)
}

/// Names are unique per folder by their client-computed hash (drafts and
/// active links; trashed ones don't count). Returns the 2500 error with the
/// details the SDK uses to resolve conflicts.
pub async fn check_name_free(
    state: &AppState,
    volume_id: &str,
    parent_id: &str,
    hash: &str,
    except: Option<&str>,
) -> ApiResult<()> {
    let row: Option<(String, i64, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, state, active_revision_id, client_uid FROM drive_links \
         WHERE volume_id = $1 AND parent_id = $2 AND name_hash = $3 AND state IN (0, 1)",
    )
    .bind(volume_id)
    .bind(parent_id)
    .bind(hash)
    .fetch_optional(&state.db)
    .await?;
    let Some((id, st, active_rev, client_uid)) = row else {
        return Ok(());
    };
    if Some(id.as_str()) == except {
        return Ok(());
    }
    let draft_rev: Option<(String,)> = if st == DRAFT {
        sqlx::query_as("SELECT id FROM drive_revisions WHERE link_id = $1 AND state = 0 LIMIT 1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await?
    } else {
        None
    };
    Err(ApiError::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        code::ALREADY_EXISTS,
        "A file or folder with that name already exists",
    )
    .with_details(json!({
        "ConflictLinkID": id,
        "ConflictRevisionID": active_rev,
        "ConflictDraftRevisionID": draft_rev.map(|r| r.0),
        "ConflictDraftClientUID": if st == DRAFT { client_uid } else { None },
    })))
}

pub fn link_dto(l: &Link, owner_email: &Option<String>) -> Value {
    json!({
        "LinkID": l.id,
        "Type": l.link_type,
        "ParentLinkID": l.parent_id,
        "State": l.state,
        "CreateTime": l.created,
        "ModifyTime": l.modified,
        "TrashTime": l.trash_time,
        "Name": l.name,
        "NameHash": l.name_hash,
        "NodeKey": l.node_key,
        "NodePassphrase": l.node_passphrase,
        "NodePassphraseSignature": l.node_passphrase_signature,
        "SignatureEmail": l.signature_email,
        "NameSignatureEmail": l.name_signature_email,
        "OwnedBy": { "Email": owner_email, "Organization": null },
        "DirectPermissions": null,
        "ThirdParty": false,
        "Sdk": false,
    })
}

#[derive(sqlx::FromRow, Clone)]
#[allow(dead_code)] // full row, some columns only used in SQL
pub struct Revision {
    pub id: String,
    pub link_id: String,
    pub state: i64,
    pub size: i64,
    pub manifest_signature: Option<String>,
    pub xattr: Option<String>,
    pub signature_email: Option<String>,
    pub checksum_verified: i64,
    pub client_uid: Option<String>,
    pub verification_code: String,
    pub created: i64,
}

pub const REVISION_COLS: &str = "id, link_id, state, size, manifest_signature, xattr, signature_email, \
    checksum_verified, client_uid, verification_code, created";

pub async fn revision(state: &AppState, link_id: &str, id: &str) -> ApiResult<Revision> {
    sqlx::query_as(leptiq_core::sql!(
        "SELECT {REVISION_COLS} FROM drive_revisions WHERE id = $1 AND link_id = $2"
    ))
    .bind(id)
    .bind(link_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::not_found("Revision"))
}

/// Thumbnails of a revision, sorted by type (the manifest order).
pub async fn thumbnails(
    state: &AppState,
    revision_id: &str,
) -> ApiResult<Vec<(String, i64, String, i64)>> {
    Ok(sqlx::query_as(
        "SELECT id, thumb_type, hash, size FROM drive_thumbnails WHERE revision_id = $1 ORDER BY thumb_type",
    )
    .bind(revision_id)
    .fetch_all(&state.db)
    .await?)
}

pub async fn revision_json(
    state: &AppState,
    r: &Revision,
    with_size_fields: bool,
) -> ApiResult<Value> {
    let thumbs = thumbnails(state, &r.id).await?;
    let thumbs_json: Vec<Value> = thumbs
        .iter()
        .map(|(id, ty, hash, size)| {
            json!({ "ThumbnailID": id, "Type": ty, "Hash": hash, "EncryptedSize": size, "Size": size })
        })
        .collect();
    let mut v = json!({
        "ID": r.id,
        "RevisionID": r.id,
        "State": r.state,
        "CreateTime": r.created,
        "EncryptedSize": r.size,
        "ManifestSignature": r.manifest_signature,
        "XAttr": r.xattr,
        "SignatureEmail": r.signature_email,
        "SignatureAddress": r.signature_email,
        "ChecksumVerified": r.checksum_verified != 0,
        "IsImported": false,
        "ThirdParty": false,
        "Sdk": false,
        "ClientUID": r.client_uid,
        "Thumbnails": thumbs_json,
        "Thumbnail": if thumbs.is_empty() { 0 } else { 1 },
        "ThumbnailSize": thumbs.first().map(|t| t.3).unwrap_or(0),
        "Photo": null,
    });
    if with_size_fields {
        v["Size"] = json!(r.size);
    }
    Ok(v)
}

/// `LoadLinkDetailsResponseDto` entry for one link.
pub async fn link_details(
    state: &AppState,
    vol: &Volume,
    l: &Link,
    owner_email: &Option<String>,
) -> ApiResult<Value> {
    let (folder, file) = if l.link_type == FOLDER {
        (
            json!({ "NodeHashKey": l.node_hash_key, "XAttr": l.xattr, "IsImported": false }),
            Value::Null,
        )
    } else {
        let active = match &l.active_revision_id {
            Some(rid) => Some(revision(state, &l.id, rid).await?),
            None => None,
        };
        let total = match &active {
            Some(r) => r.size,
            None => 0,
        };
        let active_json = match &active {
            Some(r) => revision_json(state, r, false).await?,
            None => Value::Null,
        };
        (
            Value::Null,
            json!({
                "ActiveRevision": active_json,
                "TotalEncryptedSize": total,
                "ContentKeyPacket": l.content_key_packet,
                "ContentKeyPacketSignature": l.content_key_packet_signature,
                "MediaType": l.mime_type,
            }),
        )
    };
    let sharing = if l.parent_id.is_none() && l.id == vol.root_link_id {
        json!({ "ShareID": vol.share_id, "ShareURLID": null })
    } else {
        Value::Null
    };
    Ok(json!({
        "Link": link_dto(l, owner_email),
        "Folder": folder,
        "File": file,
        "Album": null,
        "Photo": null,
        "Sharing": sharing,
        "Membership": null,
    }))
}

/// The email of the volume owner's primary address (shown as `OwnedBy`).
pub async fn owner_email(state: &AppState, user_id: &str) -> ApiResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    Ok(row.map(|r| r.0))
}

/// Appends a change to the volume's event log.
pub async fn push_event(
    conn: &mut AnyConnection,
    volume_id: &str,
    event_type: i64,
    link_id: &str,
    parent_id: Option<&str>,
    is_trashed: bool,
) -> ApiResult<()> {
    let seq = leptiq_core::db::next_counter(conn, &format!("drive_events:{volume_id}")).await?;
    sqlx::query(
        "INSERT INTO drive_events (volume_id, seq, event_type, link_id, parent_id, is_trashed, created) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(volume_id)
    .bind(seq)
    .bind(event_type)
    .bind(link_id)
    .bind(parent_id)
    .bind(is_trashed as i64)
    .bind(now())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

pub async fn event(state: &AppState, volume_id: &str, event_type: i64, l: &Link) -> ApiResult<()> {
    let mut conn = state.db.acquire().await?;
    push_event(
        &mut conn,
        volume_id,
        event_type,
        &l.id,
        l.parent_id.as_deref(),
        l.state == TRASHED,
    )
    .await
}

/// The legacy (share-based) `LinkMeta` shape, still used by parts of the web
/// app (`drive/shares/{share}/links/{link}`).
pub async fn legacy_link(state: &AppState, vol: &Volume, l: &Link) -> ApiResult<Value> {
    let (file_props, folder_props, size) = if l.link_type == FOLDER {
        (Value::Null, json!({ "NodeHashKey": l.node_hash_key }), 0)
    } else {
        let active = match &l.active_revision_id {
            Some(rid) => Some(revision(state, &l.id, rid).await?),
            None => None,
        };
        let size = active.as_ref().map(|r| r.size).unwrap_or(0);
        let active_json = match &active {
            Some(r) => revision_json(state, r, true).await?,
            None => Value::Null,
        };
        (
            json!({
                "ContentKeyPacket": l.content_key_packet,
                "ContentKeyPacketSignature": l.content_key_packet_signature,
                "ActiveRevision": active_json,
            }),
            Value::Null,
            size,
        )
    };
    let is_root = l.parent_id.is_none() && l.id == vol.root_link_id;
    Ok(json!({
        "LinkID": l.id,
        "ParentLinkID": l.parent_id,
        "VolumeID": vol.id,
        "Type": l.link_type,
        "Name": l.name,
        "EncryptedName": l.name,
        "NameSignatureEmail": l.name_signature_email,
        "Hash": l.name_hash,
        "Size": size,
        "MIMEType": l.mime_type.clone().unwrap_or_else(|| "Folder".into()),
        "CreateTime": l.created,
        "ModifyTime": l.modified,
        "RealModifyTime": l.modified,
        "Trashed": l.trash_time,
        "State": l.state,
        "NodeKey": l.node_key,
        "NodePassphrase": l.node_passphrase,
        "NodePassphraseSignature": l.node_passphrase_signature,
        "SignatureEmail": l.signature_email,
        "SignatureAddress": l.signature_email,
        "Attributes": 0,
        "Permissions": 7,
        "FileProperties": file_props,
        "FolderProperties": folder_props,
        "AlbumProperties": null,
        "PhotoProperties": null,
        "DocumentProperties": null,
        "Shared": 0,
        "ShareIDs": if is_root { vec![vol.share_id.clone()] } else { vec![] },
        "ShareUrls": [],
        "SharingDetails": if is_root { json!({ "ShareID": vol.share_id, "ShareUrl": null }) } else { Value::Null },
        "XAttr": l.xattr,
    }))
}

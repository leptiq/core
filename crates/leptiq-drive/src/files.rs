//! File upload (drafts, revisions, blocks), download and thumbnails.
//!
//! Block bytes go to a storage URL (`BareURL`) with a short-lived token, as
//! with Proton's block storage; the server hashes and stores them, so it can
//! report hashes and sizes the client verifies on download.

use axum::{
    Json,
    body::Bytes,
    extract::{Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use leptiq_core::{
    AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult, code},
    util::{new_id, new_token, now, ok, ok_empty},
};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    DriveConfig,
    model::{self, ACTIVE, DRAFT, FILE, REV_ACTIVE, REV_DRAFT, REV_OBSOLETE},
};

const UPLOAD_TOKEN_TTL: i64 = 3 * 3600;
const DOWNLOAD_TOKEN_TTL: i64 = 30 * 60;
/// Largest encrypted block accepted (4 MiB plaintext plus OpenPGP overhead).
pub const MAX_BLOCK: usize = 8 * 1024 * 1024;

fn new_verification_code() -> String {
    let mut code = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut code);
    STANDARD.encode(code)
}

async fn create_revision(
    state: &AppState,
    link_id: &str,
    client_uid: &Option<String>,
) -> ApiResult<String> {
    let id = new_id();
    sqlx::query(
        "INSERT INTO drive_revisions (id, link_id, state, size, client_uid, verification_code, created) \
         VALUES ($1, $2, 0, 0, $3, $4, $5)",
    )
    .bind(&id)
    .bind(link_id)
    .bind(client_uid)
    .bind(new_verification_code())
    .bind(now())
    .execute(&state.db)
    .await?;
    Ok(id)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateFileReq {
    #[serde(rename = "ParentLinkID")]
    parent_link_id: String,
    name: String,
    hash: String,
    #[serde(rename = "MIMEType")]
    mime_type: String,
    #[serde(rename = "ClientUID", default)]
    client_uid: Option<String>,
    #[serde(default)]
    intended_upload_size: Option<i64>,
    node_key: String,
    node_passphrase: String,
    node_passphrase_signature: String,
    content_key_packet: String,
    content_key_packet_signature: String,
    #[serde(default)]
    signature_address: Option<String>,
    #[serde(default)]
    signature_email: Option<String>,
}

/// Rejects an upload that cannot fit in the user's quota.
async fn check_quota(state: &AppState, volume: &model::Volume, extra: i64) -> ApiResult<()> {
    if volume.used_space + extra.max(0) > state.config.storage_quota_bytes {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            200002,
            "Not enough storage space",
        ));
    }
    Ok(())
}

/// `POST drive/v2/volumes/{v}/files`: a draft file with a draft revision.
pub async fn create_file(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<CreateFileReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    model::active_folder(&state, &v.id, &r.parent_link_id).await?;
    model::check_name_free(&state, &v.id, &r.parent_link_id, &r.hash, None).await?;
    check_quota(&state, &v, r.intended_upload_size.unwrap_or(0)).await?;
    let email = r.signature_address.or(r.signature_email);
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO drive_links (id, volume_id, parent_id, link_type, state, name, name_hash, node_key, \
         node_passphrase, node_passphrase_signature, signature_email, name_signature_email, mime_type, \
         content_key_packet, content_key_packet_signature, client_uid, created, modified) \
         VALUES ($1, $2, $3, 2, 0, $4, $5, $6, $7, $8, $9, $9, $10, $11, $12, $13, $14, $14)",
    )
    .bind(&id)
    .bind(&v.id)
    .bind(&r.parent_link_id)
    .bind(&r.name)
    .bind(&r.hash)
    .bind(&r.node_key)
    .bind(&r.node_passphrase)
    .bind(&r.node_passphrase_signature)
    .bind(&email)
    .bind(&r.mime_type)
    .bind(&r.content_key_packet)
    .bind(&r.content_key_packet_signature)
    .bind(&r.client_uid)
    .bind(t)
    .execute(&state.db)
    .await?;
    let rev = create_revision(&state, &id, &r.client_uid).await?;
    Ok(ok(
        json!({ "File": { "ID": id, "RevisionID": rev, "ClientUID": r.client_uid } }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NewRevisionReq {
    #[serde(rename = "CurrentRevisionID", default)]
    current_revision_id: Option<String>,
    #[serde(rename = "ClientUID", default)]
    client_uid: Option<String>,
}

/// `POST drive/v2/volumes/{v}/files/{l}/revisions`: a new draft revision of
/// an existing file.
pub async fn create_revision_handler(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id)): Path<(String, String)>,
    Json(r): Json<NewRevisionReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    if l.link_type != FILE || l.state != ACTIVE {
        return Err(ApiError::not_found("File"));
    }
    if let Some(cur) = &r.current_revision_id
        && l.active_revision_id.as_deref() != Some(cur.as_str())
    {
        return Err(
            ApiError::new(StatusCode::CONFLICT, code::ALREADY_EXISTS, "File changed").with_details(
                json!({ "ConflictLinkID": l.id, "ConflictRevisionID": l.active_revision_id }),
            ),
        );
    }
    // One draft at a time: report a pending draft as a conflict the client
    // can clean up.
    let draft: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, client_uid FROM drive_revisions WHERE link_id = $1 AND state = 0 LIMIT 1",
    )
    .bind(&l.id)
    .fetch_optional(&state.db)
    .await?;
    if let Some((rid, uid)) = draft {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            code::ALREADY_EXISTS,
            "A draft revision exists",
        )
        .with_details(json!({
            "ConflictLinkID": l.id, "ConflictRevisionID": l.active_revision_id,
            "ConflictDraftRevisionID": rid, "ConflictDraftClientUID": uid,
        })));
    }
    let id = create_revision(&state, &l.id, &r.client_uid).await?;
    Ok(ok(json!({ "Revision": { "ID": id } })))
}

/// `GET .../links/{l}/revisions/{r}/verification`.
pub async fn verification(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id, revision_id)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let rev = model::revision(&state, &l.id, &revision_id).await?;
    Ok(ok(json!({
        "VerificationCode": rev.verification_code,
        "ContentKeyPacket": l.content_key_packet,
    })))
}

fn storage_url(state: &AppState, token: &str) -> String {
    let base = state
        .ext::<DriveConfig>()
        .storage_url
        .trim_end_matches('/')
        .to_string();
    format!("{base}/{token}")
}

async fn new_storage_token(
    state: &AppState,
    kind: &str,
    volume_id: &str,
    revision_id: Option<&str>,
    idx: Option<i64>,
    enc_signature: Option<&str>,
    blob_id: Option<&str>,
    ttl: i64,
) -> ApiResult<String> {
    let token = new_token(48);
    sqlx::query(
        "INSERT INTO drive_storage_tokens (token, kind, volume_id, revision_id, idx, enc_signature, blob_id, expires) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&token)
    .bind(kind)
    .bind(volume_id)
    .bind(revision_id)
    .bind(idx)
    .bind(enc_signature)
    .bind(blob_id)
    .bind(now() + ttl)
    .execute(&state.db)
    .await?;
    Ok(token)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BlockReq {
    index: i64,
    #[serde(default)]
    enc_signature: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ThumbReq {
    #[serde(rename = "Type")]
    thumb_type: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RequestBlocksReq {
    #[serde(rename = "VolumeID")]
    volume_id: String,
    #[serde(rename = "LinkID")]
    link_id: String,
    #[serde(rename = "RevisionID")]
    revision_id: String,
    #[serde(default)]
    block_list: Vec<BlockReq>,
    #[serde(default)]
    thumbnail_list: Vec<ThumbReq>,
}

/// `POST drive/blocks`: upload URLs for a draft revision's blocks/thumbnails.
pub async fn request_blocks(
    State(state): State<AppState>,
    user: AuthUser,
    Json(r): Json<RequestBlocksReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &r.volume_id).await?;
    let l = model::link(&state, &v.id, &r.link_id).await?;
    let rev = model::revision(&state, &l.id, &r.revision_id).await?;
    if rev.state != REV_DRAFT {
        return Err(ApiError::bad_request("Revision is not a draft"));
    }
    let mut blocks = Vec::new();
    for b in &r.block_list {
        let token = new_storage_token(
            &state,
            "block_up",
            &v.id,
            Some(&rev.id),
            Some(b.index),
            b.enc_signature.as_deref(),
            None,
            UPLOAD_TOKEN_TTL,
        )
        .await?;
        let url = storage_url(&state, &token);
        blocks.push(json!({ "Index": b.index, "BareURL": url, "URL": url, "Token": token }));
    }
    let mut thumbs = Vec::new();
    for t in &r.thumbnail_list {
        let token = new_storage_token(
            &state,
            "thumb_up",
            &v.id,
            Some(&rev.id),
            Some(t.thumb_type),
            None,
            None,
            UPLOAD_TOKEN_TTL,
        )
        .await?;
        let url = storage_url(&state, &token);
        thumbs.push(
            json!({ "ThumbnailType": t.thumb_type, "BareURL": url, "URL": url, "Token": token }),
        );
    }
    Ok(ok(
        json!({ "UploadLinks": blocks, "ThumbnailLinks": thumbs }),
    ))
}

type TokenRow = (
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    i64,
);

async fn load_token(state: &AppState, token: &str, headers: &HeaderMap) -> ApiResult<TokenRow> {
    // The SDK sends the token both in the path and the pm-storage-token header.
    let header_token = headers
        .get("pm-storage-token")
        .and_then(|v| v.to_str().ok());
    if header_token.is_some_and(|h| h != token) {
        return Err(ApiError::not_found("Storage token"));
    }
    let row: Option<TokenRow> = sqlx::query_as(
        "SELECT kind, volume_id, revision_id, idx, enc_signature, blob_id, expires \
         FROM drive_storage_tokens WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(&state.db)
    .await?;
    match row {
        Some(r) if r.6 >= now() => Ok(r),
        _ => Err(ApiError::not_found("Storage token")),
    }
}

/// `POST <BareURL>`: block or thumbnail bytes (multipart field `Block`).
pub async fn storage_upload(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
    mut form: Multipart,
) -> ApiResult<Json<Value>> {
    let (kind, volume_id, revision_id, idx, enc_signature, _, _) =
        load_token(&state, &token, &headers).await?;
    let (Some(revision_id), Some(idx)) = (revision_id, idx) else {
        return Err(ApiError::bad_request("Not an upload token"));
    };
    let mut data: Option<Bytes> = None;
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(format!("Invalid upload: {e}")))?
    {
        if field.name() == Some("Block") {
            data = Some(
                field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(format!("Invalid upload: {e}")))?,
            );
        }
    }
    let data = data.ok_or_else(|| ApiError::bad_request("Missing Block"))?;
    if data.len() > MAX_BLOCK {
        return Err(ApiError::bad_request("Block too large"));
    }
    let hash = STANDARD.encode(Sha256::digest(&data));
    let blob_id = new_id();
    state
        .blobs
        .put(&blob_id, &data)
        .await
        .map_err(ApiError::internal)?;
    let size = data.len() as i64;
    let mut tx = state.db.begin().await?;
    let old: Vec<(String,)> = if kind == "block_up" {
        let old =
            sqlx::query_as("SELECT blob_id FROM drive_blocks WHERE revision_id = $1 AND idx = $2")
                .bind(&revision_id)
                .bind(idx)
                .fetch_all(&mut *tx)
                .await?;
        sqlx::query("DELETE FROM drive_blocks WHERE revision_id = $1 AND idx = $2")
            .bind(&revision_id)
            .bind(idx)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO drive_blocks (revision_id, idx, hash, size, enc_signature, blob_id) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&revision_id)
        .bind(idx)
        .bind(&hash)
        .bind(size)
        .bind(&enc_signature)
        .bind(&blob_id)
        .execute(&mut *tx)
        .await?;
        old
    } else if kind == "thumb_up" {
        let old = sqlx::query_as(
            "SELECT blob_id FROM drive_thumbnails WHERE revision_id = $1 AND thumb_type = $2",
        )
        .bind(&revision_id)
        .bind(idx)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM drive_thumbnails WHERE revision_id = $1 AND thumb_type = $2")
            .bind(&revision_id)
            .bind(idx)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO drive_thumbnails (id, revision_id, thumb_type, hash, size, blob_id) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(new_id())
        .bind(&revision_id)
        .bind(idx)
        .bind(&hash)
        .bind(size)
        .bind(&blob_id)
        .execute(&mut *tx)
        .await?;
        old
    } else {
        return Err(ApiError::bad_request("Not an upload token"));
    };
    tx.commit().await?;
    for (b,) in old {
        state.blobs.delete(&b).await;
    }
    tracing::debug!("drive: stored {kind} {idx} of revision {revision_id} in volume {volume_id}");
    Ok(ok_empty())
}

/// `GET <BareURL>`: block or thumbnail bytes.
pub async fn storage_download(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (kind, _, _, _, _, blob_id, _) = load_token(&state, &token, &headers).await?;
    let Some(blob_id) = blob_id.filter(|_| kind == "download") else {
        return Err(ApiError::not_found("Block"));
    };
    let data = state
        .blobs
        .get(&blob_id)
        .await
        .map_err(|_| ApiError::not_found("Block"))?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], data).into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CommitReq {
    #[serde(default)]
    manifest_signature: Option<String>,
    #[serde(default)]
    signature_address: Option<String>,
    #[serde(rename = "XAttr", default)]
    xattr: Option<String>,
    #[serde(default)]
    checksum_verified: Option<bool>,
}

/// `PUT drive/v2/volumes/{v}/files/{l}/revisions/{r}`: commit a draft
/// revision; it becomes the file's active revision.
pub async fn commit_revision(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id, revision_id)): Path<(String, String, String)>,
    Json(r): Json<CommitReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let rev = model::revision(&state, &l.id, &revision_id).await?;
    if rev.state != REV_DRAFT {
        return Err(ApiError::bad_request("Revision is not a draft"));
    }
    let (blocks,): (i64,) =
        sqlx::query_as("SELECT COALESCE(SUM(size), 0) FROM drive_blocks WHERE revision_id = $1")
            .bind(&rev.id)
            .fetch_one(&state.db)
            .await?;
    let (thumbs,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(size), 0) FROM drive_thumbnails WHERE revision_id = $1",
    )
    .bind(&rev.id)
    .fetch_one(&state.db)
    .await?;
    let size = blocks + thumbs;
    check_quota(&state, &v, size).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE drive_revisions SET state = $1 WHERE link_id = $2 AND state = $3")
        .bind(REV_OBSOLETE)
        .bind(&l.id)
        .bind(REV_ACTIVE)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE drive_revisions SET state = $1, size = $2, manifest_signature = $3, xattr = $4, \
         signature_email = $5, checksum_verified = $6 WHERE id = $7",
    )
    .bind(REV_ACTIVE)
    .bind(size)
    .bind(&r.manifest_signature)
    .bind(&r.xattr)
    .bind(&r.signature_address)
    .bind(r.checksum_verified.unwrap_or(false) as i64)
    .bind(&rev.id)
    .execute(&mut *tx)
    .await?;
    let was_draft = l.state == DRAFT;
    sqlx::query(
        "UPDATE drive_links SET active_revision_id = $1, state = $2, modified = $3 WHERE id = $4",
    )
    .bind(&rev.id)
    .bind(ACTIVE)
    .bind(now())
    .bind(&l.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE drive_volumes SET used_space = used_space + $1, modified = $2 WHERE id = $3",
    )
    .bind(size)
    .bind(now())
    .bind(&v.id)
    .execute(&mut *tx)
    .await?;
    model::push_event(
        &mut tx,
        &v.id,
        if was_draft {
            model::EVENT_CREATE
        } else {
            model::EVENT_UPDATE
        },
        &l.id,
        l.parent_id.as_deref(),
        false,
    )
    .await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RevisionQuery {
    page_size: Option<i64>,
    from_block_index: Option<i64>,
    no_block_urls: Option<bool>,
}

/// `GET drive/v2/volumes/{v}/files/{l}/revisions/{r}`: revision metadata and
/// a page of block download URLs (the client pages until no blocks are left).
pub async fn get_revision(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id, revision_id)): Path<(String, String, String)>,
    Query(q): Query<RevisionQuery>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let rev = model::revision(&state, &l.id, &revision_id).await?;
    let mut json = model::revision_json(&state, &rev, true).await?;
    let mut blocks_json = Vec::new();
    if !q.no_block_urls.unwrap_or(false) {
        let from = q.from_block_index.unwrap_or(1);
        let page = q.page_size.unwrap_or(20).clamp(1, 500);
        let blocks: Vec<(i64, String, i64, Option<String>, String)> = sqlx::query_as(
            "SELECT idx, hash, size, enc_signature, blob_id FROM drive_blocks \
             WHERE revision_id = $1 AND idx >= $2 ORDER BY idx LIMIT $3",
        )
        .bind(&rev.id)
        .bind(from)
        .bind(page)
        .fetch_all(&state.db)
        .await?;
        for (idx, hash, size, sig, blob) in blocks {
            let token = new_storage_token(
                &state,
                "download",
                &v.id,
                None,
                None,
                None,
                Some(&blob),
                DOWNLOAD_TOKEN_TTL,
            )
            .await?;
            let url = storage_url(&state, &token);
            blocks_json.push(json!({
                "Index": idx, "Hash": hash, "Size": size, "Token": token, "BareURL": url, "URL": url,
                "EncSignature": sig, "SignatureEmail": rev.signature_email,
            }));
        }
    }
    json["Blocks"] = json!(blocks_json);
    Ok(ok(json!({ "Revision": json })))
}

/// `GET drive/v2/volumes/{v}/files/{l}/revisions`: committed revisions.
pub async fn list_revisions(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let revs: Vec<model::Revision> = sqlx::query_as(leptiq_core::sql!(
        "SELECT {} FROM drive_revisions WHERE link_id = $1 AND state IN (1, 2) ORDER BY created DESC",
        model::REVISION_COLS
    ))
    .bind(&l.id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::new();
    for r in &revs {
        out.push(model::revision_json(&state, r, true).await?);
    }
    Ok(ok(json!({ "Revisions": out })))
}

/// `DELETE .../revisions/{r}`: delete an obsolete revision (or a draft).
pub async fn delete_revision(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id, revision_id)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let rev = model::revision(&state, &l.id, &revision_id).await?;
    if rev.state == REV_ACTIVE {
        return Err(ApiError::bad_request(
            "The active revision cannot be deleted",
        ));
    }
    let blobs: Vec<(String,)> = sqlx::query_as(
        "SELECT blob_id FROM drive_blocks WHERE revision_id = $1 UNION ALL \
         SELECT blob_id FROM drive_thumbnails WHERE revision_id = $1",
    )
    .bind(&rev.id)
    .fetch_all(&state.db)
    .await?;
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM drive_revisions WHERE id = $1")
        .bind(&rev.id)
        .execute(&mut *tx)
        .await?;
    if rev.state == REV_OBSOLETE {
        sqlx::query("UPDATE drive_volumes SET used_space = used_space - $1 WHERE id = $2")
            .bind(rev.size)
            .bind(&v.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    for (b,) in blobs {
        state.blobs.delete(&b).await;
    }
    Ok(ok_empty())
}

/// `POST .../revisions/{r}/restore`: make an older revision active again.
pub async fn restore_revision(
    State(state): State<AppState>,
    user: AuthUser,
    Path((volume_id, link_id, revision_id)): Path<(String, String, String)>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let l = model::link(&state, &v.id, &link_id).await?;
    let rev = model::revision(&state, &l.id, &revision_id).await?;
    if rev.state != REV_OBSOLETE {
        return Err(ApiError::bad_request(
            "Only an older revision can be restored",
        ));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE drive_revisions SET state = 2 WHERE link_id = $1 AND state = 1")
        .bind(&l.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE drive_revisions SET state = 1 WHERE id = $1")
        .bind(&rev.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE drive_links SET active_revision_id = $1, modified = $2 WHERE id = $3")
        .bind(&rev.id)
        .bind(now())
        .bind(&l.id)
        .execute(&mut *tx)
        .await?;
    model::push_event(
        &mut tx,
        &v.id,
        model::EVENT_UPDATE,
        &l.id,
        l.parent_id.as_deref(),
        false,
    )
    .await?;
    tx.commit().await?;
    Ok(ok_empty())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ThumbnailsReq {
    #[serde(rename = "ThumbnailIDs")]
    thumbnail_ids: Vec<String>,
}

/// `POST drive/volumes/{v}/thumbnails`: download URLs for thumbnails.
pub async fn thumbnails(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
    Json(r): Json<ThumbnailsReq>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    let mut ok_list = Vec::new();
    let mut errors = Vec::new();
    for id in r.thumbnail_ids.iter().take(30) {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT t.blob_id FROM drive_thumbnails t JOIN drive_revisions r ON r.id = t.revision_id \
             JOIN drive_links l ON l.id = r.link_id WHERE t.id = $1 AND l.volume_id = $2",
        )
        .bind(id)
        .bind(&v.id)
        .fetch_optional(&state.db)
        .await?;
        match row {
            Some((blob,)) => {
                let token =
                    new_storage_token(&state, "download", &v.id, None, None, None, Some(&blob), DOWNLOAD_TOKEN_TTL)
                        .await?;
                ok_list.push(json!({ "ThumbnailID": id, "BareURL": storage_url(&state, &token), "Token": token }));
            }
            None => errors.push(json!({ "ThumbnailID": id, "Error": "Thumbnail not found", "Code": code::NOT_FOUND })),
        }
    }
    Ok(ok(json!({ "Thumbnails": ok_list, "Errors": errors })))
}

/// Removes expired storage tokens (background job).
pub async fn cleanup(state: &AppState) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM drive_storage_tokens WHERE expires < $1")
        .bind(now())
        .execute(&state.db)
        .await?;
    Ok(())
}

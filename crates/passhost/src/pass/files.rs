//! File attachments. Files are uploaded as encrypted chunks to a pending file,
//! then linked to an item revision together with the file key (encrypted
//! with the item key). The server only ever sees ciphertext.

use std::path::PathBuf;

use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, State},
    http::header,
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AnyConnection;

use super::{
    items::{self, FLAG_HAD_FILES, FLAG_HAS_FILES},
    shares,
};
use crate::{
    app::AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult, code},
    events::{self, kind},
    util::{new_id, now, ok},
};

/// Maximum size of a single encrypted chunk.
pub const MAX_CHUNK: usize = 16 * 1024 * 1024;
pub const MAX_CHUNKS: i64 = 10_000;

pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(root: &str) -> anyhow::Result<Self> {
        let root = PathBuf::from(root).join("blobs");
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    fn path(&self, key: &str) -> PathBuf {
        // Keys are server-generated IDs; still refuse anything path-like.
        let safe: String = key
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        let (a, b) = (
            safe.get(0..2).unwrap_or("00"),
            safe.get(2..4).unwrap_or("00"),
        );
        self.root.join(a).join(b).join(safe)
    }

    pub async fn put(&self, key: &str, data: &[u8]) -> std::io::Result<()> {
        let p = self.path(key);
        if let Some(dir) = p.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let tmp = p.with_extension("tmp");
        tokio::fs::write(&tmp, data).await?;
        tokio::fs::rename(tmp, p).await
    }

    pub async fn get(&self, key: &str) -> std::io::Result<Vec<u8>> {
        tokio::fs::read(self.path(key)).await
    }

    pub async fn delete(&self, key: &str) {
        let _ = tokio::fs::remove_file(self.path(key)).await;
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreatePendingReq {
    pub metadata: String,
    pub chunk_count: i64,
    pub encryption_version: Option<i64>,
}

pub async fn create_pending(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreatePendingReq>,
) -> ApiResult<Json<Value>> {
    if req.chunk_count < 1 || req.chunk_count > MAX_CHUNKS {
        return Err(ApiError::bad_request("Invalid chunk count"));
    }
    let id = new_id();
    let t = now();
    sqlx::query(
        "INSERT INTO files (id, user_id, metadata, chunk_count, total_size, encryption_version, created, modified) \
         VALUES ($1,$2,$3,$4,0,$5,$6,$6)",
    )
    .bind(&id)
    .bind(&user.user_id)
    .bind(&req.metadata)
    .bind(req.chunk_count)
    .bind(req.encryption_version.unwrap_or(1))
    .bind(t)
    .execute(&state.db)
    .await?;
    Ok(ok(json!({ "File": { "FileID": id } })))
}

async fn own_pending(state: &AppState, user_id: &str, file_id: &str) -> ApiResult<(i64, i64)> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT chunk_count, linked FROM files WHERE id = $1 AND user_id = $2 AND orphaned = 0",
    )
    .bind(file_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    row.ok_or_else(|| ApiError::not_found("File"))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct MetadataReq {
    pub metadata: String,
}

pub async fn update_pending_metadata(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    Json(req): Json<MetadataReq>,
) -> ApiResult<Json<Value>> {
    own_pending(&state, &user.user_id, &file_id).await?;
    sqlx::query("UPDATE files SET metadata = $1, modified = $2 WHERE id = $3")
        .bind(&req.metadata)
        .bind(now())
        .bind(&file_id)
        .execute(&state.db)
        .await?;
    Ok(ok(json!({ "File": { "FileID": file_id } })))
}

/// `POST file/{id}/chunk` (multipart: `ChunkIndex`, `ChunkData`).
pub async fn upload_chunk(
    State(state): State<AppState>,
    user: AuthUser,
    Path(file_id): Path<String>,
    mut form: Multipart,
) -> ApiResult<Json<Value>> {
    let (chunk_count, linked) = own_pending(&state, &user.user_id, &file_id).await?;
    if linked != 0 {
        return Err(ApiError::bad_request("File already linked"));
    }
    let mut index: Option<i64> = None;
    let mut data: Option<Vec<u8>> = None;
    while let Some(field) = form
        .next_field()
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?
    {
        match field.name() {
            Some("ChunkIndex") => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                index = text.trim().parse().ok();
            }
            Some("ChunkData") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::bad_request(e.to_string()))?;
                if bytes.len() > MAX_CHUNK {
                    return Err(ApiError::bad_request("Chunk too large"));
                }
                data = Some(bytes.to_vec());
            }
            _ => {}
        }
    }
    let index = index.ok_or_else(|| ApiError::bad_request("ChunkIndex required"))?;
    let data = data.ok_or_else(|| ApiError::bad_request("ChunkData required"))?;
    if index < 0 || index >= chunk_count {
        return Err(ApiError::bad_request("Chunk index out of range"));
    }
    let (used,): (i64,) = sqlx::query_as("SELECT used_space FROM users WHERE id = $1")
        .bind(&user.user_id)
        .fetch_one(&state.db)
        .await?;
    if used + data.len() as i64 > state.config.file_quota_bytes {
        return Err(ApiError::new(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            code::QUOTA_EXCEEDED,
            "Storage quota exceeded",
        ));
    }
    let chunk_id = new_id();
    state
        .blobs
        .put(&chunk_id, &data)
        .await
        .map_err(ApiError::internal)?;
    let size = data.len() as i64;
    let mut tx = state.db.begin().await?;
    let old: Option<(String, i64)> = sqlx::query_as(
        "SELECT chunk_id, size FROM file_chunks WHERE file_id = $1 AND chunk_index = $2",
    )
    .bind(&file_id)
    .bind(index)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((_, old_size)) = &old {
        sqlx::query("DELETE FROM file_chunks WHERE file_id = $1 AND chunk_index = $2")
            .bind(&file_id)
            .bind(index)
            .execute(&mut *tx)
            .await?;
        adjust_usage(&mut tx, &user.user_id, -old_size).await?;
        sqlx::query("UPDATE files SET total_size = total_size - $1 WHERE id = $2")
            .bind(old_size)
            .bind(&file_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO file_chunks (file_id, chunk_index, chunk_id, size) VALUES ($1,$2,$3,$4)",
    )
    .bind(&file_id)
    .bind(index)
    .bind(&chunk_id)
    .bind(size)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE files SET total_size = total_size + $1, modified = $2 WHERE id = $3")
        .bind(size)
        .bind(now())
        .bind(&file_id)
        .execute(&mut *tx)
        .await?;
    adjust_usage(&mut tx, &user.user_id, size).await?;
    tx.commit().await?;
    if let Some((old_chunk, _)) = old {
        state.blobs.delete(&old_chunk).await;
    }
    Ok(ok(json!({})))
}

async fn adjust_usage(conn: &mut AnyConnection, user_id: &str, delta: i64) -> ApiResult<()> {
    sqlx::query("UPDATE users SET used_space = used_space + $1 WHERE id = $2")
        .bind(delta)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `ItemFileOutput` JSON.
async fn file_json(conn: &mut AnyConnection, item_id: &str, file_id: &str) -> ApiResult<Value> {
    let (size, metadata, enc, file_key, rotation, added, removed, created, modified): (
        i64, String, i64, String, i64, i64, Option<i64>, i64, i64,
    ) = sqlx::query_as(
        "SELECT f.total_size, f.metadata, f.encryption_version, i.file_key, i.key_rotation, i.revision_added, \
         i.revision_removed, i.created, i.modified FROM files f JOIN item_files i ON i.file_id = f.id \
         WHERE i.item_id = $1 AND f.id = $2",
    )
    .bind(item_id)
    .bind(file_id)
    .fetch_one(&mut *conn)
    .await?;
    let chunks: Vec<(String, i64, i64)> =
        sqlx::query_as("SELECT chunk_id, chunk_index, size FROM file_chunks WHERE file_id = $1 ORDER BY chunk_index")
            .bind(file_id)
            .fetch_all(&mut *conn)
            .await?;
    let chunks: Vec<Value> = chunks
        .into_iter()
        .map(|(id, idx, size)| json!({ "ChunkID": id, "Index": idx, "Size": size }))
        .collect();
    Ok(json!({
        "FileID": file_id,
        "Size": size,
        "Metadata": metadata,
        "FileKey": file_key,
        "ItemKeyRotation": rotation,
        "Chunks": chunks,
        "EncryptionVersion": enc,
        "RevisionAdded": added,
        "RevisionRemoved": removed,
        "PersistentFileUID": file_id,
        "CreateTime": created,
        "ModifyTime": modified,
    }))
}

/// Bumps the item revision (attachments changes create a new revision).
async fn bump_revision(conn: &mut AnyConnection, item_id: &str) -> ApiResult<i64> {
    let t = now();
    sqlx::query("UPDATE items SET revision = revision + 1, modify_time = $1, revision_time = $1 WHERE id = $2")
        .bind(t)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO item_revisions (item_id, revision, content_format_version, content, key_rotation, state, flags, modify_time, revision_time) \
         SELECT id, revision, content_format_version, content, key_rotation, state, flags, modify_time, revision_time FROM items WHERE id = $1",
    )
    .bind(item_id)
    .execute(&mut *conn)
    .await?;
    let (rev,): (i64,) = sqlx::query_as("SELECT revision FROM items WHERE id = $1")
        .bind(item_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(rev)
}

async fn refresh_file_flags(conn: &mut AnyConnection, item_id: &str) -> ApiResult<()> {
    let (active,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM item_files WHERE item_id = $1 AND revision_removed IS NULL",
    )
    .bind(item_id)
    .fetch_one(&mut *conn)
    .await?;
    let (flags,): (i64,) = sqlx::query_as("SELECT flags FROM items WHERE id = $1")
        .bind(item_id)
        .fetch_one(&mut *conn)
        .await?;
    let mut f = flags | FLAG_HAD_FILES;
    if active > 0 {
        f |= FLAG_HAS_FILES
    } else {
        f &= !FLAG_HAS_FILES
    }
    sqlx::query("UPDATE items SET flags = $1 WHERE id = $2")
        .bind(f)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE item_revisions SET flags = $1 WHERE item_id = $2 AND revision = (SELECT revision FROM items WHERE id = $2)")
        .bind(f)
        .bind(item_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FileToAdd {
    #[serde(rename = "FileID")]
    pub file_id: String,
    pub file_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LinkReq {
    pub item_revision: i64,
    #[serde(default)]
    pub files_to_add: Vec<FileToAdd>,
    #[serde(default)]
    pub files_to_remove: Vec<String>,
}

/// `POST share/{}/item/{}/link_files`.
pub async fn link_files(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<LinkReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = items::load(&mut tx, &share, &item_id).await?;
    if item.revision != req.item_revision {
        return Err(ApiError::new(
            axum::http::StatusCode::CONFLICT,
            code::REVISION_CONFLICT,
            "Item has been modified",
        ));
    }
    let rev = bump_revision(&mut tx, &item.id).await?;
    let t = now();
    for f in &req.files_to_add {
        let row: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT chunk_count, linked, (SELECT COUNT(*) FROM file_chunks c WHERE c.file_id = files.id) FROM files \
             WHERE id = $1 AND user_id = $2 AND orphaned = 0",
        )
        .bind(&f.file_id)
        .bind(&user.user_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((count, linked, uploaded)) = row else {
            return Err(ApiError::not_found("File"));
        };
        if linked != 0 {
            return Err(ApiError::bad_request("File already linked"));
        }
        if uploaded != count {
            return Err(ApiError::bad_request("File upload is incomplete"));
        }
        sqlx::query("UPDATE files SET linked = 1, modified = $1 WHERE id = $2")
            .bind(t)
            .bind(&f.file_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO item_files (item_id, file_id, file_key, key_rotation, revision_added, created, modified) \
             VALUES ($1,$2,$3,$4,$5,$6,$6)",
        )
        .bind(&item.id)
        .bind(&f.file_id)
        .bind(&f.file_key)
        .bind(item.key_rotation)
        .bind(rev)
        .bind(t)
        .execute(&mut *tx)
        .await?;
    }
    for fid in &req.files_to_remove {
        sqlx::query("UPDATE item_files SET revision_removed = $1, modified = $2 WHERE item_id = $3 AND file_id = $4 AND revision_removed IS NULL")
            .bind(rev)
            .bind(t)
            .bind(&item.id)
            .bind(fid)
            .execute(&mut *tx)
            .await?;
    }
    refresh_file_flags(&mut tx, &item.id).await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let item = items::load(&mut tx, &share, &item.id).await?;
    let out = items::item_json(&mut tx, &share, &item).await?;
    tx.commit().await?;
    Ok(ok(json!({ "Item": out })))
}

async fn list_files(
    state: &AppState,
    user: &AuthUser,
    share_id: &str,
    item_id: &str,
    all: bool,
) -> ApiResult<Value> {
    let share = shares::load(state, &user.user_id, share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = items::load(&mut conn, &share, item_id).await?;
    let filter = if all {
        ""
    } else {
        " AND revision_removed IS NULL"
    };
    let ids: Vec<(String,)> = sqlx::query_as(crate::sql!(
        "SELECT file_id FROM item_files WHERE item_id = $1{filter} ORDER BY created"
    ))
    .bind(&item.id)
    .fetch_all(&mut *conn)
    .await?;
    let mut files = vec![];
    for (fid,) in ids {
        files.push(file_json(&mut conn, &item.id, &fid).await?);
    }
    Ok(json!({ "Files": { "Files": files, "Total": files.len(), "LastID": null } }))
}

pub async fn item_files(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        list_files(&state, &user, &share_id, &item_id, false).await?
    ))
}

pub async fn item_revision_files(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    Ok(ok(
        list_files(&state, &user, &share_id, &item_id, true).await?
    ))
}

fn raw(data: Vec<u8>) -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(data))
        .expect("valid response")
}

pub async fn download_chunk(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id, file_id, chunk_id)): Path<(String, String, String, String)>,
) -> ApiResult<Response> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let mut conn = state.db.acquire().await?;
    let item = items::load(&mut conn, &share, &item_id).await?;
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT c.chunk_id FROM file_chunks c JOIN item_files i ON i.file_id = c.file_id \
         WHERE i.item_id = $1 AND c.file_id = $2 AND c.chunk_id = $3",
    )
    .bind(&item.id)
    .bind(&file_id)
    .bind(&chunk_id)
    .fetch_optional(&mut *conn)
    .await?;
    drop(conn);
    let (chunk,) = row.ok_or_else(|| ApiError::not_found("Chunk"))?;
    let data = state
        .blobs
        .get(&chunk)
        .await
        .map_err(|_| ApiError::not_found("Chunk"))?;
    Ok(raw(data))
}

pub async fn update_metadata(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id, file_id)): Path<(String, String, String)>,
    Json(req): Json<MetadataReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = items::load(&mut tx, &share, &item_id).await?;
    let r = sqlx::query("UPDATE files SET metadata = $1, modified = $2 WHERE id = $3 AND id IN (SELECT file_id FROM item_files WHERE item_id = $4)")
        .bind(&req.metadata)
        .bind(now())
        .bind(&file_id)
        .bind(&item.id)
        .execute(&mut *tx)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("File"));
    }
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let out = file_json(&mut tx, &item.id, &file_id).await?;
    tx.commit().await?;
    Ok(ok(json!({ "File": out })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestoreReq {
    pub file_key: String,
    pub item_key_rotation: i64,
}

async fn restore_one(
    conn: &mut AnyConnection,
    item_id: &str,
    file_id: &str,
    file_key: &str,
    rotation: i64,
    rev: i64,
) -> ApiResult<()> {
    let r = sqlx::query(
        "UPDATE item_files SET revision_removed = NULL, revision_added = $1, file_key = $2, key_rotation = $3, modified = $4 \
         WHERE item_id = $5 AND file_id = $6",
    )
    .bind(rev)
    .bind(file_key)
    .bind(rotation)
    .bind(now())
    .bind(item_id)
    .bind(file_id)
    .execute(&mut *conn)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("File"));
    }
    Ok(())
}

pub async fn restore(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id, file_id)): Path<(String, String, String)>,
    Json(req): Json<RestoreReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = items::load(&mut tx, &share, &item_id).await?;
    let rev = bump_revision(&mut tx, &item.id).await?;
    restore_one(
        &mut tx,
        &item.id,
        &file_id,
        &req.file_key,
        req.item_key_rotation,
        rev,
    )
    .await?;
    refresh_file_flags(&mut tx, &item.id).await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let item = items::load(&mut tx, &share, &item.id).await?;
    let item_out = items::item_json(&mut tx, &share, &item).await?;
    let file_out = file_json(&mut tx, &item.id, &file_id).await?;
    tx.commit().await?;
    Ok(ok(
        json!({ "Result": { "Item": item_out, "File": file_out } }),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestoreOne {
    #[serde(rename = "FileID")]
    pub file_id: String,
    pub file_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RestoreBatchReq {
    pub files_to_restore: Vec<RestoreOne>,
    pub item_key_rotation: i64,
}

pub async fn restore_batch(
    State(state): State<AppState>,
    user: AuthUser,
    Path((share_id, item_id)): Path<(String, String)>,
    Json(req): Json<RestoreBatchReq>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    share.require_write()?;
    let mut tx = state.db.begin().await?;
    let item = items::load(&mut tx, &share, &item_id).await?;
    let rev = bump_revision(&mut tx, &item.id).await?;
    for f in &req.files_to_restore {
        restore_one(
            &mut tx,
            &item.id,
            &f.file_id,
            &f.file_key,
            req.item_key_rotation,
            rev,
        )
        .await?;
    }
    refresh_file_flags(&mut tx, &item.id).await?;
    events::push_item(&mut tx, &item.vault_id, &item.id, kind::ITEM_UPDATED).await?;
    let item = items::load(&mut tx, &share, &item.id).await?;
    let item_out = items::item_json(&mut tx, &share, &item).await?;
    let mut files = vec![];
    for f in &req.files_to_restore {
        files.push(file_json(&mut tx, &item.id, &f.file_id).await?);
    }
    tx.commit().await?;
    Ok(ok(
        json!({ "Result": { "Item": item_out, "Files": files } }),
    ))
}

/// `GET vault/usage/{shareId}`.
pub async fn vault_usage(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let share = shares::load(&state, &user.user_id, &share_id).await?;
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT i.item_id, CAST(SUM(f.total_size) AS BIGINT) FROM item_files i JOIN files f ON f.id = i.file_id JOIN items it ON it.id = i.item_id \
         WHERE it.vault_id = $1 GROUP BY i.item_id ORDER BY SUM(f.total_size) DESC",
    )
    .bind(&share.vault_id)
    .fetch_all(&state.db)
    .await?;
    let total: i64 = rows.iter().map(|r| r.1).sum();
    let largest: Vec<Value> = rows
        .iter()
        .take(10)
        .map(|(i, s)| json!({ "ItemID": i, "TotalSize": s }))
        .collect();
    Ok(ok(
        json!({ "VaultFileStorageInfo": { "VaultID": share.vault_id, "TotalSize": total, "LargestFiles": largest } }),
    ))
}

/// Files visible through a public link (files of the linked revision).
async fn public_link_item(state: &AppState, token: &str) -> ApiResult<(String, i64)> {
    let row: Option<(String, i64, i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT item_id, revision, expiration_time, read_count, max_read_count FROM public_links WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(&state.db)
    .await?;
    let Some((item_id, rev, exp, reads, max)) = row else {
        return Err(ApiError::not_found("Link"));
    };
    // The content read counts once; files may be fetched right after it.
    if exp < now() || max.map(|m| reads > m).unwrap_or(false) {
        return Err(ApiError::not_found("Link"));
    }
    Ok((item_id, rev))
}

pub async fn public_files(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<Value>> {
    let (item_id, rev) = public_link_item(&state, &token).await?;
    let mut conn = state.db.acquire().await?;
    let ids: Vec<(String,)> = sqlx::query_as(
        "SELECT file_id FROM item_files WHERE item_id = $1 AND revision_added <= $2 AND (revision_removed IS NULL OR revision_removed > $2)",
    )
    .bind(&item_id)
    .bind(rev)
    .fetch_all(&mut *conn)
    .await?;
    let mut files = vec![];
    for (fid,) in ids {
        files.push(file_json(&mut conn, &item_id, &fid).await?);
    }
    Ok(ok(
        json!({ "Files": { "Files": files, "Total": files.len(), "LastID": null } }),
    ))
}

pub async fn public_chunk(
    State(state): State<AppState>,
    Path((token, file_id, chunk_id)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let (item_id, _) = public_link_item(&state, &token).await?;
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT c.chunk_id FROM file_chunks c JOIN item_files i ON i.file_id = c.file_id \
         WHERE i.item_id = $1 AND c.file_id = $2 AND c.chunk_id = $3",
    )
    .bind(&item_id)
    .bind(&file_id)
    .bind(&chunk_id)
    .fetch_optional(&state.db)
    .await?;
    let (chunk,) = row.ok_or_else(|| ApiError::not_found("Chunk"))?;
    let data = state
        .blobs
        .get(&chunk)
        .await
        .map_err(|_| ApiError::not_found("Chunk"))?;
    Ok(raw(data))
}

/// Garbage-collects orphaned files and abandoned uploads (> 1 day unlinked).
pub async fn cleanup(state: &AppState) -> anyhow::Result<()> {
    let stale: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT id, user_id, total_size FROM files WHERE orphaned = 1 OR (linked = 0 AND created < $1) \
         OR (linked = 1 AND id NOT IN (SELECT file_id FROM item_files))",
    )
    .bind(now() - 86400)
    .fetch_all(&state.db)
    .await?;
    for (id, user_id, size) in stale {
        let chunks: Vec<(String,)> =
            sqlx::query_as("SELECT chunk_id FROM file_chunks WHERE file_id = $1")
                .bind(&id)
                .fetch_all(&state.db)
                .await?;
        let mut tx = state.db.begin().await?;
        sqlx::query("DELETE FROM files WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE users SET used_space = CASE WHEN used_space > $1 THEN used_space - $1 ELSE 0 END WHERE id = $2")
            .bind(size)
            .bind(&user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        for (c,) in chunks {
            state.blobs.delete(&c).await;
        }
    }
    Ok(())
}

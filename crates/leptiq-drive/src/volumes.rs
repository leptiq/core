//! Volumes, their root share and root folder (My files and Photos).

use axum::{
    Json,
    extract::{Path, State},
};
use leptiq_core::{
    AppState,
    auth::AuthUser,
    error::{ApiError, ApiResult},
    util::{new_id, now, ok},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::model::{self, Share, Volume};

/// Email of one of the user's addresses (the share creator).
async fn address_email(state: &AppState, user_id: &str, address_id: &str) -> ApiResult<String> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT email FROM addresses WHERE id = $1 AND user_id = $2")
            .bind(address_id)
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    row.map(|r| r.0)
        .ok_or_else(|| ApiError::bad_request("Unknown address"))
}

struct NewVolume<'a> {
    volume_type: i64,
    share_type: i64,
    address_id: &'a str,
    address_key_id: &'a str,
    share_key: &'a str,
    share_passphrase: &'a str,
    share_passphrase_signature: &'a str,
    folder_name: &'a str,
    folder_key: &'a str,
    folder_passphrase: &'a str,
    folder_passphrase_signature: &'a str,
    folder_hash_key: &'a str,
}

async fn create_volume(state: &AppState, user: &AuthUser, v: NewVolume<'_>) -> ApiResult<Volume> {
    if model::user_volume(state, &user.user_id, v.volume_type)
        .await?
        .is_some()
    {
        return Err(ApiError::conflict("Volume already exists"));
    }
    let email = address_email(state, &user.user_id, v.address_id).await?;
    let (volume_id, share_id, link_id) = (new_id(), new_id(), new_id());
    let t = now();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO drive_volumes (id, user_id, volume_type, share_id, root_link_id, used_space, created, modified) \
         VALUES ($1, $2, $3, $4, $5, 0, $6, $6)",
    )
    .bind(&volume_id)
    .bind(&user.user_id)
    .bind(v.volume_type)
    .bind(&share_id)
    .bind(&link_id)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO drive_shares (id, volume_id, share_type, link_id, address_id, address_key_id, creator_email, \
         share_key, passphrase, passphrase_signature, created, modified) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)",
    )
    .bind(&share_id)
    .bind(&volume_id)
    .bind(v.share_type)
    .bind(&link_id)
    .bind(v.address_id)
    .bind(v.address_key_id)
    .bind(&email)
    .bind(v.share_key)
    .bind(v.share_passphrase)
    .bind(v.share_passphrase_signature)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO drive_links (id, volume_id, parent_id, link_type, state, name, name_hash, node_key, \
         node_passphrase, node_passphrase_signature, node_hash_key, signature_email, name_signature_email, \
         created, modified) VALUES ($1, $2, NULL, 1, 1, $3, NULL, $4, $5, $6, $7, $8, $8, $9, $9)",
    )
    .bind(&link_id)
    .bind(&volume_id)
    .bind(v.folder_name)
    .bind(v.folder_key)
    .bind(v.folder_passphrase)
    .bind(v.folder_passphrase_signature)
    .bind(v.folder_hash_key)
    .bind(&email)
    .bind(t)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    model::volume(state, &user.user_id, &volume_id).await
}

fn volume_json(state: &AppState, v: &Volume) -> Value {
    json!({
        "ID": v.id,
        "VolumeID": v.id,
        "CreationTime": v.created,
        "CreateTime": v.created,
        "ModifyTime": v.modified,
        "MaxSpace": state.config.storage_quota_bytes,
        "UsedSpace": v.used_space,
        "DownloadedBytes": 0,
        "UploadedBytes": 0,
        "State": 1,
        "Type": v.volume_type,
        "Share": { "ShareID": v.share_id, "ID": v.share_id, "LinkID": v.root_link_id },
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreateVolumeReq {
    #[serde(rename = "AddressID")]
    address_id: String,
    #[serde(rename = "AddressKeyID")]
    address_key_id: String,
    share_key: String,
    share_passphrase: String,
    share_passphrase_signature: String,
    folder_name: String,
    folder_key: String,
    folder_passphrase: String,
    folder_passphrase_signature: String,
    folder_hash_key: String,
}

/// `POST drive/volumes`: the user's main volume ("My files").
pub async fn create(
    State(state): State<AppState>,
    user: AuthUser,
    Json(r): Json<CreateVolumeReq>,
) -> ApiResult<Json<Value>> {
    let v = create_volume(
        &state,
        &user,
        NewVolume {
            volume_type: model::VOLUME_REGULAR,
            share_type: 1,
            address_id: &r.address_id,
            address_key_id: &r.address_key_id,
            share_key: &r.share_key,
            share_passphrase: &r.share_passphrase,
            share_passphrase_signature: &r.share_passphrase_signature,
            folder_name: &r.folder_name,
            folder_key: &r.folder_key,
            folder_passphrase: &r.folder_passphrase,
            folder_passphrase_signature: &r.folder_passphrase_signature,
            folder_hash_key: &r.folder_hash_key,
        },
    )
    .await?;
    Ok(ok(json!({ "Volume": volume_json(&state, &v) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PhotoShareReq {
    #[serde(rename = "AddressID")]
    address_id: String,
    #[serde(rename = "AddressKeyID")]
    address_key_id: String,
    key: String,
    passphrase: String,
    passphrase_signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PhotoLinkReq {
    name: String,
    node_key: String,
    node_passphrase: String,
    node_passphrase_signature: String,
    node_hash_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreatePhotosReq {
    share: PhotoShareReq,
    link: PhotoLinkReq,
}

/// `POST drive/photos/volumes`: the photos volume, created at startup.
pub async fn create_photos(
    State(state): State<AppState>,
    user: AuthUser,
    Json(r): Json<CreatePhotosReq>,
) -> ApiResult<Json<Value>> {
    let v = create_volume(
        &state,
        &user,
        NewVolume {
            volume_type: model::VOLUME_PHOTOS,
            share_type: 4,
            address_id: &r.share.address_id,
            address_key_id: &r.share.address_key_id,
            share_key: &r.share.key,
            share_passphrase: &r.share.passphrase,
            share_passphrase_signature: &r.share.passphrase_signature,
            folder_name: &r.link.name,
            folder_key: &r.link.node_key,
            folder_passphrase: &r.link.node_passphrase,
            folder_passphrase_signature: &r.link.node_passphrase_signature,
            folder_hash_key: &r.link.node_hash_key,
        },
    )
    .await?;
    Ok(ok(json!({ "Volume": volume_json(&state, &v) })))
}

pub async fn list(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let mut vols = Vec::new();
    for ty in [model::VOLUME_REGULAR, model::VOLUME_PHOTOS] {
        if let Some(v) = model::user_volume(&state, &user.user_id, ty).await? {
            vols.push(volume_json(&state, &v));
        }
    }
    Ok(ok(json!({ "Volumes": vols })))
}

pub async fn get(
    State(state): State<AppState>,
    user: AuthUser,
    Path(volume_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let v = model::volume(&state, &user.user_id, &volume_id).await?;
    Ok(ok(json!({ "Volume": volume_json(&state, &v) })))
}

/// `GET drive/v2/shares/my-files` and `.../photos`: the volume, its root share
/// and root folder; 2501 when it does not exist yet (the client creates it).
async fn root(state: &AppState, user: &AuthUser, volume_type: i64) -> ApiResult<Json<Value>> {
    let v = model::user_volume(state, &user.user_id, volume_type)
        .await?
        .ok_or_else(|| ApiError::not_found("Volume"))?;
    let s = model::share(state, &v.share_id).await?;
    let root = model::link(state, &v.id, &v.root_link_id).await?;
    let owner = model::owner_email(state, &user.user_id).await?;
    Ok(ok(json!({
        "Volume": { "VolumeID": v.id, "UsedSpace": v.used_space },
        "Share": {
            "ShareID": s.id,
            "CreatorEmail": s.creator_email,
            "Key": s.share_key,
            "Passphrase": s.passphrase,
            "PassphraseSignature": s.passphrase_signature,
            "AddressID": s.address_id,
        },
        "Link": model::link_details(state, &v, &root, &owner).await?,
    })))
}

pub async fn my_files(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    root(&state, &user, model::VOLUME_REGULAR).await
}

pub async fn photos(State(state): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    root(&state, &user, model::VOLUME_PHOTOS).await
}

fn share_json(v: &Volume, s: &Share) -> Value {
    json!({
        "ShareID": s.id,
        "VolumeID": s.volume_id,
        "Type": s.share_type,
        "State": 1,
        "VolumeType": v.volume_type,
        "Creator": s.creator_email,
        "Locked": false,
        "CreateTime": s.created,
        "ModifyTime": s.modified,
        "CreationTime": s.created,
        "LinkID": s.link_id,
        "LinkType": 1,
        "PermissionsMask": 22,
        "Flags": 0,
        "BlockSize": 4 * 1024 * 1024,
        "VolumeSoftDeleted": false,
        "Key": s.share_key,
        "Passphrase": s.passphrase,
        "PassphraseSignature": s.passphrase_signature,
        "AddressID": s.address_id,
        "AddressKeyID": s.address_key_id,
        "Memberships": [],
        "PossibleKeyPackets": [],
        "RootLinkRecoveryPassphrase": null,
        "EditorsCanShare": false,
    })
}

/// `GET drive/shares/{shareID}`: share bootstrap (called on navigation).
pub async fn get_share(
    State(state): State<AppState>,
    user: AuthUser,
    Path(share_id): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = model::share(&state, &share_id).await?;
    let v = model::volume(&state, &user.user_id, &s.volume_id).await?;
    Ok(ok(share_json(&v, &s)))
}

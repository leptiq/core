# Implemented API

Every route is served under each configured base path (by default `/api` and `/`).
Successful responses look like `{"Code": 1000, ...}`; errors look like `{"Code": N, "Error": "..."}`.

Personal access tokens (`account/v4/personal-access-token`) use leptiq's own request format, because Proton's is not public. `POST` takes
`{Name, ExpirationTime?, UserKey: {PrivateKey}, AddressKey: {PrivateKey, Token?, Signature?}, KeySalt?}`, where the keys are
locked with a secret the client generates. It returns `Token` (`pst_...`). The string the CLI uses is `<Token>::<base64url secret>`.

## Authentication

| Methods | Path |
|---|---|
| POST | `/auth/v4/info` |
| POST | `/core/v4/auth/info` |
| GET | `/auth/v4/modulus` |
| GET | `/core/v4/auth/modulus` |
| DELETE, POST | `/auth/v4` |
| DELETE, POST | `/core/v4/auth` |
| POST | `/auth/v4/2fa` |
| POST | `/core/v4/auth/2fa` |
| POST | `/auth/v4/refresh` |
| POST | `/core/v4/auth/refresh` |
| POST | `/auth/v4/cookies` |
| POST | `/core/v4/auth/cookies` |
| GET | `/auth/v4/scopes` |
| GET | `/core/v4/auth/scopes` |
| POST | `/auth/refresh` |
| DELETE, GET, POST | `/auth/v4/sessions` |
| DELETE | `/auth/v4/sessions/{uid}` |
| GET | `/auth/v4/sessions/local` (signed-in accounts of this browser, from its cookies) |
| GET, PUT | `/auth/v4/sessions/local/key` |
| GET, POST | `/auth/v4/sessions/forks` |
| GET | `/auth/sessions/forks` |
| GET | `/auth/v4/sessions/forks/code/{code}` |
| GET | `/auth/v4/sessions/forks/{selector}` |
| GET | `/auth/sessions/forks/{selector}` |
| PUT | `/core/v4/users/unlock` |
| PUT | `/core/v4/users/lock` |

## Core account API

| Methods | Path |
|---|---|
| GET, POST | `/core/v4/users` |
| GET | `/core/v4/users/available` |
| GET | `/core/v4/users/availableExternal` |
| POST | `/core/v4/users/code` |
| PUT | `/core/v4/users/check` |
| PUT | `/core/v4/users/delete` |
| GET | `/core/v4/addresses` |
| POST | `/core/v4/addresses/setup` |
| GET, PUT | `/core/v4/addresses/{id}` |
| GET | `/core/v4/domains/available` |
| GET | `/domains/available` |
| GET | `/domains/premium` |
| GET | `/core/v4/domains/premium` |
| POST | `/core/v4/keys/setup` |
| GET | `/core/v4/keys/salts` |
| GET | `/core/v4/keys/all` |
| GET | `/core/v4/keys` |
| POST | `/core/v4/keys/user` |
| POST | `/core/v4/keys/address` |
| PUT | `/core/v4/keys/private` |
| POST | `/core/v4/keys/signedkeylists` |
| GET | `/core/v4/keys/signedkeylist` |
| GET | `/core/v4/settings` |
| PUT | `/core/v4/settings/password` |
| POST | `/core/v4/settings/2fa/totp` |
| PUT | `/core/v4/settings/2fa/totp/disable` |
| GET, POST | `/core/v4/settings/2fa/register` |
| POST | `/core/v4/settings/2fa/{id}/remove` |
| PUT | `/core/v4/settings/2fa/{id}/rename` |
| PUT | `/core/v4/settings/{*field}` |
| GET | `/core/v4/events/latest` |
| GET | `/core/v4/events/{id}` |
| GET | `/core/v5/events/latest` |
| GET | `/core/v5/events/{id}` |
| GET, POST | `/account/v4/personal-access-token` |
| POST | `/account/v4/personal-access-token/session` |
| DELETE | `/account/v4/personal-access-token/{id}` |

## Compatibility stubs

| Methods | Path |
|---|---|
| GET | `/feature/v2/frontend` |
| GET, POST | `/feature/v2/frontend/{*rest}` |
| GET | `/core/v4/features` |
| GET, PUT | `/core/v4/features/{*rest}` |
| GET | `/payments/v4/plans` |
| GET | `/payments/v4/plans/default` |
| GET | `/payments/v5/plans/default` |
| GET | `/payments/v5/web-configuration` |
| GET | `/payments/v5/plans` |
| GET | `/payments/v4/subscription` |
| GET | `/payments/v5/subscription` |
| GET | `/payments/v4/status` |
| GET | `/payments/v5/status` |
| GET | `/payments/v4/methods` |
| GET | `/payments/v5/methods` |
| GET | `/payments/v4/subscription/latest` |
| GET | `/mail/v4/settings` |
| GET | `/core/v4/organizations` |
| GET | `/core/v4/members` |
| GET | `/core/v4/members/me` |
| GET | `/vpn/v1/location` |
| GET | `/core/v4/notifications` |
| POST | `/data/v1/stats` |
| POST | `/data/v1/stats/multiple` |
| POST | `/data/v1/telemetry` |
| POST | `/data/v1/metrics` |
| POST | `/core/v4/reports/bug` |
| POST | `/core/v4/reports/sentry/{*rest}` |
| GET | `/challenge/v4/html` |
| POST | `/core/v4/metrics` |
| GET | `/core/v4/images/logo` |
| GET | `/core/v4/users/apps` |
| GET | `/core/v4/checklist/{*rest}` |
| GET, PUT | `/account/v1/onboarding` |
| PUT | `/core/v4/settings/telemetry` |

### Account dashboard stubs

The account app's signed-in pages (`account.<domain>/u/<n>/...`) also call
these. They answer with empty data for Proton features leptiq does not have
(mail, contacts, calendar, billing, delegated access, breach monitoring,
sign-in history).

| Methods | Path |
|---|---|
| GET | `/account/v1/access/incoming`, `/account/v1/access/outgoing` |
| GET | `/account/v4/breaches` |
| GET | `/contacts/v4/contacts/emails` |
| GET | `/core/v4/groups/members/internal` |
| GET | `/core/v4/users/invitations` |
| GET | `/core/v4/referrals/info` (always "not eligible") |
| GET | `/core/v4/logs/auth` |
| GET | `/core/v4/system/config` |
| GET | `/core/v5/entitlements` |
| GET | `/payments/v4/invoices`, `/payments/v5/invoices` |
| GET | `/payments/v5/account/billing-information` |
| GET | `/payments/v6/plans/entitlements` |
| GET | `/payments/v6/subscription/latest` |
| GET | `/oauth-token/v1/tokens` |
| GET | `/{core,mail,contacts,calendar}/v6/events/latest` and `/{id}` (never any changes) |

## Proton Pass API

| Methods | Path |
|---|---|
| GET, POST | `/pass/v1/user/access` |
| GET | `/pass/v1/user/access/check` |
| PUT | `/pass/v1/user/default_share/{share}` |
| PUT | `/pass/v1/user/monitor` |
| PUT | `/pass/v1/user/inapp_notifications_disabled` |
| POST | `/pass/v1/user/coupon/redeem` |
| GET | `/pass/v1/user/sync_event` |
| GET | `/pass/v1/user/sync_event/{event}` |
| DELETE, POST | `/pass/v1/user/session/lock` |
| GET | `/pass/v1/user/session/lock/check` |
| POST | `/pass/v1/user/session/lock/unlock` |
| POST | `/pass/v1/user/session/lock/force_lock` |
| DELETE, GET, POST | `/pass/v1/user/srp` |
| GET | `/pass/v1/user/srp/info` |
| POST | `/pass/v1/user/srp/auth` |
| GET | `/pass/v1/notification` |
| PUT | `/pass/v1/notification/{id}` |
| GET | `/pass/v1/share` |
| PUT | `/pass/v1/share/hide` |
| DELETE, GET | `/pass/v1/share/{share}` |
| PUT | `/pass/v1/share/{share}/hide` |
| PUT | `/pass/v1/share/{share}/unhide` |
| GET, POST | `/pass/v1/share/{share}/key` |
| GET, POST | `/pass/v1/share/{share}/key/pending` |
| GET | `/pass/v1/share/{share}/user` |
| GET | `/pass/v1/share/{share}/user/item/{item}` |
| DELETE, GET, PUT | `/pass/v1/share/{share}/user/{member}` |
| GET, POST | `/pass/v1/share/{share}/invite` |
| POST | `/pass/v1/share/{share}/invite/batch` |
| POST | `/pass/v1/share/{share}/invite/check_address` |
| POST | `/pass/v1/share/{share}/invite/new_user` |
| POST | `/pass/v1/share/{share}/invite/new_user/batch` |
| DELETE | `/pass/v1/share/{share}/invite/new_user/{invite}` |
| POST | `/pass/v1/share/{share}/invite/new_user/{invite}/keys` |
| GET | `/pass/v1/share/{share}/invite/recommended_emails` |
| GET | `/pass/v1/share/{share}/invite/recommended_emails/organization` |
| GET | `/pass/v1/share/{share}/invite/recommended_emails/suggested` |
| DELETE | `/pass/v1/share/{share}/invite/{invite}` |
| POST | `/pass/v1/share/{share}/invite/{invite}/reminder` |
| GET | `/pass/v1/invite` |
| GET | `/pass/v1/invite/group` |
| DELETE, POST | `/pass/v1/invite/{token}` |
| POST | `/pass/v1/file` |
| PUT | `/pass/v1/file/{file}/metadata` |
| POST | `/pass/v1/file/{file}/chunk` |
| POST | `/pass/v1/share/{share}/item/{item}/link_files` |
| GET | `/pass/v1/share/{share}/item/{item}/files` |
| GET | `/pass/v1/share/{share}/item/{item}/revisions/files` |
| POST | `/pass/v1/share/{share}/item/{item}/file/restore` |
| PUT | `/pass/v1/share/{share}/item/{item}/file/{file}/metadata` |
| POST | `/pass/v1/share/{share}/item/{item}/file/{file}/restore` |
| GET | `/pass/v1/share/{share}/item/{item}/file/{file}/chunk/{chunk}` |
| GET | `/pass/v1/vault/usage/{share}` |
| GET | `/pass/v1/public_link/files/{token}` |
| GET | `/pass/v1/public_link/files/{token}/{file}/{chunk}` |
| GET | `/pass/v1/share/{share}/alias/options` |
| POST | `/pass/v1/share/{share}/alias/custom` |
| POST | `/pass/v1/share/{share}/alias/random` |
| POST | `/pass/v1/share/{share}/alias/bulk/get` |
| POST | `/pass/v1/share/{share}/item/with_alias` |
| GET | `/pass/v1/share/{share}/alias/{item}` |
| POST | `/pass/v1/share/{share}/alias/{item}/mailbox` |
| PUT | `/pass/v1/share/{share}/alias/{item}/name` |
| PUT | `/pass/v1/share/{share}/alias/{item}/note` |
| PUT | `/pass/v1/share/{share}/alias/{item}/status` |
| GET, POST | `/pass/v1/share/{share}/alias/{item}/contact` |
| DELETE, GET | `/pass/v1/share/{share}/alias/{item}/contact/{contact}` |
| PUT | `/pass/v1/share/{share}/alias/{item}/contact/{contact}/blocked` |
| GET | `/pass/v1/share/{share}/alias/{item}/breaches` |
| POST | `/pass/v1/share/{share}/alias/{item}/breaches/resolved` |
| POST | `/pass/v1/share/{share}/alias/{item}/breaches/{breach}/resolve` |
| GET | `/pass/v1/user/alias/settings` |
| PUT | `/pass/v1/user/alias/settings/default_alias_domain` |
| PUT | `/pass/v1/user/alias/settings/default_mailbox_id` |
| GET | `/pass/v1/user/alias/domain` |
| GET | `/pass/v1/user/alias/count` |
| GET | `/pass/v1/user/alias/missing` |
| GET, POST | `/pass/v1/user/alias/mailbox` |
| DELETE | `/pass/v1/user/alias/mailbox/{id}` |
| GET, POST | `/pass/v1/user/alias/mailbox/{id}/verify` |
| DELETE, PUT | `/pass/v1/user/alias/mailbox/{id}/email` |
| GET, POST | `/pass/v1/user/alias/custom_domain` |
| DELETE, GET, POST | `/pass/v1/user/alias/custom_domain/{id}` |
| GET | `/pass/v1/user/alias/custom_domain/{id}/settings` |
| PUT | `/pass/v1/user/alias/custom_domain/{id}/settings/catch_all` |
| PUT | `/pass/v1/user/alias/custom_domain/{id}/settings/mailboxes` |
| PUT | `/pass/v1/user/alias/custom_domain/{id}/settings/name` |
| PUT | `/pass/v1/user/alias/custom_domain/{id}/settings/random_prefix` |
| GET | `/pass/v1/alias_sync/pending` |
| GET | `/pass/v1/alias_sync/status` |
| POST | `/pass/v1/alias_sync/sync` |
| POST | `/pass/v1/alias_sync/share/{share}/create` |
| GET | `/pass/v1/organization` |
| PUT | `/pass/v1/organization/settings` |
| PUT | `/pass/v1/organization/settings/password_policy` |
| GET | `/pass/v1/organization/report` |
| POST | `/pass/v1/organization/report/client_data` |
| GET | `/pass/v1/organization/report/user_shares` |
| GET, POST | `/pass/v1/organization/urlpause` |
| DELETE, PUT | `/pass/v1/organization/urlpause/{id}` |
| GET | `/pass/v1/breach` |
| GET | `/pass/v1/breach/address/{a}/breaches` |
| PUT | `/pass/v1/breach/address/{a}/monitor` |
| POST | `/pass/v1/breach/address/{a}/resolved` |
| POST | `/pass/v1/breach/custom_email` |
| DELETE | `/pass/v1/breach/custom_email/{e}` |
| GET | `/pass/v1/breach/custom_email/{e}/breaches` |
| PUT | `/pass/v1/breach/custom_email/{e}/breaches/{b}/resolve` |
| PUT | `/pass/v1/breach/custom_email/{e}/monitor` |
| POST | `/pass/v1/breach/custom_email/{e}/resend_verification` |
| PUT | `/pass/v1/breach/custom_email/{e}/resolved` |
| PUT | `/pass/v1/breach/custom_email/{e}/verify` |
| POST | `/pass/v1/personal-access-token/{pat}/access` |
| DELETE | `/pass/v1/personal-access-token/{pat}/access/{share}` |
| POST | `/pass/v1/pat/monitor` |
| GET | `/pass/v1/pat/monitor/{pat}` |
| POST | `/pass/v1/share/{share}/item/{item}/public_link` |
| GET | `/pass/v1/public_link` |
| DELETE | `/pass/v1/public_link/inactive` |
| GET | `/pass/v1/public_link/content/{token}` |
| DELETE | `/pass/v1/public_link/{id}` |
| GET | `/pass/v1/share/{share}/event` |
| GET | `/pass/v1/share/{share}/event/{event}` |
| POST | `/pass/v1/vault` |
| DELETE, PUT | `/pass/v1/vault/{share}` |
| PUT | `/pass/v1/vault/{share}/primary` |
| PUT | `/pass/v1/vault/{share}/owner` |
| GET | `/pass/v1/vault/share/{vault}` |
| DELETE, GET, POST | `/pass/v1/share/{share}/item` |
| POST | `/pass/v1/share/{share}/item/trash` |
| POST | `/pass/v1/share/{share}/item/untrash` |
| PUT | `/pass/v1/share/{share}/item/read` |
| PUT | `/pass/v1/share/{share}/item/share` |
| PUT | `/pass/v1/share/{share}/item/folder` |
| POST | `/pass/v1/share/{share}/item/import/batch` |
| GET, PUT | `/pass/v1/share/{share}/item/{item}` |
| GET | `/pass/v1/share/{share}/item/{item}/revision` |
| DELETE | `/pass/v1/share/{share}/item/{item}/revisions` |
| DELETE, POST | `/pass/v1/share/{share}/item/{item}/pin` |
| PUT | `/pass/v1/share/{share}/item/{item}/flags` |
| PUT | `/pass/v1/share/{share}/item/{item}/lastuse` |
| GET | `/pass/v1/share/{share}/item/{item}/key` |
| GET | `/pass/v1/share/{share}/item/{item}/key/latest` |
| DELETE, GET, POST | `/pass/v1/share/{share}/folder` |
| GET, PUT | `/pass/v1/share/{share}/folder/{folder}` |
| PUT | `/pass/v1/share/{share}/folder/{folder}/move` |

## Authenticator API (`leptiq-authenticator`)

Sync for the Proton Authenticator apps. The server stores only ciphertext:
authenticator keys are encrypted by the client with a user key, entries with
an authenticator key.

| Methods | Path |
|---|---|
| GET, POST | `/authenticator/v1/key` |
| GET, POST | `/authenticator/v1/entry` (GET pages 100 at a time: `Since` = previous `LastID`) |
| POST, PUT, DELETE | `/authenticator/v1/entry/bulk` |
| PUT, DELETE | `/authenticator/v1/entry/{id}` (PUT needs `LastRevision`; stale → 409) |
| PUT | `/authenticator/v1/entry/{id}/order` (`AfterID`, null = top) |
| PUT | `/authenticator/v1/entry/order` (`StartingPosition`, `Entries`) |

## Drive API (`leptiq-drive`)

The API of Proton's Drive SDK, used by the Drive web app. Names, keys, extended
attributes and file blocks are client ciphertext; the server checks name-hash
uniqueness per folder (2500 with `ConflictLinkID`), tracks revisions, sizes and
quota, and stores each block's SHA-256 for the client to verify.

| Methods | Path |
|---|---|
| GET, POST | `/drive/volumes`; GET `/drive/volumes/{volume}` |
| POST | `/drive/photos/volumes` |
| GET | `/drive/v2/shares/my-files`, `/drive/v2/shares/photos` (2501 until created) |
| GET | `/drive/shares`, `/drive/shares/{share}`, `/drive/shares/{share}/links/{link}` |
| GET | `/drive/v2/volumes/{volume}/folders/{link}/children` (`AnchorID` paging) |
| POST | `/drive/v2/volumes/{volume}/links`, `/drive/photos/volumes/{volume}/links` |
| POST | `/drive/v2/volumes/{volume}/folders` |
| PUT | `/drive/v2/volumes/{volume}/links/{link}/rename`, `.../move` |
| POST | `/drive/v2/volumes/{volume}/trash_multiple`, `.../trash/delete_multiple`, `.../delete_multiple` |
| PUT | `/drive/v2/volumes/{volume}/trash/restore_multiple` |
| GET, DELETE | `/drive/volumes/{volume}/trash` (GET pages with `Page` until empty) |
| POST | `/drive/v2/volumes/{volume}/links/{link}/checkAvailableHashes` |
| GET | `/drive/volumes/{volume}/folders/{link}/calculate-descendents-size` |
| POST | `/drive/v2/volumes/{volume}/files` (draft file + revision) |
| GET, POST | `/drive/v2/volumes/{volume}/files/{link}/revisions` |
| GET, PUT, DELETE | `/drive/v2/volumes/{volume}/files/{link}/revisions/{revision}` (PUT commits; GET pages blocks with `FromBlockIndex`) |
| POST | `/drive/v2/volumes/{volume}/files/{link}/revisions/{revision}/restore` |
| GET | `/drive/v2/volumes/{volume}/links/{link}/revisions/{revision}/verification` |
| POST | `/drive/blocks` (upload URLs), `/drive/volumes/{volume}/thumbnails` (download URLs) |
| GET, POST | `/drive/storage/{token}` (block bytes; multipart field `Block`; no app version needed) |
| GET | `/drive/volumes/{volume}/events/latest`, `/drive/v2/volumes/{volume}/events/{event}` |
| GET, PUT | `/drive/me/settings` |

Sharing, devices, photo and album lists, invitations and onboarding answer empty.
Block URLs are relative (`[drive] storage_url`, default `/api/drive/storage`), so
the Drive web app must be served with `/api` proxied to the server.

## Assistant API (`leptiq-assistant`)

Serves Proton's Lumo clients ("Leptiq Assistant"). Prompts and answers are
end-to-end encrypted between the client and the server: each request carries a
fresh AES-256-GCM key, OpenPGP-encrypted to the server's key (the client build
embeds the public half). The server decrypts the turns, forwards them to an
OpenAI-compatible chat API, and streams the answer back as encrypted SSE
deltas. Conversations are stored as client ciphertext.

| Methods | Path |
|---|---|
| POST | `/ai/v1/chat/completions` (SSE; upstream 429 → 429) |
| GET | `/ai/v1/models`, `/ai/v1/limits` |
| GET | `/assistant/public-key` (armored key to build the Lumo client with) |
| GET, POST | `/lumo/v1/masterkeys` |
| GET, POST, DELETE | `/lumo/v1/spaces`; GET, PUT, DELETE `/lumo/v1/spaces/{id}` |
| POST | `/lumo/v1/spaces/{id}/conversations`, `/lumo/v1/spaces/{id}/assets` |
| GET, PUT, DELETE | `/lumo/v1/conversations/{id}`; POST `.../messages` |
| GET, DELETE | `/lumo/v1/messages/{id}` |
| GET, PUT, DELETE | `/lumo/v1/assets/{id}` |
| GET, POST, PUT | `/lumo/v1/settings` |
| GET | `/lumo/v1/events/latest`, `/lumo/v1/events/{id}` |

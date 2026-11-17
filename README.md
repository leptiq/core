<p align="center"><img src="assets/leptiq-mark.svg" alt="Leptiq" width="120"></p>

# Leptiq

An open-source, self-hostable server for the official **Proton** apps, written
in Rust. Products are added one at a time; the first is **Leptiq Pass**, for
the Proton Pass clients.

Leptiq reimplements the HTTP API the official apps use: Proton's core account
API (SRP login, sessions, keys, addresses, events) and, per product, its own
API (for Pass, `pass/v1`). Clients built to point at your domain can then store
their end-to-end-encrypted data on your own server. It is an independent
project, not affiliated with or endorsed by Proton AG.

| Crate | Contents |
|---|---|
| `leptiq-core` | Accounts, authentication, sessions, keys, events, config, storage, and the `Product` trait products plug into |
| `leptiq-pass` | Leptiq Pass: the Pass API, aliases, personal access tokens |
| `leptiq-authenticator` | Leptiq Authenticator: sync for the Proton Authenticator apps (encrypted 2FA entries) |
| `leptiq-drive` | Leptiq Drive: files and folders for the Proton Drive apps (encrypted blocks, revisions, trash) |
| `leptiq` | The `leptiq` server binary and admin commands; end-to-end tests |

The server is **zero-knowledge**, like Proton's. Clients encrypt everything before
upload: vault keys (OpenPGP, to the user's address key), item keys and contents
(AES-256-GCM), and attachment chunks. The server stores and relays ciphertext.
Its only cryptographic job is checking SRP login proofs, which uses Proton's own
[`proton-srp`](https://github.com/ProtonMail/proton-crypto-rs) crate.

## Leptiq Pass features

| Area | Status |
|---|---|
| Accounts | Signup (open / invite-only / closed), SRP login, token refresh with rotation, cookie sessions for web clients, session forks (account app → Pass app/extension, CLI user codes), session list/revoke |
| Keys | User/address key setup, key salts, public key lookup, signed key lists, password change |
| 2FA | TOTP, FIDO2 security keys (webauthn-rs) |
| Vaults & items | Vaults, items with full revision history, trash, pins, flags, last-use, import, moves between vaults, nested folders |
| Sync | Core event loop, Pass sync events v2 and legacy per-share events |
| Sharing | Invites to existing and not-yet-registered users, vault and single-item shares, roles, members, key rotation with pending keys, ownership transfer, public (secure) links |
| Attachments | Chunked encrypted uploads, linking to item revisions, restore, quotas, garbage collection |
| Security | Pass PIN session lock, Pass extra password (second SRP verifier) |
| Aliases | SimpleLogin-style aliases: signed suffixes, custom/random aliases, mailboxes with verification, contacts and reverse aliases, custom domains with DNS checks, catch-all, built-in inbound SMTP forwarder |
| Organization | Instance-wide policies managed by admins, member health reports, URL pause list |
| Personal access tokens | For `pass-cli` (`pass login --pat`): token identities, per-vault/item access grants, audit log |
| Not available | Breach monitoring (no data source), payments, SimpleLogin account sync |

Storage is **SQLite** (single file, good for personal use) or **PostgreSQL**. The
test suite runs against both.

## Quick start

```bash
cargo build --release
cp leptiq.example.toml leptiq.toml   # edit public_url, mail_domain, ...
./target/release/leptiq serve
```

Or with Docker:

```bash
docker build -t leptiq .
docker run -p 8080:8080 -v leptiq-data:/var/lib/leptiq \
  -e LEPTIQ_PUBLIC_URL=https://pass.example.com \
  -e LEPTIQ_MAIL_DOMAIN=example.com leptiq
```

The first account created on a fresh instance becomes the instance admin.

Admin commands:

```bash
leptiq admin invite              # one-time signup code (signup = "invite")
leptiq admin users               # list users
leptiq admin set-admin alice     # grant admin
leptiq admin delete-user alice
```

## Clients

The official clients are open source but hard-wired to Proton's servers. Each
needs a build that points at your domain; see [docs/clients.md](docs/clients.md).

- **Browser extension / web app**: build WebClients with `API_ENV=<domain>` and
  host the account app for login ([leptiq/webclients](https://github.com/leptiq/webclients)).
- **Android**: build `android-pass` with `PROD_ENV_URL=<domain>`
  (`clients/build-android.sh`).
- **Pass CLI**: `PROTON_PASS_ENVIRONMENT=https://<host> pass login --pat <token>`.
- **iOS**: only QA builds accept a custom environment.

leptiq serves the SRP modulus that Proton published and signed, so clients
verify it without patches. To use your own modulus, set `srp_modulus_file` and
patch the modulus-signing key into your client builds.

## Documentation

- [docs/deployment.md](docs/deployment.md): reverse proxy, TLS, email/aliases, backups
- [docs/clients.md](docs/clients.md): building and configuring the official clients
- [docs/api.md](docs/api.md): implemented endpoints

## Development

```bash
cargo test                                    # SQLite
LEPTIQ_TEST_DATABASE_URL=postgres://... cargo test   # Postgres
```

The integration tests act as a real client. They use real SRP and generate real
OpenPGP keys. They also encrypt with AES-GCM using Pass's associated-data tags.

## License

AGPL-3.0-or-later. "Proton" and "Proton Pass" are trademarks of Proton AG; this
project is not affiliated with Proton.

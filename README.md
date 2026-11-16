# passhost

An open-source, self-hostable server for **Proton Pass** clients, written in Rust.

passhost reimplements the HTTP API that the official Proton Pass apps use: Proton's
core account API (SRP login, sessions, keys, addresses, events) and the Pass API
(`pass/v1`). Clients built to point at your domain can then store their
end-to-end-encrypted vaults on your own server. It is an independent project, not
affiliated with or endorsed by Proton AG.

The server is **zero-knowledge**, like Proton's. Clients encrypt everything before
upload: vault keys (OpenPGP, to the user's address key), item keys and contents
(AES-256-GCM), and attachment chunks. The server stores and relays ciphertext.
Its only cryptographic job is checking SRP login proofs, which uses Proton's own
[`proton-srp`](https://github.com/ProtonMail/proton-crypto-rs) crate.

## Features

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
cp passhost.example.toml passhost.toml   # edit public_url, mail_domain, ...
./target/release/passhost serve
```

Or with Docker:

```bash
docker build -t passhost .
docker run -p 8080:8080 -v passhost-data:/var/lib/passhost \
  -e PASSHOST_PUBLIC_URL=https://pass.example.com \
  -e PASSHOST_MAIL_DOMAIN=example.com passhost
```

The first account created on a fresh instance becomes the instance admin.

Admin commands:

```bash
passhost admin invite              # one-time signup code (signup = "invite")
passhost admin users               # list users
passhost admin set-admin alice     # grant admin
passhost admin delete-user alice
```

## Clients

The official clients are open source but hard-wired to Proton's servers. Each
needs a build that points at your domain; see [docs/clients.md](docs/clients.md).

- **Browser extension / web app**: build WebClients with `API_ENV=<domain>` and
  host the account app for login (`clients/build-webclients.sh`).
- **Android**: build `android-pass` with `PROD_ENV_URL=<domain>`
  (`clients/build-android.sh`).
- **Pass CLI**: `PROTON_PASS_ENVIRONMENT=https://<host> pass login --pat <token>`.
- **iOS**: only QA builds accept a custom environment.

passhost serves the SRP modulus that Proton published and signed, so clients
verify it without patches. To use your own modulus, set `srp_modulus_file` and
patch the modulus-signing key into your client builds.

## Documentation

- [docs/deployment.md](docs/deployment.md): reverse proxy, TLS, email/aliases, backups
- [docs/clients.md](docs/clients.md): building and configuring the official clients
- [docs/api.md](docs/api.md): implemented endpoints

## Development

```bash
cargo test                                    # SQLite
PASSHOST_TEST_DATABASE_URL=postgres://... cargo test   # Postgres
```

The integration tests act as a real client. They use real SRP and generate real
OpenPGP keys. They also encrypt with AES-GCM using Pass's associated-data tags.

## License

AGPL-3.0-or-later. "Proton" and "Proton Pass" are trademarks of Proton AG; this
project is not affiliated with Proton.

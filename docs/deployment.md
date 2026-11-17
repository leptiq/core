# Deployment

## Layout

The official web clients expect these hosts:

| Host | Serves |
|---|---|
| `pass.example.com` | Pass web app (static files, `applications/pass/dist`) and `/api` → leptiq |
| `account.example.com` | Account app (static files, login/signup) and `/api` → leptiq |
| `drive.example.com` | Drive web app (static files, `applications/drive/dist`) and `/api` → leptiq |
| `lumo.example.com` | Assistant web app (`applications/lumo/dist`) and `/api` → leptiq (disable response buffering for streaming) |
| `account-api.example.com` | → leptiq (the account app's anti-abuse challenge frame, `/challenge/v4/html`) |
| `api.example.com` | API root for the Android app (`PROD_ENV_URL=example.com`) |

leptiq answers on both `/api/...` and `/...` (`base_paths` in the config), so one
instance can serve all of these hosts.

The account app's signup and login forms load an iframe from
`account-api.<domain>/challenge/v4/html` (Proton's bot detection; it also draws
the username field). leptiq serves a stand-in that draws the fields and
reports an empty fingerprint. Without that host the forms wait for the frame
to time out (about a minute) and the username field is missing.

### Caddy example

```caddy
pass.example.com {
    handle /api/* {
        reverse_proxy 127.0.0.1:8080
    }
    handle {
        root * /srv/proton-pass-web
        try_files {path} /index.html
        file_server
    }
}

account.example.com {
    handle /api/* {
        reverse_proxy 127.0.0.1:8080
    }
    handle {
        root * /srv/proton-account
        # Same routing as the app's .htaccess: the signed-in pages (/u/<n>/...)
        # are a separate page, private.html. Serving index.html there makes the
        # sign-in page redirect back to /u/<n>/... forever.
        @html path / *.html /u/* /switch* /login* /signup*
        header @html Cache-Control "no-cache, no-store, must-revalidate"
        @private path /u/*
        rewrite @private /private.html
        @oauth path /oauth/callback*
        rewrite @oauth /oauth.html
        try_files {path} {path}/index.html /index.html
        file_server
    }
}

account-api.example.com, api.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

The account app ships an Apache `.htaccess` with its routing rules; the Caddy
block above mirrors the parts that matter. Its signed-in pages (account
settings, `/u/<n>/...`) work: profile and password, recovery, session
management, language and appearance. Sections for Proton features leptiq
does not have (billing, Sentinel, dark-web monitoring, sign-in history) show
their empty or "upgrade" state.

Set `public_url = "https://pass.example.com"`. Cookies use the `Secure` flag when
`public_url` is https. Set `webauthn_rp_id = "example.com"` so security keys work
on every subdomain.

## Database

- SQLite: `database_url = "sqlite:///var/lib/leptiq/leptiq.db?mode=rwc"`. Uses a
  single connection in WAL mode; fine for families and small teams.
- PostgreSQL: `database_url = "postgres://user:pass@host/db"`.

Migrations run automatically at start-up (`leptiq migrate` runs them alone).

## Backups

Back up the database and `data_dir` (attachment blobs) together. Everything in
them is end-to-end encrypted, except metadata such as usernames, email addresses,
item counts and timestamps.

## Email

Outbound mail (alias forwarding and mailbox verification codes) goes through an
SMTP relay:

```toml
[smtp]
host = "smtp.example.com"
port = 587
username = "leptiq@example.com"
password = "..."
from = "leptiq@example.com"
security = "starttls"   # or "tls" / "none"
```

Without a relay, verification codes are written to the log.

## Aliases

```toml
[pass.alias]
enabled = true
domains = ["alias.example.com"]
smtp_listen = "127.0.0.1:2525"
mx_host = "mx.example.com"
max_aliases = 0          # 0 = unlimited
```

The built-in SMTP listener only accepts mail for existing aliases and reverse
aliases. Put a real MTA (Postfix, Haraka...) in front of it to handle TLS, spam
filtering and retries, and relay the alias domains to `smtp_listen`. Mail
forwarded to a mailbox comes from a per-correspondent reverse alias. Replies
sent to that reverse alias from one of the alias's mailboxes go out from the
alias address.

For users' custom domains, users add a TXT record
`leptiq-verification=<token>` and an MX pointing at `mx_host`. Then they press
"verify" in the client.

## Assistant

The Assistant (Proton's Lumo clients) forwards conversations to an
OpenAI-compatible chat API:

```toml
[assistant]
base_url = "https://opencode.ai/zen/v1"   # default: OpenCode Zen
api_key = "public"                          # Zen's anonymous key for free models
model = "big-pickle"
# models = { "lumo-max" = "some-bigger-model" }   # per client model
# system_prompt = "..."
# server_key_file = "assistant-key.asc"           # default: generated, kept in the DB
```

Any OpenAI-compatible endpoint works: OpenRouter, a local Ollama or llama.cpp
server (`base_url = "http://127.0.0.1:11434/v1"`, `api_key = ""`), or a paid
provider. OpenCode Zen's anonymous free tier is rate limited (and may answer 429
right away); rate limits reach the client as "try again later".

The Lumo client must be built with this server's public key: `leptiq/build.sh`
in leptiq/webclients downloads it from `https://pass.<domain>/api/assistant/public-key`
(or set `LUMO_PUB_KEY_PATH`). Prompts are decrypted on the server and sent to the
model provider in plain text; choose a provider you trust.

# Deployment

## Layout

The official web clients expect these hosts:

| Host | Serves |
|---|---|
| `pass.example.com` | Pass web app (static files, `applications/pass/dist`) and `/api` → passhost |
| `account.example.com` | Account app (static files, login/signup) and `/api` → passhost |
| `account-api.example.com` | → passhost (the account app's anti-abuse challenge frame, `/challenge/v4/html`) |
| `api.example.com` | API root for the Android app (`PROD_ENV_URL=example.com`) |

passhost answers on both `/api/...` and `/...` (`base_paths` in the config), so one
instance can serve all of these hosts.

The account app's signup and login forms load an iframe from
`account-api.<domain>/challenge/v4/html` (Proton's bot detection; it also draws
the username field). passhost serves a stand-in that draws the fields and
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
        try_files {path} /index.html
        file_server
    }
}

account-api.example.com, api.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Set `public_url = "https://pass.example.com"`. Cookies use the `Secure` flag when
`public_url` is https. Set `webauthn_rp_id = "example.com"` so security keys work
on every subdomain.

## Database

- SQLite: `database_url = "sqlite:///var/lib/passhost/passhost.db?mode=rwc"`. Uses a
  single connection in WAL mode; fine for families and small teams.
- PostgreSQL: `database_url = "postgres://user:pass@host/db"`.

Migrations run automatically at start-up (`passhost migrate` runs them alone).

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
username = "passhost@example.com"
password = "..."
from = "passhost@example.com"
security = "starttls"   # or "tls" / "none"
```

Without a relay, verification codes are written to the log.

## Aliases

```toml
[alias]
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
`passhost-verification=<token>` and an MX pointing at `mx_host`. Then they press
"verify" in the client.

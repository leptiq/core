# Using the official clients

Proton's clients are GPL-3.0 and have build-time switches for other
environments. leptiq does not ship modified client code. The scripts in
`clients/` clone the upstream repositories, adjust configuration, and build.

## Browser extension, web apps and account app

Use [leptiq/webclients](https://github.com/leptiq/webclients). It patches Proton's
WebClients with the Leptiq branding and with plans and upsells hidden, then builds
the apps for your domain:

```bash
DOMAIN=example.com ./build.sh                                  # account, pass, pass-extension
DOMAIN=example.com APPS="pass-extension" BUILD_TARGET=firefox ./build.sh
```

- `API_ENV=<domain>` makes the extension use `https://pass.<domain>/api` and log in
  through `https://account.<domain>`. The extension's webpack config also rewrites
  the manifest's `account.`/`pass.` match patterns to that domain, which lets the
  account page hand the session to the extension.
- The account app does the SRP signup/login and then forks the session to the
  extension or web app (`auth/v4/sessions/forks`). Serve its `dist/` at
  `account.<domain>`, with `/api` proxied to the server (see `docs/deployment.md`).
- For Firefox, load `dist/` as a temporary add-on (`about:debugging`) or sign it
  with `web-ext sign` for a permanent install.

Tested end to end with Firefox against a local instance: signup in the account
app, session fork to the extension, initial sync (default vault creation), and
saving a login from a web page through the extension's "Save login" prompt.

For a local test setup with a port, e.g. `DOMAIN=leptiq.localhost:8443`: the
`*.localhost` names resolve to 127.0.0.1 in Firefox without DNS changes, the
script strips the port from the manifest patterns, and a self-signed wildcard
certificate for `*.leptiq.localhost` works once its exception has been
accepted for each host (`pass.`, `account.`, `account-api.`).

## Pass web app

`build.sh` in leptiq/webclients also builds the web app (`applications/pass/dist`).
Serve it at `pass.example.com` with `/api` proxied to leptiq (see
`docs/deployment.md`). It signs in through the account app at
`account.<same domain>`, which forks the session to it.

Tested end to end with Firefox: sign-in via the account app (including its
account switcher and password re-authentication), vault sync and decryption of
items saved by the extension, editing an item, the password lock, and
unlocking after a reload.

## Android

```bash
HOST=example.com ./clients/build-android.sh
```

When `PROD_ENV_URL` is set, `android-pass` builds against `https://api.<host>/`
and turns off Proton's certificate pinning. Login uses SRP inside the app. Check
`app/build.gradle.kts` upstream if the Gradle task name has changed.

## Pass CLI

```bash
export PROTON_PASS_ENVIRONMENT=https://pass.example.com
pass login --pat 'pst_...::<key>'
```

The CLI only supports personal-access-token login against custom environments.
leptiq exposes token management at `account/v4/personal-access-token`. The
token's keys are created client-side; see `docs/api.md`.

## iOS

Only QA builds of `protonpass/ios-pass` read the custom-environment settings.
App Store builds always use Proton's servers.

## SRP modulus

Clients only accept an SRP modulus signed with Proton's modulus key. By default
leptiq serves the modulus Proton already published and signed. It is a public
2048-bit safe prime, so reusing it costs no security, and no client needs a
patch for it. To use your own, set `srp_modulus_file` to a clearsigned modulus
and replace the modulus public key in your client builds.

# Using the official clients

Proton's clients are GPL-3.0 and have build-time switches for other
environments. leptiq does not ship modified client code. The scripts in
`clients/` clone the upstream repositories, adjust configuration, and build.

## Browser extension (Chrome / Firefox)

```bash
DOMAIN=example.com ./clients/build-webclients.sh
DOMAIN=example.com BUILD_TARGET=firefox ./clients/build-webclients.sh
```

The script builds the extension, the Pass web app and Proton's **account
app**, which the extension and web app need for login and signup.

- `API_ENV=example.com` makes the extension use `https://pass.example.com/api` and
  log in through `https://account.example.com`. The extension's webpack config
  also rewrites the manifest's `account.`/`pass.` match patterns to that domain,
  which lets the account page hand the session to the extension.
- The account app does the SRP signup/login and then forks the session to the
  extension (`auth/v4/sessions/forks`). Serve its `dist/` at
  `account.example.com`, with `/api` proxied to leptiq (see
  `docs/deployment.md`).
- The script works around the parts of the public WebClients mirror that only
  build inside Proton's network (a missing preinstall script, internal npm
  registries, internal-only test packages). It only edits the checkout.
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

`build-webclients.sh` also builds the web app (`applications/pass/dist`).
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

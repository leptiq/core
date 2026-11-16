# Using the official clients

Proton's clients are GPL-3.0 and have build-time switches for other
environments. passhost does not ship modified client code. The scripts in
`clients/` clone the upstream repositories, adjust configuration, and build.

## Browser extension (Chrome / Firefox)

```bash
DOMAIN=example.com ./clients/build-webclients.sh
DOMAIN=example.com BUILD_TARGET=firefox ./clients/build-webclients.sh
```

- `API_ENV=example.com` makes the extension use `https://pass.example.com/api` and
  log in through `https://account.example.com`.
- `patch-extension-manifests.py` adds `*.example.com` next to the `proton.me`
  patterns in the manifests (`externally_connectable`, content-script matches).
  Without it the account page cannot hand the session to the extension.
- Login uses Proton's **account app**: it does the SRP login and then forks the
  session to the extension (`auth/v4/sessions/forks`). Build
  `applications/account` from the same checkout and serve it at
  `account.example.com` (see `docs/deployment.md`).

## Pass web app

Build `applications/pass` from WebClients with the API pointed at your domain
(see the WebClients README; local development uses
`pnpm run start-all --applications "proton-pass" --api <env>`). Serve it at
`pass.example.com`. It finds the account app at `account.<same domain>`.

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
passhost exposes token management at `account/v4/personal-access-token`. The
token's keys are created client-side; see `docs/api.md`.

## iOS

Only QA builds of `protonpass/ios-pass` read the custom-environment settings.
App Store builds always use Proton's servers.

## SRP modulus

Clients only accept an SRP modulus signed with Proton's modulus key. By default
passhost serves the modulus Proton already published and signed. It is a public
2048-bit safe prime, so reusing it costs no security, and no client needs a
patch for it. To use your own, set `srp_modulus_file` to a clearsigned modulus
and replace the modulus public key in your client builds.

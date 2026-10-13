# Browser trust on Linux and macOS

Browser acceptance targets native Google Chrome on Ubuntu 24.04 and macOS arm64.
Use a local HTTP backend and one configured `<name>.sandbar.localhost` route.
NetBox is an optional application example. Sandbar needs no NetBox-specific settings or code.
Firefox, Java, and other browser package formats are outside this acceptance target.
macOS support is available from the unreleased checkout. Published beta.2 is Linux-only.
Real macOS service, browser trust, trust removal, and login acceptance remain pending until separately checked.

## Start and request trust

Complete [Linux service setup](install.md#connect-the-standard-caddy-service) or [macOS setup](install.md#connect-homebrew-caddy-on-macos) first.
For an existing beta.1 router, follow the [migration guide](install.md#upgrade-from-the-private-router).
Run the backend on `127.0.0.1:8000`, then add its app name:

```sh
sandbar add app.sandbar.localhost 8000
sandbar trust
```

Use the same `--home <directory>` or `SANDBAR_HOME` for every command when selecting another Sandbar home.
The HTTP URL redirects to `https://app.sandbar.localhost`.
The backend must be running before browser verification.

Installed `trust` uses CA ID `sandbar` at the selected service's private admin socket.
On Linux that endpoint is `unix//var/lib/sandbar/admin/admin.sock`. macOS uses its Application Support state.
Development `trust` uses CA ID `local` at the selected home's private socket.
The selected Caddy router must be running. Sandbar does not start it or try another endpoint.
Installation, setup, migration, initialization, route changes, start, and stop do not change trust stores.

Run Sandbar as your normal user. Caddy can request elevated access through its standard privilege mechanism.
Sandbar forwards standard input, output, diagnostics, and Caddy's exit status.
Sandbar does not collect passwords, invoke its own privilege helper, or install packages.
Avoid running the whole CLI with `sudo`, which can change user-store selection and file ownership.

Installed use selects the service's Sandbar CA. An explicit development home selects that home's CA. Trust commands inherit the caller's `HOME` and XDG environment.
**`--home` does not isolate user or system trust stores.**
Caddy can also attempt updates to available Firefox and Java stores.
Its command interface does not provide a store-selection flag.
Trusting the root authorizes certificates issued by that CA, beyond this one route.
Keep private CA keys private. Import only the public `root.crt`.

## Identify the exact root

`start`, `trust`, and `untrust` identify the public root certificate path.
Installed Linux public root: `/var/lib/sandbar/root.crt`.
Installed macOS public root: `~/Library/Application Support/sandbar/state/root.crt`.
With `--home <directory>`, it is `<directory>/state/caddy/pki/authorities/local/root.crt`.
The old beta defaults were `$XDG_STATE_HOME/sandbar/caddy/pki/authorities/local/root.crt`, or `~/.local/state/sandbar/caddy/pki/authorities/local/root.crt`.
Migration preserves that root's bytes and signing material under the installed `sandbar` authority.
Compare the old and installed root fingerprints after migration. Existing trust stays valid when the root is identical.
Migration does not import another root or replace the service's unrelated `local` CA.
See the [migration guide](install.md#upgrade-from-the-private-router) for cutover and rollback.
Use that printed path below:

```sh
root_cert='/replace/with/the/printed/root.crt'
openssl x509 -in "$root_cert" -noout -subject -issuer -serial -sha256 -fingerprint
```

Compare the SHA-256 fingerprint with the certificate shown in Chrome before importing or removing it.
Roots from different Sandbar homes can share the same display name. The name alone does not identify the certificate.
Retain the public root and its fingerprint until all trust removal is complete.

## Verify Chrome and import manually on Linux

Open `http://app.sandbar.localhost` in Chrome on the same machine as Sandbar.
Confirm the HTTPS URL, expected backend content, and absence of certificate warnings.
Successful Caddy delegation does not prove Chrome trust or mean that every optional store changed.

If Chrome on Linux reports `NET::ERR_CERT_AUTHORITY_INVALID`, open `chrome://certificate-manager` (Chrome 134 or later).
Use its certificate manager and the local or custom authority certificate controls.
Import the selected public `root.crt` as an authority trusted to identify websites.
Compare its SHA-256 fingerprint with the local file. Labels vary between Chrome versions.
Close the browser process and reopen it before repeating the request.
Do not bypass the warning, disable certificate checks, or import private keys.

Chrome on Linux uses an NSS shared database for local certificate management.
Current Chromium uses `~/.local/share/pki/nssdb`, but retains `~/.pki/nssdb` when that database already exists.
A separate browser profile alone does not isolate this database.
The [isolated browser proof](browser-proof.md) uses a separate process home and explicit temporary NSS database.
See [Chromium's Linux certificate guide](https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md) for certificate utility commands.

## macOS manual trust and removal

Chrome reads explicit local trust from the default and System keychains.
SSL trust can be set in Keychain Access. See [Chromium's platform trust rules](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md#how-does-the-chrome-certificate-verifier-integrate-with-platform-trust-stores-for-local-trust-decisions).
A separate Chrome profile does not isolate these keychains.
Ordinary tests never run the commands in this section.
Use manual steps only as a deliberate trust operation for the exact public root identified above.

After `sandbar trust`, check the route in a fresh Chrome process.
If Chrome still rejects the CA, open Keychain Access through Spotlight.
Choose the login keychain and import the selected public `root.crt`, then open that certificate.
Compare its SHA-256 fingerprint with `openssl x509` before changing trust.
Expand Trust and set Secure Sockets Layer (SSL) to Always Trust. Save and authenticate if macOS requests it.
Do not import a private key or change another certificate with the same display name.
See Apple's [certificate import](https://support.apple.com/guide/keychain-access/add-certificates-to-a-keychain-kyca2431/mac) and [trust settings](https://support.apple.com/guide/keychain-access/change-the-trust-settings-of-a-certificate-kyca11871/mac) guides.

The equivalent current-user command is available through macOS `security`:

```sh
security add-trusted-cert -r trustRoot -p ssl -k "$HOME/Library/Keychains/login.keychain-db" "$root_cert"
```

Run it as your normal user, with `root_cert` set to the exact printed public root path.
This changes user trust. It is not part of automated validation.
Record the keychain and trust domain you changed.
Caddy can also use the administrator trust domain. Do not infer which stores changed from command success alone.

When exact-root removal is separately requested, run `sandbar untrust` first.
Remove any manual user-domain trust for that same certificate with:

```sh
security remove-trusted-cert "$root_cert"
```

Only if you recorded trust in the administrator domain, remove that exact root's administrator trust with:

```sh
sudo security remove-trusted-cert -d "$root_cert"
```

These commands remove trust settings and can leave the certificate entry present.
Use Keychain Access to inspect the recorded keychain and compare the SHA-256 fingerprint before deleting any remaining manual import.
Preserve other roots, including those with the same display name.
Remove any separately imported authority in Chrome's certificate manager too, checking the fingerprint first.
Keep Caddy and the backend running, then verify certificate rejection in a fresh Chrome process.
Do not remove the installed CA automatically after a successful browser check.

## macOS browser acceptance

Run this checklist after requested installation and explicit trust setup.
Quit Chrome fully and confirm its process exits before each trust transition. A new window or profile is insufficient.
Record Chrome and macOS versions, the root fingerprint, and each result as pending or verified.

1. Run a generic backend and configure `app.sandbar.localhost` and `api.app.sandbar.localhost` to its port.
2. Open `http://app.sandbar.localhost/check.html?phase=trusted` with normal hostname resolution.
3. Confirm HTTP 308 followed by verified HTTPS on port 443, the expected backend content, and unchanged path and query.
4. Repeat for `http://api.app.sandbar.localhost/check.html?phase=trusted`. Confirm the nested name resolves and verifies.
5. Open `https://sandbar.localhost` and confirm the built-in welcome page remains available.
6. Only after a separate removal request, remove the exact root and any recorded manual imports, then repeat with a fresh Chrome process.
7. Confirm certificate rejection while the backend and Caddy remain reachable. A connection failure does not prove removal.

Do not use DNS overrides, hosts-file changes, proxy changes, warning exceptions, or certificate-error bypasses for browser acceptance.
Caddy command delegation, direct-root curl probes, and setup fixtures are separate evidence. They do not prove browser trust.
Unperformed service, browser, removal, and new-login checks stay pending without blocking development readiness.
The [installation checklist](development.md#macos-installation-acceptance) records service and login checks separately.

## Remove trust

Record the exact certificate fingerprint and each store used during setup, including manual imports.
Then remove Caddy-managed trust for the selected root.
Stopping is optional. Installed `sandbar stop` would stop every route Caddy serves:

```sh
sandbar untrust
```

`untrust` delegates `caddy untrust --cert <selected-root.crt>`.
It works after Caddy stops and does not need valid route configuration.
The stored public root must remain readable. Sandbar does not search other homes or regenerate a missing root.
Configuration, logs, the public certificate, and private CA keys remain intact.
Caddy can remove trust without deleting a certificate entry completely.
Repeated commands retain Caddy's result. They do not replace the CA or promise atomic changes across stores.

On Linux, remove any separately imported Chrome authority through the same certificate manager used for import.
On macOS, follow the exact-root keychain steps above and review any separate Chrome imports.
Compare the SHA-256 fingerprint before removing it. Preserve other roots with the same display name.
Review any Firefox or Java stores used during setup, even though their browser or application acceptance is outside the current native acceptance target.
After removal, start the selected router and backend again, then use a fresh Chrome process to verify certificate rejection.
A connection failure while Caddy is stopped does not prove that trust was removed.
Successful `untrust` alone does not prove that Chrome or every other store stopped trusting the root.

## Diagnose incomplete setup

A nonzero Caddy result remains a failure. Some stores might already have changed before that failure.
Read its diagnostics and retain the root certificate for recovery.
Complete removal in every store used during setup before retrying or abandoning it.
Sandbar does not roll back partial changes or infer individual store results from Caddy's output.

Name resolution, connection errors, certificate errors, and backend responses describe different problems:

- `.localhost` reserves loopback names. It establishes no certificate trust and requires no public domain registration.
- A name-resolution or proxy error requires checking the supported local client and its proxy settings.
- A connection error requires checking the backend, Caddy, and configured ports.
- A certificate authority error requires checking the exact CA and Chrome's applicable trust store.
- An application error can require backend allowed-host or CSRF settings. These remain application configuration.

Trust belongs on the browser's machine. This guide assumes the browser and Sandbar run locally together.
Sandbar does not modify DNS, `/etc/hosts`, proxy settings, or browser security settings to fix client restrictions.

See [Caddy trust](https://caddyserver.com/docs/command-line#caddy-trust) and [Caddy untrust](https://caddyserver.com/docs/command-line#caddy-untrust) for the delegated interfaces.

# Browser trust on Ubuntu

Browser acceptance targets Ubuntu 24.04 and Google Chrome installed from its native Debian package.
Use a local HTTP backend and one configured `<name>.sandbar.localhost` route.
NetBox is an optional application example. Sandbar needs no NetBox-specific settings or code.
Firefox, Java, macOS, and other browser package formats are outside this acceptance target.

## Start and request trust

Complete [service setup](install.md#connect-the-standard-caddy-service) with the current source version first.
The released `v0.1.0-beta.1` still uses a private router and has no service setup command.
Run the backend on `127.0.0.1:8000`, then add its app name:

```sh
sandbar add app.sandbar.localhost 8000
sandbar trust
```

Use the same `--home <directory>` or `SANDBAR_HOME` for every command when selecting another Sandbar home.
The HTTP URL redirects to `https://app.sandbar.localhost`.
The backend must be running before browser verification.

Installed `trust` uses CA ID `sandbar` at `unix//var/lib/sandbar/admin/admin.sock`.
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
Installed public root: `/var/lib/sandbar/root.crt`.
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

## Verify Chrome and import manually if needed

Open `http://app.sandbar.localhost` in Chrome on the same machine as Sandbar.
Confirm the HTTPS URL, expected backend content, and absence of certificate warnings.
Successful Caddy delegation does not prove Chrome trust or mean that every optional store changed.

If Chrome reports `NET::ERR_CERT_AUTHORITY_INVALID`, open `chrome://settings/certificates`.
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

Remove any separately imported Chrome authority through the same certificate manager used for import.
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

# Sandbar user reference

These commands describe apt/systemd on Linux and unreleased Homebrew user-service support on macOS arm64.
Beta.1 uses a private user router. See [installation and migration](install.md) before upgrading.

## App names and addresses

App names must be below `.sandbar.localhost`, such as `app.sandbar.localhost`.
Names normalize to lowercase. Duplicate names after normalization are rejected.
Sandbar routes accept connections only from this computer through IPv4 and available IPv6 loopback addresses.
Sandbar does not edit DNS or hosts files. Clients and proxies can handle `.localhost` names differently.
Your app may need allowed-host and CSRF-origin settings for its new name.

| Input | Stored address |
| --- | --- |
| `8000` | `http://127.0.0.1:8000` |
| `localhost:8000` | `http://localhost:8000` |
| `[::1]:8000` | `http://[::1]:8000` |
| `https://127.0.0.1:9443` | `https://127.0.0.1:9443` |

Only `localhost` and loopback IP addresses, which refer to this computer, are allowed.
IPv6 addresses must use brackets.
Credentials, paths, trailing slashes, queries, and fragments are rejected.
Each app port must differ from both router ports.
HTTP(S) URLs may omit their port when the default differs from both router ports.
Caddy verifies certificates for HTTPS apps. Custom app trust settings are not supported.

## Route changes

`add` succeeds unchanged for identical normalized version 2 settings. A different address requires `--replace`.
`rm` rejects unknown names. Removing the final app keeps the installed welcome page and certificates.
Removing a route never removes certificate trust.

Candidates are checked with Caddy before saving. Changes apply without restarting a running Caddy.
When stopped, changes are saved without starting Caddy. Use `sandbar start` when ready.
A rejected `reload` keeps your edited source for correction and leaves active routes unchanged.
On Linux, ordinary commands need no sudo after setup and logging out and back in.
A new terminal pane is not a new login session and may retain the old groups.
On macOS, setup and ordinary commands run as the current user.
`stop` affects every Caddy route, including unrelated sites.
Linux stop preserves boot startup. macOS stop removes login registration, and start registers it again.
The macOS user service does not provide boot-before-login operation.

## Read status results

`status` reports service state, startup registration, and access to Caddy's private control socket.
Startup means boot enablement on Linux and login registration on macOS.
Development status checks the selected private router.
It reports pending source edits, differences from active configuration, and pending recovery.

Each configured app check sends HTTPS `HEAD /` through IPv4 loopback, with a three-second limit.
It uses the configured hostname, verifies against the selected root certificate, and bypasses proxy settings.
It does not follow redirects. Stopped routers report apps as unchecked.
HTTP codes appear separately from TLS and connection errors.
HTTP 5xx means failure. Other HTTP responses show reachability, not application health.

The exit code is nonzero for stopped or inaccessible routers, incomplete startup setup, pending configuration or recovery, or failed checks.
Invalid configuration and missing required root certificates are errors.
The built-in welcome page is separate from configured app checks.
Status does not prove browser trust, system DNS resolution, or operating-system listeners.
See the [browser guide](browser-trust.md) for explicit trust, manual imports, and removal.

## Configuration

| Platform | Installed app list | Installed state |
| --- | --- | --- |
| Linux | `/etc/sandbar/config.json` | `/var/lib/sandbar` |
| macOS | `~/Library/Application Support/sandbar/config.json` | `~/Library/Application Support/sandbar/state` |

macOS owned directories use `0700` and private files use `0600` under the current user.
Without a home override, commands use the standard service.
An explicit `--home`, or `SANDBAR_HOME` when the flag is absent, selects a [private development router](development.md#private-development-homes).

Edit the app list, then run `sandbar reload` while running or `sandbar start` while stopped.
Do not edit generated Caddy files.
`init` creates an empty version 2 configuration and preserves matching existing settings.
The `init <hostname> <app-address>` form remains available for a new configuration.
Installed use requires completed setup. Private development initialization does not require Caddy.
Options must precede positional arguments.

```json
{
  "version": 2,
  "http_port": 80,
  "https_port": 443,
  "routes": [
    {"hostname": "app.sandbar.localhost", "upstream": "http://127.0.0.1:8000"}
  ]
}
```

The JSON above shows fresh installed defaults. Linux installed routes must keep ports 80 and 443.
macOS setup can select other installed ports with `--http-port` and `--https-port`.
For example, `sandbar setup --http-port 8080 --https-port 8443` saves those ports for future commands.
Repeated setup without port options retains saved ports. An omitted option uses its fresh default only when no value exists.
These settings affect Caddy's shared HTTP/HTTPS ports. Setup rejects conflicting existing explicit settings.
Use setup to change installed macOS ports, and use `init` port options only with an explicit development home.
With HTTP 8080 and HTTPS 8443, visit `http://app.sandbar.localhost:8080` or `https://app.sandbar.localhost:8443`.
App backends must use other ports.
An empty `routes` list is valid. The built-in welcome site is outside this list and `sandbar ls`.
Unknown fields and invalid ports are rejected.
Version 1 remains readable. A successful `add` or `rm` converts it to version 2.
Conversion first saves the exact source in `config.v1.backup.json` beside `config.json`.
An identical version 1 addition also performs this conversion.

Linux keeps `/etc/caddy/Caddyfile`. macOS keeps `<Homebrew prefix>/etc/Caddyfile`.
Setup adds marked imports and preserves unrelated supported sites and settings.
Everyday commands change only Sandbar's owned route file.
Read [supported Caddy configurations](install.md#supported-caddy-configurations) before combining sites.

## Router state and recovery

One installed lock serializes route changes. Private homes have separate locks.
Linux shared files may belong to their last writer while retaining the `sandbar` group and required access modes.
macOS state belongs only to the current user.
Caddy keeps installed CA keys in its service storage, preserving unrelated CAs.
Linux exports its public root to `/var/lib/sandbar/root.crt`.
macOS reads the original at `<verified Caddy storage>/pki/authorities/sandbar/root.crt`, without a state copy or symlink.
Use the root path printed by Sandbar. Setup checks, status probes, and untrust use that original file.
A missing or unreadable macOS original is an error, even when an old copy remains in Sandbar state.
See [unused macOS root cleanup](install.md#remove-an-unused-macos-root-copy) before deleting an earlier copy.
Private development routers use separate logs, control sockets, and certificates.
An active or inaccessible private socket prevents another private start.
Use `journalctl -u caddy.service` for Linux logs. macOS uses `<Homebrew prefix>/var/log/caddy.log`.
Sandbar reports the verified log path.

Sandbar saves previous and candidate files before publication or reload.
Recovery runs before initialization, route changes, and startup.
It checks active Caddy configuration to finish a confirmed change or restore the previous state.
Unknown active state, conflicting edits, or changed installation identity preserve recovery files and block mutations.

Recovery files stay under `transaction/` in the selected state directory until recovery succeeds.
They include `journal.json`, previous and candidate source and generated files, and adapted configuration copies when available.
Errors name the conflict and recovery directory.
Keep these files while comparing your edits with both saved states. They may contain private service configuration.
Correct the reported conflict without discarding needed edits, then retry the command or `start`.
`status` reports pending recovery without changing it.
`stop` and `untrust` remain available with invalid source or recovery state.

Avoid external Caddy edits and commands while a Sandbar change runs.
Other commands do not take Sandbar's lock. Sandbar detects observable conflicts but cannot coordinate arbitrary administrator actions atomically.
Changed external inputs require review and explicit setup reconciliation before another route change.
For one-time setup or migration failures, use the separate [manual recovery guide](install.md#setup-and-migration-recovery).

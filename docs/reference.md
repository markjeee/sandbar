# Sandbar user reference

These beta.4 commands describe apt/systemd on Linux and Homebrew Caddy with a Sandbar-managed user LaunchAgent on macOS arm64.
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

`add` succeeds unchanged for identical normalized version 2 or 3 settings. A different address requires `--replace`.
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
Homebrew supplies the Caddy package. Use Sandbar to control its service after setup.
The `local.sandbar.caddy` job owns HTTP TCP and HTTPS TCP/UDP loopback sockets.
Stop unloads this job and releases its sockets. Requests cannot restart it after a successful stop.
Start uses the retained private template to restore the login copy. Reload retains the job and Caddy PID.

On installed Linux and macOS, `sandbar start` restarts a failed owned service when its private admin endpoint is absent or refuses connections.
Sandbar resolves pending route recovery first, then stops the failed service before applying saved routes and starting it.
Unresolved recovery, ambiguous admin access, or failed shutdown blocks restart without replacing route files.

## Inspect and diagnose

| Command | Purpose |
| --- | --- |
| `sandbar config --path` | Print the absolute source path, including before setup. |
| `sandbar config --print` | Print the exact source bytes, including readable invalid JSON. |
| `sandbar status` | Summarize local service, routes, pending state, and current-user Teleport connections. |
| `sandbar doctor` | Check configuration, listeners, resolution, HTTPS, trust, and Teleport transport separately. |

These commands observe state without creating files, changing permissions, repairing state, or opening SSH connections.
They do not change services or trust stores. Normal HTTPS requests can still cause server logs or certificate issuance.
Observations are snapshots and can become stale during concurrent changes.

Use exactly one config option. Missing or unreadable source makes `config --print` fail with its path.
Printing does not validate, normalize, upgrade, or substitute generated configuration.
Both config operations work without Caddy. `config --path` does not require an existing source file.

```sh
sandbar config --path
sandbar config --print
sandbar --home .sandbox/home config --path
sandbar --home .sandbox/home config --print
sandbar --home .sandbox/home status
sandbar --home .sandbox/home doctor
```

Global `--home` takes priority over `SANDBAR_HOME`. Without either, use the installed platform source.
Relative homes print as absolute paths. Suggested corrective commands retain the absolute selected home, with shell quoting.

## Read status results

`status` reports service state, startup registration, and access to Caddy's private control socket.
Startup means boot enablement on Linux and login registration on macOS.
macOS reports Caddy process state, registration, and launchd socket ownership separately.
Open sockets alone do not establish working routing because launchd can own them while Caddy has failed.
Development status checks the selected private router.
It reports pending source edits, differences from active configuration, and pending recovery.

Each configured app check sends HTTPS `HEAD /` through IPv4 loopback, with a three-second limit.
It uses the configured hostname, verifies against the selected root certificate, and bypasses proxy settings.
It does not follow redirects. Stopped routers report apps as unchecked.
HTTP codes appear separately from TLS and connection errors.
HTTP 5xx means failure. Other HTTP responses show reachability, not application health.

Status also lists registered Teleport machines in name order, with their local welcome URLs and current-user SSH connection states.
`connected` means the existing SSH control check passed. It does not prove forwarded HTTPS or remote app health.
`disconnected` means no control connection exists and includes an explicit `teleport connect` command.
`unknown` includes the reason inspection could not establish the state. It does not mean connected or healthy.
Disconnected and unknown destinations alone do not change the exit code. Status never connects them.

The exit code is nonzero for stopped or inaccessible routers, incomplete startup setup, pending configuration or recovery, or failed checks.
Invalid configuration and missing required root certificates are errors.
The built-in welcome page is separate from configured app checks.
Status does not prove browser trust, system DNS resolution, or operating-system listeners.
See the [browser guide](browser-trust.md) for explicit trust, manual imports, and removal.

## Read doctor results

Doctor continues independent checks when a prerequisite fails. Skipped checks identify the unavailable prerequisite.
It does not reload configuration, resolve recovery, connect destinations, or request administrator access.
Run suggested corrective commands separately after reviewing the result.

| Result | Meaning | Exit contribution |
| --- | --- | --- |
| `pass` | The stated check succeeded. | None |
| `failure` | A required input or attempted compatibility, service, connection, or TLS check failed. | Nonzero |
| `warning` | An actionable condition, including a disconnected destination. | None |
| `unknown` | Inspection cannot establish the result, including unavailable optional tools. | None |
| `not applicable` | The selected mode or configuration does not use this check. | None |

No failures observed does not mean every layer was verified. Missing or invalid source, incompatible Caddy, and incomplete setup are failures.
Local HTTPS, private admin requests, and system resolution each have three-second bounds.
Forwarded welcome requests have five-second bounds. Native and SSH subprocesses each have a 30-second bound.
Total time grows with configured routes and destinations. Doctor does not retry automatically.

System resolution reports addresses or errors separately from direct IPv4 and available IPv6 loopback HTTPS.
Direct local checks send `HEAD /`, retain the configured hostname, bypass proxies, and do not follow redirects.
HTTP 5xx indicates failure. Other responses show reachability, not app health.
Unsupported IPv6 alone does not fail an explicitly IPv4-only router.

Doctor prints the public CA path and SHA-256 certificate fingerprint.
It separates selected-root verification from the current process's system verifier.
Neither result proves browser trust. Use explicit `sandbar trust` and the [browser guide](browser-trust.md) when appropriate.
A private home selects its CA but does not isolate trust stores.

Connected Teleport destinations receive a forwarded machine-welcome check with their saved CA and expected hostname.
A successful SSH control check can coexist with a failed forwarded HTTPS check.
Disconnected destinations skip the forwarded check and show the explicit selected-context connect command without causing failure alone.
Doctor does not discover remote apps or prove their health.

Native listener inspection reports available TCP and UDP ownership for selected ports.
Launchd can own macOS sockets. Missing tools or owner access remain unknown without elevation or installation.
Proxy observations name applicable environment variables without exposing their values or credentials.
Direct checks cannot prove browser proxy behavior. Doctor does not audit every firewall or network policy or infer a specific firewall cause.

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
`init` creates an empty version 3 configuration and preserves existing routes and listener ports.
The `init <hostname> <app-address>` form remains available for a new configuration.
Installed use requires completed setup. Fresh private development initialization does not require Caddy. Upgrading version 1 or 2 source requires Caddy validation.
Options must precede positional arguments.

```json
{
  "version": 3,
  "machine": "mark-pro4",
  "teleports": [],
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
Migration to the Sandbar job retains saved ports unless explicit setup flags change them.
The socket plan is saved during setup. Use setup to change installed macOS ports, and use `init` port options only with an explicit development home.
With HTTP 8080 and HTTPS 8443, visit `http://app.sandbar.localhost:8080` or `https://app.sandbar.localhost:8443`.
App backends must use other ports.
An empty `routes` list is valid. The built-in welcome site is outside this list and `sandbar ls`.
Unknown fields and invalid ports are rejected.
Version 1 remains readable. A successful `add` or `rm` converts it to version 2.
Conversion first saves the exact source in `config.v1.backup.json` beside `config.json`.
An identical version 1 addition also performs this conversion.

## Machine identity and local aliases

Setup and development `init` save a machine name automatically.
The initial suggestion is the lowercase first label from the OS hostname.
Use `--machine <name>` to select a different initial name, or when the suggestion is invalid.
Names must contain one ASCII DNS label, with at most 55 characters.
Saved identity stays unchanged after an OS rename. Changing an established name is not supported.

```sh
sandbar setup --machine mark-pro4
sandbar --home /tmp/sandbar-demo init --machine demo --http-port 18080 --https-port 18443
```

Every canonical app gains an alias automatically.
For machine `mark-pro4`, `app.sandbar.localhost` also serves `app.sandbar-mark-pro4.localhost`.
Nested names retain all labels, such as `api.app.sandbar-mark-pro4.localhost`.
Both names reach the same backend directly, without SSH or a redirect to the canonical hostname.
The backend receives the requested hostname and browser-facing port.
Add, replace, and remove canonical routes. Their aliases change together and do not appear in `ls`.

Installed routers serve both `sandbar.localhost` and `sandbar-<machine>.localhost` as static welcome pages.
Version 3 private homes serve only the machine-qualified welcome, alongside configured apps.
For the private example above, visit `https://sandbar-demo.localhost:18443`.
Installed mark-pro4 uses `https://sandbar-mark-pro4.localhost` on HTTPS 443.

Configure apps to accept their canonical and machine-qualified URLs.
Review allowed hosts, redirects, cookies, CSRF origins, and login callback settings.
Sandbar does not rewrite application URLs or response bodies.
Identical full URLs on two machines need matching browser-facing HTTPS ports.

`teleport info --json` describes a prepared peer without changing it.
It returns protocol version 1, saved machine identity, HTTPS port, and the selected public root PEM.
Use `--home` before `teleport` for a private development peer.
Installed peers require completed setup. Private peers require initialized version 3 source and an existing public CA.
Start the private router once to create its CA. The metadata command does not create certificates or read private keys.

## Upgrade existing source

Versions 1 and 2 remain readable for local commands.
Run setup for installed upgrades, or explicit development `init` for a private upgrade.
The upgrade preserves routes, saved ports, and CA identity, then enables automatic aliases.
A failed Caddy validation leaves accepted source and active routes unchanged.
Read-only commands do not upgrade source. Version 3 app changes retain destination settings.
Older Sandbar binaries cannot read version 3 source.

Development upgrades reuse the route transaction and save the original source beside `config.json` as `config.v1.backup.json` or `config.v2.backup.json`.
When an original generated file exists, the matching `config.v1.backup.Caddyfile` or `config.v2.backup.Caddyfile` is saved too.
An earlier version 1 to version 2 route conversion keeps its own version 1 backup.
Installed setup uses its existing setup backup, containing source and generated files with their modes and owners.

For rollback, stop the selected router and keep the accepted version 3 files separately.
Restore the source and generated files from the same upgrade backup before using an older binary.
If development initialization had no generated file before the upgrade, remove only the upgrade-generated Caddyfile after preserving it.
For installed rollback, restore all matched setup files and service state using [setup recovery](install.md#setup-and-migration-recovery).
Keep the original CA storage and trust. Do not combine source from one backup with generated configuration from another.

Linux keeps `/etc/caddy/Caddyfile`. macOS keeps `<Homebrew prefix>/etc/Caddyfile`.
Setup adds marked imports and preserves unrelated supported sites and settings.
Everyday commands change only Sandbar's owned route file.
Read [supported Caddy configurations](install.md#supported-caddy-configurations) before combining sites.

## Router state and recovery

One installed lock serializes route changes. Private homes have separate locks.
Linux shared files may belong to their last writer while retaining the `sandbar` group and required access modes.
macOS state belongs only to the current user.
The private restart template is `state/launchd/caddy.plist` under the installed home.
The registered login copy is `~/Library/LaunchAgents/local.sandbar.caddy.plist`.
Both job definitions and saved identity must agree before installed mutations.
The original Homebrew job must remain disabled after migration. Competing ownership blocks changes.
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

## Installed removal

Beta.4 provides `sandbar uninstall --check` for read-only preview and `sandbar uninstall --yes` for confirmed cleanup. Run the command as your normal user without `--home` or `SANDBAR_HOME`.
Linux requests ordinary administrator authorization for protected inspection and system cleanup. Trust and SSH actions retain the caller's environment.
The command keeps the CLI and refuses before mutation when the selected Caddy serves unrelated sites.
It removes saved routes, identity, registrations, owned runtime files, integration, backups, and the selected CA after successful untrust and shutdown.
It preserves unrelated files, packages, authorities, backends, remote machines, and private development homes.

Partial cleanup returns nonzero with completed actions, failures, and retained paths. No service, trust, or connection is restored automatically.
`stop` and `untrust` remain separate operations. Successful untrust alone does not establish removal of manual browser imports.
Fresh setup creates a new installation and CA. Peers need deliberate registration updates.
Read [installed removal and recovery](install.md#uninstall-installed-sandbar) before confirming cleanup.

## Teleport destinations

Setup and development initialization enable machine-qualified URLs automatically.
For example, `website.sandbar-mark-work-rise.localhost` routes locally on mark-work-rise and through a registered destination on another machine.
The alias keeps every app label, including `api.website.sandbar-mark-work-rise.localhost`.
Configure each app to accept its machine-qualified URL.

```sh
sandbar teleport register mark-work-rise
sandbar teleport ls
sandbar teleport disconnect mark-work-rise
sandbar teleport connect mark-work-rise
sandbar teleport rm mark-work-rise
```

Registration calls connect after saving the destination. A failed connect retains registration for explicit retry.
Disconnect retains its route. Removal disconnects and removes its route and destination proxy trust.
`ls` reports observed SSH state, not app health.
The invoking user owns the background connection. Boot, login, and Caddy lifecycle commands do not connect it.

See [Teleport](teleport.md) for direct SSH options, private files, app settings, trust, and error behavior.

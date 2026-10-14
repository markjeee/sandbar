# Install Sandbar

Beta.3 targets Linux amd64 and macOS arm64. Beta.1 and beta.2 assets remain Linux-only.
Linux uses apt-packaged Caddy with systemd, Polkit, and sudo. Ubuntu 24.04 is its acceptance target.
macOS uses native Homebrew Caddy and one Sandbar-managed current-user LaunchAgent.
Install prerequisites separately. Sandbar packages need no Go runtime.
Other Caddy packages, Intel Macs, and Windows are outside these integrations.
Automated native checks establish development readiness. Real macOS installation checks remain separate.

## Release installation

Install `v0.1.0-beta.3` on Linux amd64 or macOS arm64:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.3/install.sh | sh
```

The versioned installer downloads the matching archive and checks its SHA-256 checksum before replacing `sandbar`.
The checksum comes from the same HTTPS release. It checks transfer integrity, not an independent signature.

The destination defaults to `~/.local/bin` on Linux and `/usr/local/bin` on macOS. Select another directory with `--bin-dir`:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.3/install.sh | sh -s -- --bin-dir "$HOME/bin"
```

Make sure the selected directory is in `PATH`, or use the full executable path.
The installer does not edit shell profiles, install Caddy, start services, or change certificate trust.

macOS assets are unsigned and unnotarized. Local candidates do not establish public download availability.
Actual launchd startup after logout/login remains deferred. Registration and start/stop checks do not establish that result.

## Upgrade to beta.3

Installing beta.3 replaces only the executable. Preview and apply setup separately using the platform commands below.
Setup upgrades installed source to version 3 and saves a stable machine name, machine URLs, and Teleport settings.
Matching setup preserves routes, configured ports, CA identity, and existing trust.
Do not import the root again when its identity is unchanged. Request trust separately for a new CA.
Beta.1 users must follow [explicit private-router migration](#upgrade-from-the-private-router).

Older binaries cannot read version 3 configuration. Keep the setup backup reported during the upgrade.
Rollback requires matched source, generated configuration, setup files, and service state before using the old binary.
Keep original CA storage and trust. See [configuration upgrades and rollback](reference.md#upgrade-existing-source).
For a private development home, use its matched `config.v1.backup.json` or `config.v2.backup.json` and generated Caddyfile backup.

Both Teleport peers need beta.3 or another Teleport-capable build and prepared Caddy before registration.
Apps must accept their machine-qualified URLs, including allowed hosts, CSRF origins, redirects, cookies, and login settings.
See [Teleport](teleport.md) for commands and URL requirements. Registration configures only the connecting machine.

## Checkout installation

Use the Go version declared in `go.mod`. macOS also requires clang and the macOS SDK from Xcode or Command Line Tools.
Run `xcode-select --install` if either prerequisite is missing. Source builds use cgo on macOS and remain static on Linux.
Downloaded packages need no compiler, Go, Python, or separate helper executable.
Run the installer from a checkout:

```sh
sh ./install.sh
sh ./install.sh --bin-dir "$HOME/bin"
"$HOME/bin/sandbar" --version
```

The checkout installer builds the current local source, including uncommitted changes.
It locates source beside the script, so invocation from another working directory also works.
The source executable reports `development` unless the source version was changed.
The checkout installer builds for the host: darwin/arm64 on macOS or linux/amd64 on Linux.
macOS defaults to the regular executable `/usr/local/bin/sandbar`, without a symlink or application bundle.
Linux keeps `~/.local/bin/sandbar`. Both support `--bin-dir`.
Application configuration and state remain separate from the executable.

Build or download as your normal user. On macOS, the installer requests administrator access only if final publication needs it.
Do not run the complete checkout build with sudo.
Use a writable `--bin-dir` to avoid that request, and make sure that directory is in PATH.
The installer does not edit shell profiles.
Both methods reject unsupported operating systems and architectures.

Downloads, checksums, and builds finish before the executable is replaced.
The final temporary file shares the destination directory, so replacement uses an atomic rename.
A failed download, checksum check, or build preserves the installed executable.
The installer removes its temporary files when it exits.

## Connect Homebrew Caddy on macOS

Use native arm64 Homebrew Caddy v2.11.7 or a later v2 release.
Homebrew supplies the package. Sandbar manages the user LaunchAgent `local.sandbar.caddy` after explicit setup.
Sandbar verifies executable paths, configuration, storage, and service identity before changes.
An unregistered installation or verified standard Homebrew user job is supported.
A root-managed, foreign custom, or competing job must be resolved separately. Sandbar does not stop unrelated services or start a fallback router.

Run as the current user, without sudo:

```sh
sandbar setup --check --http-port 80 --https-port 443
sandbar setup --http-port 80 --https-port 443
```

Launchd opens HTTP TCP and HTTPS TCP/UDP sockets on `127.0.0.1` and available `::1`.
Caddy inherits these sockets and runs as your user. HTTP/1.1, HTTP/2, and HTTP/3 share the selected HTTPS port.
No root Caddy process, system LaunchDaemon, packet-filter rule, separate helper, or persistent Sandbar process is installed.
Use Sandbar for service commands after setup. Do not enable `brew services start caddy` alongside the Sandbar job.
Homebrew remains responsible for package installation and upgrades.

Fresh setup defaults to HTTP 80 and HTTPS 443. Existing installations keep saved ports when options are omitted.
For example, migration without flags retains saved 8080/8443. Moving to 80/443 requires the explicit flags above.
Custom ports remain available through `--http-port 8080 --https-port 8443`.
Selected ports persist for start, route changes, reload, and repeated setup.
Ports must be valid, distinct, and different from app backend ports.
Changing the socket plan requires setup. Reload cannot replace launchd's bound sockets.
Caddy HTTP/HTTPS settings affect shared configuration. Setup rejects conflicting explicit settings rather than replacing them.

Do not pass `--home` or set `SANDBAR_HOME` during setup.
Preview changes no files, services, sockets, or trust stores.
It reports old and new job labels, executable paths, selected sockets, job files, retained storage, backups, service actions, and conflicts.
Review the preview before applying. macOS does not accept Linux `--user`, `--migrate-config`, or `--migrate-state` options.
Binary installation alone does not migrate an existing Homebrew service.
The new CLI retains inspection and shutdown for an old setup. Mutations that need the new integration direct you to setup.

Setup creates a missing `<Homebrew prefix>/etc/Caddyfile` and preserves supported unrelated content.
`--replace-default-site` authorizes only a recognized stock welcome block. It never authorizes custom-site replacement.
Setup validates the complete runtime configuration before stopping the verified old Homebrew job.
Backups include changed files, prior job registration, and running state.
Setup waits for old-job removal before registering the replacement. It does not repeatedly retry activation.
Repeated matching setup preserves routes, CA identity, selected ports, and one owned job.
Ordinary failures unload the new job before restoring prior files, registration, and running state where safe.
Conflicting external edits remain intact. Failures report backup paths and unresolved restoration steps.

`sandbar start` validates committed configuration and restores the saved job and login registration when absent.
`sandbar reload` applies validated routes without replacing the job or Caddy process.
`sandbar stop` unloads the job, releases TCP/UDP sockets, and removes login registration.
Stop affects every route the selected Caddy serves, including unrelated sites. Requests cannot reactivate a successfully stopped job.
Stop retains the private job template, configuration, certificates, and trust. A later start restores registration.
This user service does not run before login. Registration alone does not prove startup after an actual later login.

The default installed layout is:

```text
/usr/local/bin/sandbar                         # Regular standalone executable
~/Library/Application Support/sandbar/
├── config.json                               # App list
└── state/
    ├── setup.json                            # Accepted installation and socket plan
    ├── launchd/caddy.plist                    # Private restart template
    └── backups/setup-<id>/backup.json         # Setup rollback record
~/Library/LaunchAgents/local.sandbar.caddy.plist # Login registration copy
```

A custom `--bin-dir` remains supported. Setup records the verified absolute CLI path for the job.
Moving that executable or changing its installation identity requires explicit setup reconciliation.
Owned directories use `0700`. Private files and the control socket permit only this user.
The Homebrew Caddyfile remains at `<prefix>/etc/Caddyfile`.
Caddy storage remains at `<prefix>/var/lib/caddy`, including the `sandbar` authority and unrelated CAs.
Sandbar reads the original public root at `<verified Caddy storage>/pki/authorities/sandbar/root.crt`.
A typical arm64 path is `/opt/homebrew/var/lib/caddy/pki/authorities/sandbar/root.crt`.
Use the root path printed by Sandbar. Setup, status probes, and untrust use this original file without a state copy or symlink.
Service logs remain at `<prefix>/var/log/caddy.log`. Sandbar reports the verified path.

With ports 80/443, open `https://sandbar.localhost` or `https://app.sandbar.localhost`.
HTTP redirects retain status 308, hostname, path, and query.
With custom ports 8080/8443, use `http://sandbar.localhost:8080` and `https://sandbar.localhost:8443`.
Redirects and HTTP/3 advertisement identify the selected HTTPS port. The job claims no other ports.
The static welcome page needs no backend and remains after removing the final app.
Service migration preserves the original CA and existing trust. It does not run trust or untrust.
For a fresh installation, request `sandbar trust` separately, then follow the [macOS browser steps](browser-trust.md#macos-manual-trust-and-removal).
Stopping or removing the executable does not remove certificates, routes, or trust.
There is no automatic macOS uninstaller. Preserve unrelated configuration and CA material during manual restoration.

Real service, browser trust, exact-root removal, and new-login checks remain pending until verified separately.
See the [installation checklist](development.md#macos-installation-acceptance) and [macOS setup recovery](#macos-setup-recovery).

## macOS setup recovery

Ordinary setup rollback removes the new job before restoring the previous configuration and service state.
Setup reports `~/Library/Application Support/sandbar/state/backups/setup-<id>/backup.json` for manual review.
Keep that private record, the original Caddy storage, and any reported diagnostics.
There is no automatic setup resumption or separate setup journal. Route transaction recovery remains separate.

Inspect both possible job owners without changing them:

```sh
launchctl print "gui/$(id -u)/local.sandbar.caddy"
launchctl print "gui/$(id -u)/sh.brew.caddy"
tail -n 100 /opt/homebrew/var/log/caddy.log
```

An absent job can make `launchctl print` return nonzero. Use the verified log path if your Homebrew prefix differs.
Compare current files with the backup record before restoring them. Its file entries retain original and published bytes.
Keep comparison output private because configuration can contain secrets. Preserve external edits made after setup began.

If the replacement job still owns the sockets, unload it before restoring any prior files or restarting Homebrew Caddy:

```sh
launchctl bootout "gui/$(id -u)/local.sandbar.caddy"
```

Confirm removal and listener closure. Review the login copy before removing or restoring it from the record.
Restore the matched Caddyfile, source, generated files, setup record, and job files together, keeping recorded modes and owners.
A path that did not previously exist needs removal only after checking the record and preserving later edits.
Do not restore old source alone while a different generated configuration or job remains active.
Only restore the previous Homebrew registration and running state recorded in the backup after files and sockets are restored.
For a previously running and registered standard Homebrew job, its supported start command is `brew services start caddy`.
Do not start both jobs. Do not start a previously stopped service merely to reproduce registration.
If prior registration and running state differ, follow the reported restoration steps rather than guessing a service command.
Verify the old routes with the original CA before retrying setup or removing backups.
Keep existing trust, CA keys, unrelated CAs, and external configuration unchanged.

## Remove an unused macOS root copy

After installing the updated CLI, an earlier `~/Library/Application Support/sandbar/state/root.crt` becomes unused.
Fresh setup does not create it, and repeated setup leaves any old copy untouched.
Sandbar uses Caddy's original even if the old copy differs. A missing or unreadable original causes an error without fallback.

Before manual cleanup, use the original root path printed by the updated CLI.
Check that it is readable and compare both certificate identities:

```sh
root_cert='/replace/with/the/printed/original/root.crt'
old_root="$HOME/Library/Application Support/sandbar/state/root.crt"
test -r "$root_cert"
openssl x509 -in "$root_cert" -noout -subject -issuer -serial -sha256 -fingerprint
openssl x509 -in "$old_root" -noout -subject -issuer -serial -sha256 -fingerprint
```

Continue only if the original is readable, both certificate commands succeed, and their SHA-256 fingerprints match.
If they differ, keep the old certificate and its fingerprint for a separately requested trust cleanup.
If the old file is absent, no cleanup is needed.
After confirming a match, remove only the unused copy:

```sh
rm -- "$old_root"
```

Deleting this duplicate does not remove trust and requires no certificate import or trust removal.
Keep Caddy's original root, private keys, storage permissions, unrelated CAs, and historical setup backups unchanged.
The original remains available for status checks and untrust while Caddy is stopped.
Sandbar does not perform this cleanup automatically.

## Connect the standard Caddy service

This section applies to apt/systemd on Linux amd64.

Install apt-packaged [Caddy](https://caddyserver.com/docs/install) v2.11.7 or a later stable v2 release first.
The integration checks package and service metadata, not just whether `apt` or `systemctl` exists.
Unsupported packages or customized service layouts fail before changes. There is no private-router fallback.

Run setup as an administrator with an explicit existing non-root user.
Use the absolute Sandbar executable path because sudo may omit `~/.local/bin` from PATH.
Preview first:

```sh
sudo "$HOME/.local/bin/sandbar" setup --check --user "$USER"
```

Preview changes no files, services, permissions, or trust.
It shows prerequisites, affected files, backups, access grants, boot startup, and any required service restart.
Review its output and resolve conflicts before applying setup.
Do not pass `--home` or set `SANDBAR_HOME` for setup. Those select private development routers for ordinary commands.

For Caddy's recognized stock welcome site:

```sh
sudo "$HOME/.local/bin/sandbar" setup --user "$USER" --replace-default-site
```

`--replace-default-site` authorizes only the recognized stock site, including its `/usr/share/caddy` root and file server.
Setup backs up the exact configuration and preserves comments and bytes outside its owned changes.
It does not overwrite package page files or disable `caddy.service`.
Without the option, a conflicting stock site blocks setup and reports the replacement command.
Custom sites remain protected. A customized conflicting block requires manual review, even with this option.

If there is no stock-site conflict, use `setup --user "$USER"` without the replacement option.
Setup creates an empty app list unless you select legacy migration.
Matching repeated setup preserves existing routes and certificates without duplicate imports or membership.

**Log out and log back in after setup** so the account receives its group membership.
A new terminal tab or pane does not refresh the groups inherited from an existing desktop session.
Ordinary commands then work without sudo or a password prompt:

```sh
sandbar status
sandbar add netbox.sandbar.localhost 8000
```

Setup enables and starts the packaged `caddy.service` as `caddy`.
Its existing low-port permissions remain in place. There is no Sandbar service or installed private router.
The service reads durable configuration at boot without a user login.
`stop` stops all Caddy routes but does not disable boot startup.
Use `journalctl -u caddy.service` for service diagnostics.

Open `https://sandbar.localhost` before or after adding apps.
Caddy serves this static welcome page directly on local addresses, without a backend.
The page stays available after the final app is removed. It is outside the JSON app list and `sandbar ls`.
HTTP port 80 redirects to HTTPS port 443. Linux installed ports are fixed. macOS setup and private development homes support explicit port selections.

Setup does not install certificate trust. Use `sandbar trust` explicitly as your normal user.
Read the [browser guide](browser-trust.md), then verify the page and app in your browser.

## Access and removal

This section applies to Linux access grants. macOS uses the invoking user without a shared group or policy.

Setup adds the named account to the `sandbar` group without replacing its other memberships.
Members can change Sandbar's app list, generated routes, and private Caddy control socket.
**This is access to all Caddy routes and files the Caddy service can read.**
It is not a security boundary between apps or administrators.
Grant membership only to users who may administer the whole Caddy service.

The installed Polkit rule permits only start, stop, and reload of `caddy.service` for group members.
It does not permit restart, other units, unit-file edits, service environment changes, or general root commands.
Shared mutable files may belong to the last user who wrote them.
Their `sandbar` group and required access modes remain in place so other authorized users and Caddy retain access.
The group cannot edit the service unit, drop-in, access policies, or packaged Caddy executable through this grant.

Full configuration checks can need service certificate keys.
A separate sudo rule permits exactly this command as `caddy`, never as root:

```text
/usr/bin/caddy validate --config /var/lib/sandbar/validation/Caddyfile --adapter caddyfile
```

Sandbar runs it noninteractively with a clean environment and the service account's home.
The rule grants no shell, alternate executable, extra arguments, other candidate path, or arbitrary environment settings.
Setup checks the rule with `visudo`. Private keys stay restricted to the service account and administrators.
Trust commands retain their separate permission checks.

To revoke one user's access, an administrator removes that membership:

```sh
sudo gpasswd -d alice sandbar
```

Replace `alice` with the account to revoke. End its existing sessions because running processes retain their groups.
This does not remove browser trust or routes. Keep the shared policy while another authorized user needs it.
An administrator can remove Sandbar-owned Polkit and sudo policy files after the final user's access ends.
The owned policy paths are `/etc/polkit-1/rules.d/50-sandbar.rules` and `/etc/sudoers.d/sandbar-caddy-validate`.
After revoking all human users, an administrator can remove them:

```sh
sudo rm -- /etc/polkit-1/rules.d/50-sandbar.rules /etc/sudoers.d/sandbar-caddy-validate
```

Keep the service integration, `caddy` membership, and group while Caddy still serves Sandbar routes.
Do not remove unrelated policies or Caddy configuration as part of access removal.
See [browser trust removal](browser-trust.md#remove-trust) for the separate certificate step.

## Supported Caddy configurations

Linux keeps `/etc/caddy/Caddyfile` as its main configuration.
macOS keeps `<Homebrew prefix>/etc/Caddyfile` and private integration files in Application Support.
Setup adds marked imports for owned global integration and generated routes. Linux routes use `/var/lib/sandbar/routes/Caddyfile`.
It preserves unrelated configuration bytes and Caddy's existing `local` CA.
Sandbar uses the separate CA ID `sandbar`. Private development homes keep CA ID `local`.

Normal top-level global blocks and static imports are supported when the complete configuration passes validation and safety checks.
Relative imports keep their source directory. Static glob membership is recorded for later drift checks.
All relevant inputs must be readable by authorized Sandbar administrators.
Setup does not widen permissions on unrelated secrets.

Hostname overlap, wildcard listener conflicts, admin endpoint conflicts, or a conflicting `sandbar` CA block integration.
Unrelated sites need compatible nonconflicting listeners.
On macOS, shared loopback HTTP routes retain their handlers through the inherited listener.
Independent listeners remain unchanged. Explicit compatible protocol restrictions remain effective.
TLS sites whose automatic redirect listeners conflict with inherited sockets block migration before the old service stops.
Sandbar reports the conflicting site or listener. It does not globally disable redirects or silently rebind unrelated sites.
Dynamic imports, unsupported adapters, custom storage, ambiguous syntax, and required custom service environments need manual integration review.
Sandbar reports the affected inputs rather than rewriting unsupported configurations.
`--replace-default-site` never authorizes deletion of custom sites.

Avoid external Caddy edits during Sandbar changes. Other commands do not use Sandbar's lock.
Sandbar detects observable conflicts but cannot promise atomic coordination with unrelated administrator actions.
After changing an external input, review the complete configuration and reconcile through explicit setup before more route changes.
Do not edit Sandbar's generated route file directly.
For everyday route recovery, follow the [user reference](reference.md#router-state-and-recovery).

## Upgrade from the private router

This legacy migration applies to Linux. macOS does not import legacy Linux state.

Beta.1 uses a private router. Beta.2 uses the standard Caddy service by default.
Installing beta.2 does not migrate routes, stop the old router, or change trust.
Back up the old executable and record its version before installing beta.2.
Record the old configuration path, state directory, CA fingerprint, and command used to start its router.
Keep the legacy configuration and signing files protected and available until migration is verified.
Resolve any existing route transaction recovery with the legacy version before migration.

Supply both legacy paths explicitly. These examples use the old Linux defaults:

```sh
sudo "$HOME/.local/bin/sandbar" setup --check --user "$USER" \
  --migrate-config "$HOME/.config/sandbar/config.json" \
  --migrate-state "$HOME/.local/state/sandbar" \
  --replace-default-site
```

Review the preview, then repeat the same command without `--check` to apply.
Use your actual XDG paths or private home paths if they differ.
Do not pass `--home` to privileged setup. Migration does not silently merge multiple homes.
If legacy default state exists without explicit paths, setup reports it and leaves the old router working.

Migration preserves hostnames, app addresses, root certificate bytes, and signing material.
Installed routes require HTTP port 80 and HTTPS port 443.
Legacy configurations with other router ports are rejected before cutover. Sandbar does not remap them automatically.
It copies only the selected CA material into the service's `sandbar` authority.
It does not copy private process or admin state, replace the unrelated `local` CA, or install trust.
Missing keys, a conflicting destination CA, or pending legacy route recovery blocks cutover.

The candidate is validated before the old router stops.
The routers cannot own the same ports together, so cutover causes a brief interruption.
Setup records prior service state and the legacy restart command, then backs up affected configuration and CA files.
It stops only the identified legacy router and verifies its unit command and home before controlling a temporary user service.
The matching `sandbar-router.service` is retired only after standard service routing and TLS succeed.
Other user services and development routers remain untouched.

Compare the root fingerprints before and after migration:

```sh
openssl x509 -in "$HOME/.local/state/sandbar/caddy/pki/authorities/local/root.crt" -noout -sha256 -fingerprint
openssl x509 -in /var/lib/sandbar/root.crt -noout -sha256 -fingerprint
sandbar status
```

The fingerprints must match. Verify your existing app with its existing browser trust.
Do not import another root merely because the CA storage path changed.
Keep backups until route, TLS, browser, service, and boot checks are complete.

## Setup and migration recovery

The following commands and backup paths apply to Linux. Use [macOS setup recovery](#macos-setup-recovery) for launchd migration.

Ordinary setup errors restore prior file and service state where safe.
Failed startup or migrated route verification also attempts to restart the identified legacy router.
Conflicting external edits are preserved. A failed rollback reports the remaining outage, backup paths, and manual steps.
Setup has no separate journal, automatic resumption, or migration recovery engine.
Everyday route transaction recovery remains separate and available.

If setup exits unexpectedly, inspect state before running more mutation commands:

```sh
systemctl status caddy.service --no-pager
systemctl is-enabled caddy.service
journalctl -u caddy.service --no-pager -n 100
systemctl --user status sandbar-router.service --no-pager
```

Run the user-service check as the legacy account. A collected temporary unit can already be absent.
Setup prints `/var/backups/sandbar-setup-<id>/backup.json`, restricted to root.
That file records previous file bytes, modes, owners, service state, and the legacy restart command.
Its `Files` entries contain base64-encoded `data` and `published` bytes, not separate ready-to-copy backup files.
Use the setup output and that record to identify exact original and replacement paths.
Compare current files with the backups before restoring anything. Preserve edits made after setup began.
Do not copy private keys into logs or broadly readable directories.

If the new service owns the old ports, stop it before restarting the old router:

```sh
sudo systemctl stop caddy.service
```

For each selected path, decode its original `data` into a protected review file.
This example extracts only `/etc/caddy/Caddyfile`. Replace the backup directory with the one printed by setup:

```sh
sudo python3 - /var/backups/sandbar-setup-REPLACE/backup.json /etc/caddy/Caddyfile <<'PYTHON'
import base64, json, os, sys
from pathlib import Path
record = Path(sys.argv[1])
entry = next(item for item in json.loads(record.read_text())['Files'] if item['path'] == sys.argv[2])
if entry['data'] is None:
    raise SystemExit('This file did not exist before setup. Review removal manually.')
target = record.parent / 'restore-file'
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as output:
    output.write(base64.b64decode(entry['data'], validate=True))
os.chown(target, entry['UID'], entry['GID'])
os.chmod(target, entry['mode'])
print(target)
PYTHON
```

Compare that protected file with the current path. Keep comparison output private because Caddy configuration may contain secrets.
After review, restore that one file with `sudo cp --preserve=mode,ownership` from the printed review path to its original path.
Use a new review filename before extracting another entry. Keep `backup.json` unchanged.
Restore each affected file only after reviewing its comparison.
Preserve the backup's owner and mode. Remove newly created integration files only when the backup record confirms their previous absence.
Restore the previous boot-enable state shown in the setup record.
Run `sudo systemctl daemon-reload` after restoring service drop-ins.
Restart the prior service only if it was previously active.

As an administrator, run the recorded legacy restart command.
It uses `runuser` to start packaged Caddy as the original user with the saved private Caddyfile and exact state environment.
It does not invoke the new installed Sandbar default mode.
The recorded command works without the collected temporary unit. `systemctl start` alone cannot recreate a missing transient unit.
Do not substitute the new default installed mode for that old private-router command.
Verify the prior HTTPS route using its original root before removing backups or retrying setup.
If the original state or restart command cannot be established, retain all evidence and resolve that uncertainty before cutover.

## Release preparation

Prepare beta.3 with `scripts/release`, or prepare a distinct unreleased native candidate:

```sh
scripts/release --version v0.1.0-beta.3-candidate
cd .sandbox/release/v0.1.0-beta.3-candidate
```

On macOS arm64, verify the package and system-only dynamic linkage with native tools:

```sh
shasum -a 256 -c SHA256SUMS
./sandbar_v0.1.0-beta.3-candidate_darwin_arm64 --version
go version -m ./sandbar_v0.1.0-beta.3-candidate_darwin_arm64
otool -L ./sandbar_v0.1.0-beta.3-candidate_darwin_arm64
```

macOS build metadata must show `CGO_ENABLED=1`. Dynamic libraries must come from `/usr/lib` or `/System/Library`.
The archive retains one Sandbar executable and needs no compiler, Go runtime, Python, or extra helper at runtime.

On Linux amd64, use `sha256sum -c SHA256SUMS` and the `_linux_amd64` executable.
Run native packaging on the corresponding platform. Do not build or test Linux on the development Mac.
`scripts/release --version <candidate-version> [output-directory]` prepares these assets without publishing:

- `sandbar_<version>_<os>_<arch>`, the native executable.
- The matching `.tar.gz`, containing `sandbar`, `LICENSE`, `install.sh`, and `RELEASE_NOTES.md`.
- `install.sh`, pinned to the selected version.
- `RELEASE_NOTES.md`, containing authored notes or identifying the local candidate.
- `SHA256SUMS`, covering the executable, archive, installer, and release notes.

Default output is `.sandbox/release/<version>/`. An explicit directory overrides it.
Without options, `scripts/release` prepares beta.3 on either native platform.
When `docs/releases/<version>.md` exists, packaging uses those authored notes.
Other versions retain notes that identify an unpublished local candidate.
Run `scripts/test-install` to test checkout builds and controlled release downloads into temporary destinations.
These checks select platform defaults without writing to `/usr/local/bin`.
A local candidate is unsigned development output, not a published or notarized macOS release.
Keep existing beta.1 and beta.2 tags and assets unchanged. Publish new versions separately under their own tags.
Verify public downloads and installation only after publication.

For public beta.3 preparation, build the same committed revision on each native platform.
Compare the installer, notes, and license bytes from both archives.
Assemble both executables and archives with one shared installer and notes, then generate one combined SHA-256 manifest.
That manifest covers six files. Upload those six files and the manifest as one GitHub prerelease.
Use temporary `--bin-dir` destinations to verify both public downloads without setup, trust changes, or installed executable replacement.

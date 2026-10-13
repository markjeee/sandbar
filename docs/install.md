# Install Sandbar

The checkout supports Linux amd64 and macOS arm64. Published beta.2 supports Linux amd64 only.
Linux uses apt-packaged Caddy with systemd, Polkit, and sudo. Ubuntu 24.04 is its acceptance target.
macOS uses native Homebrew Caddy and the current user's launchd service.
Install prerequisites separately. Sandbar packages need no Go runtime.
Other Caddy packages, Intel Macs, and Windows are outside these integrations.
Automated native checks establish development readiness. Real macOS installation checks remain separate.

## Release installation

Install `v0.1.0-beta.2` on Linux amd64:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.2/install.sh | sh
```

The versioned installer downloads the matching archive and checks its SHA-256 checksum before replacing `sandbar`.
The checksum comes from the same HTTPS release. It checks transfer integrity, not an independent signature.

The published beta.2 destination defaults to `~/.local/bin` on Linux. Select another directory with `--bin-dir`:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.2/install.sh | sh -s -- --bin-dir "$HOME/bin"
```

Make sure the selected directory is in `PATH`, or use the full executable path.
The installer does not edit shell profiles, install Caddy, start services, or change certificate trust.

Beta.2 has no macOS release asset. Its installer cannot install Sandbar on macOS.
Use checkout installation until a native release is published. Local candidates do not establish public download availability.

## Checkout installation

Use the Go version declared in `go.mod`. Run the installer from a checkout:

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

Use a native arm64 Homebrew installation with Caddy v2.11.7 or a later v2 release.
Sandbar checks formula paths, the service command, storage environment, and existing launchd job before changing configuration.
A root-managed service or incompatible job must be resolved separately. Sandbar does not replace it or start a fallback router.
A standard user service need not be registered before setup.

Run as the current user, without sudo:

```sh
sandbar setup --check
sandbar setup
```

Do not pass `--home` or set `SANDBAR_HOME` during setup.
Preview changes no files, services, or trust stores.
It reports application paths, planned Caddyfile changes, backups, service actions, login startup, and conflicts.
Review conflicts before applying. Setup does not accept Linux `--user`, `--migrate-config`, or `--migrate-state` options.

Setup creates a missing `<Homebrew prefix>/etc/Caddyfile` or preserves supported unrelated content in an existing file.
`--replace-default-site` authorizes only a recognized stock welcome block. It never authorizes replacement of custom sites.
Setup validates the complete candidate before activation and backs up changed files.
Repeated matching setup preserves routes, CA identity, and single owned imports.
Ordinary errors restore prior files, running state, and service registration where safe.
Conflicting external edits remain intact. Failures report backup paths and unresolved restoration steps.

Setup and installed `start` use `brew services start caddy`, registering startup for this user's login.
Installed `stop` uses `brew services stop caddy`, stopping all Caddy routes and removing login registration.
A later `sandbar start` registers it again. This user service does not provide boot-before-login operation.
Registration alone does not prove that a later login starts Caddy.
No Sandbar daemon, system LaunchDaemon, group access grant, or Linux policy is installed.

The installed layout is:

```text
/usr/local/bin/sandbar                         # Regular standalone executable
~/Library/Application Support/sandbar/
├── config.json                               # App list
└── state/                                    # Private runtime files and setup backups
```

Owned directories use `0700`, and private files and the control socket permit only this user.
The Homebrew Caddyfile remains at `<prefix>/etc/Caddyfile`.
Caddy storage remains at `<prefix>/var/lib/caddy`, including its `sandbar` authority and unrelated CAs.
Sandbar copies only the public selected root to `~/Library/Application Support/sandbar/state/root.crt`.
Service logs use `<prefix>/var/log/caddy.log`. Sandbar reports the verified path.

Open `https://sandbar.localhost` after setup. HTTP port 80 redirects to HTTPS port 443.
The static welcome page has no backend and remains after removing the final app.
Request trust separately with `sandbar trust`, then follow the [macOS browser steps](browser-trust.md#macos-manual-trust-and-removal).
To remove trust later, keep the selected public root and request `sandbar untrust` explicitly.
Stopping or removing the executable does not remove certificates, routes, or trust.
There is no automatic macOS uninstaller. Review setup backups before restoring owned Caddy changes and preserve unrelated content.

Real service, browser trust, exact-root removal, and new-login checks remain pending until each installation acceptance check runs.
See the [installation checklist](development.md#macos-installation-acceptance).

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
HTTP port 80 redirects to HTTPS port 443. Installed ports are fixed. Only private development homes support other ports.

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

The following commands and backup paths apply to Linux setup and migration. macOS setup reports its Application Support backup path.

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

Published beta.2 assets and their historical release notes remain Linux-only.
Prepare a distinct unreleased native candidate from the checkout:

```sh
scripts/release --version v0.1.0-beta.3-candidate
cd .sandbox/release/v0.1.0-beta.3-candidate
```

On macOS arm64, verify the package with native tools:

```sh
shasum -a 256 -c SHA256SUMS
./sandbar_v0.1.0-beta.3-candidate_darwin_arm64 --version
```

On Linux amd64, use `sha256sum -c SHA256SUMS` and the `_linux_amd64` executable.
Run native packaging on the corresponding platform. Do not build or test Linux on the development Mac.
`scripts/release --version <candidate-version> [output-directory]` prepares these assets without publishing:

- `sandbar_<version>_<os>_<arch>`, the native executable.
- The matching `.tar.gz`, containing `sandbar`, `LICENSE`, `install.sh`, and `RELEASE_NOTES.md`.
- `install.sh`, pinned to the candidate version.
- `RELEASE_NOTES.md`, identifying the local candidate.
- `SHA256SUMS`, covering the executable, archive, installer, and release notes.

Default output is `.sandbox/release/<version>/`. An explicit directory overrides it.
The legacy no-option beta.2 packaging path remains Linux-only.
Run `scripts/test-install` to test checkout builds and controlled release downloads into temporary destinations.
These checks select platform defaults without writing to `/usr/local/bin`.
A local candidate is unsigned development output, not a published or notarized macOS release.
Keep existing beta.1 and beta.2 tags and assets unchanged. Publish new versions separately under their own tags.
Verify public downloads and installation only after publication.

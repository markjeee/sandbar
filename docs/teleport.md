# Teleport

Teleport exposes a prepared Sandbar machine through local Caddy and a background SSH connection.
Both machines must run Teleport-capable Sandbar. Configure remote Caddy and apps before registration.
Registration reads public metadata. It does not configure the remote service or apps.

## Machine URLs

Setup and development initialization save a stable machine name.
Use `--machine <name>` to select its initial value. Otherwise Sandbar uses the lowercase first label of the OS hostname.
The name must be one ASCII DNS label of at most 55 characters. Later hostname changes do not change saved identity.

For machine `mark-work-rise`, canonical `website.sandbar.localhost` gains `website.sandbar-mark-work-rise.localhost`.
Nested `api.website.sandbar.localhost` gains `api.website.sandbar-mark-work-rise.localhost`.
On mark-work-rise, these aliases route directly to their apps without SSH or a redirect to the canonical name.
On a connecting machine, registering mark-work-rise routes its whole namespace through that destination.
Adding remote apps later needs no new registration.

Installed welcome names are `sandbar.localhost` and `sandbar-<machine>.localhost`.
A version 3 private development home serves only the machine-qualified welcome name.
Identical full URLs require matching browser-facing HTTPS ports on both machines.
Installed 443 omits the port. Private HTTPS 18443 uses `https://website.sandbar-mark-work-rise.localhost:18443`.
Teleport preserves the browser hostname, port, path, query, and HTTPS scheme information.

Configure allowed hosts, CSRF origins, login URLs, redirects, and cookies in each app for the machine-qualified URL.
Sandbar does not rewrite application response bodies, redirects, or cookies.

## Register and connect

Use your existing SSH agent with its keys already loaded. Sandbar reads `SSH_AUTH_SOCK`.
It does not start an agent, read or manage private key files, or forward your agent.

```sh
sandbar teleport register mark-work-rise
sandbar teleport ls
sandbar teleport disconnect mark-work-rise
sandbar teleport connect mark-work-rise
sandbar teleport rm mark-work-rise
```

Register resolves a direct SSH alias once with `ssh -G`, then saves its hostname, user, and port.
`--host`, `--user`, and `--port` override those values. Put options before the SSH host.
Jump hosts and proxy commands are unsupported. Other personal SSH settings are not copied.
Later personal SSH configuration changes do not change a registered destination.
Sandbar never edits personal SSH configuration or personal known-host files.

The default remote command is `sandbar teleport info --json` through the remote command environment.
Use `--remote-bin <absolute-path>` when Sandbar is absent from that environment's PATH.
Use `--remote-home <absolute-path>` to select a private development peer.

```sh
sandbar --home .sandbox teleport register --remote-bin /srv/sandbar/sandbar --remote-home /srv/sandbar/.sandbox mark-work-rise
sandbar --home .sandbox teleport connect mark-work-rise
```

Remote paths are arguments, not shell commands. Spaces and shell quotes are passed as data.
Registration commits local routes and public destination trust, then calls the same connect command exposed by the CLI.
If connect fails, the destination remains registered. Correct the connection and retry explicitly.
An identical registration can connect again. Changed settings require removal and registration.
Connect rejects changed remote machine identity, HTTPS port, or CA without replacing saved trust.

## Connection ownership and files

The invoking user owns the OpenSSH background connection.
Caddy routes remain usable by local users who can reach Caddy. Sandbar targets dedicated developer environments.
Connect opens one loopback TCP forward to the remote Caddy HTTPS listener.
It verifies the machine welcome through that forward before reporting success.
A failed readiness check closes a newly opened connection and keeps registration.
Repeated connect reuses an existing destination connection.

SSH files live beneath the selected Sandbar configuration directory:

```text
ssh/
  config
  known_hosts
state/teleport/<destination-id>/
  control.sock
  ssh.log
```

On macOS the installed configuration directory is `~/Library/Application Support/sandbar`.
An explicit development home uses the same relative layout.
Installed Linux keeps SSH configuration under `/etc/sandbar/ssh`.
Its runtime files use `/var/lib/sandbar/work/teleport`, the existing writable command-state directory.
SSH directories use mode 0700. Files use mode 0600 and belong to the invoking user.
Long paths use a short, user-owned runtime directory below `/tmp` for control sockets.
OpenSSH performs normal host-key verification with Sandbar's dedicated known-host file.
Its first connection can ask for host-key confirmation. A changed key is rejected by OpenSSH.

Disconnect uses this destination's control socket and retains registration.
Removal disconnects first, publishes removal through the normal route transaction, then removes owned runtime files.
If publication fails, the destination stays registered for explicit reconnect.
Other SSH sessions and destination connections remain unchanged.
`ls` reports registered names, browser URLs, and observed SSH state. Connected does not mean the app is healthy.

Connections never start automatically at boot, login, or Caddy startup.
Stopping Caddy does not disconnect SSH. Use disconnect explicitly.
OpenSSH keepalives end a broken connection. Sandbar adds no reconnect daemon.

## Trust and errors

The browser trusts the connecting machine's local Sandbar CA.
Registration obtains the destination public CA through verified SSH and stores it only in that destination's proxy transport.
It does not import the remote CA into browser or system trust stores or request another CA approval.
Both certificate-chain and hostname verification remain enabled.
Only explicit `trust` and `untrust` commands change local trust stores.

Caddy issues local internal certificates for registered destination names, including nested app labels.
It does not issue them for unrelated names.
A registered destination with an unavailable connection returns Caddy's ordinary 502.
An unknown destination follows normal unmatched-host behavior and can fail TLS before an HTTP response.
There is no browser diagnostic page. Use `sandbar status` for a combined local and current-user Teleport summary.
Use `sandbar doctor` to check SSH state and forwarded machine-welcome HTTPS separately.
A connected SSH control session does not prove forwarded HTTPS or remote app health.
Disconnected destinations show an explicit connect command and do not cause either command to fail for that condition alone.
Unknown connection state includes its reason and alone does not fail either command.
Both commands leave connections unchanged. Observations can become stale.
Use `sandbar teleport connect <machine>` to connect explicitly, retaining any selected `--home`.
Remote app failures still need remote service and app checks. See [diagnostic result meanings](reference.md#read-doctor-results).

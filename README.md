<!-- Editors: Use plain English. Keep this file within 100 lines. Put users first. Keep progress reports and detailed procedures out. -->
# Sandbar

Sandbar gives local apps HTTPS names such as `https://app.sandbar.localhost`. Teleport reaches another Sandbar machine's apps through your local Caddy and SSH.
Add, change, and remove app names while Caddy runs. Sandbar exits after each command. Caddy keeps running.

## Install

Use Linux amd64 with apt Caddy and systemd, or macOS arm64 with Homebrew Caddy and Sandbar's user LaunchAgent. Install [Caddy](https://caddyserver.com/docs/install) v2.11.7 or a later v2 release separately.
Linux also needs Polkit and sudo. Ubuntu 24.04 is its acceptance target.

Install beta.3 on either platform with the versioned installer. macOS packages are unsigned and unnotarized:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.3/install.sh | sh
```

macOS installs a regular executable at `/usr/local/bin/sandbar`. Linux defaults to `~/.local/bin/sandbar`. Add that directory to `PATH`.

Use `--bin-dir <directory>` for another destination. The installer requests macOS administrator access only for executable publication. It does not install Caddy, start services, change trust, or edit shell profiles.
See [installation and upgrades](docs/install.md) for prerequisites, explicit setup, version 3 backups and rollback, and beta.1 migration.

## Set up Caddy

On macOS, preview and apply as your normal user:

```sh
sandbar setup --check --http-port 80 --https-port 443
sandbar setup --http-port 80 --https-port 443
```

Setup transfers a verified Homebrew user job to Sandbar. Homebrew supplies Caddy, which runs as your user. Launchd opens loopback TCP/UDP sockets. HTTP/1.1, HTTP/2, and HTTP/3 use the selected HTTPS port. Omitted port options retain saved ports.
On Linux, use an administrator once:

```sh
sudo "$HOME/.local/bin/sandbar" setup --check --user "$USER"
sudo "$HOME/.local/bin/sandbar" setup --user "$USER" --replace-default-site
```

`--replace-default-site` backs up and replaces only Caddy's recognized stock welcome site. Custom sites remain protected. Linux grants access to **all Caddy routes and files Caddy can read**. Review [access and removal](docs/install.md#access-and-removal).
**After Linux setup, log out and back in. A new terminal pane does not refresh group membership.**

macOS starts the user service and registers login startup. It does not provide service before login. Setup saves a stable name from the lowercase first OS hostname label. `--machine <name>` overrides the initial name.
Saved identity survives OS renames. For a new CA, request trust as your normal user:

```sh
sandbar trust
```

Migration keeps existing trust. Open `https://sandbar.localhost`. Command success does not prove browser trust. See the [browser guide](docs/browser-trust.md).

## Add an app

Run your app on `127.0.0.1:8000`, then use `sandbar add app.sandbar.localhost 8000` and `sandbar status`.
Open `https://app.sandbar.localhost`. HTTP redirects to HTTPS. Backends must use other ports. Custom macOS ports remain supported.

Machine `work` also serves `https://app.sandbar-work.localhost` directly, without SSH or a redirect to the canonical name. Nested names work too. Aliases change with canonical routes. Changes apply without restarting Caddy.
When Caddy is stopped, route changes are saved for its next start.

Apps must accept their machine URLs. Review allowed hosts, CSRF, redirects, cookies, and login settings. Sandbar does not rewrite app URLs.

| Command | Result |
| --- | --- |
| `sandbar add --replace app.sandbar.localhost 8001` | Change an app's address. |
| `sandbar ls` / `sandbar rm app.sandbar.localhost` | List apps / remove a name. |
| `sandbar reload` | Check and apply manual app-list edits. |
| `sandbar start` / `sandbar stop` | Start Caddy / stop every Caddy route. |
| `sandbar untrust` | Request certificate trust removal. |
| `sandbar <command> --help` | Show options and examples. |

Linux stop keeps boot startup enabled. macOS stop unregisters login startup. Start registers it again. See the [user reference](docs/reference.md) for paths, logs, status, and recovery.

## Teleport to another machine

Prepare remote Caddy and `app.sandbar.localhost` first. Both peers need beta.3 or another Teleport-capable build and completed setup.
This example assumes direct SSH alias `work`, remote machine name `work`, and HTTPS 443 on both machines. Use your existing SSH agent with keys loaded. Sandbar keeps dedicated SSH files under its configuration directory and does not manage keys or forward the agent.
On the connecting machine, run `sandbar teleport register work`.

Registration saves the destination, then calls connect. Open `https://app.sandbar-work.localhost` in the connecting machine's browser.
If SSH cannot find Sandbar, add `--remote-bin <absolute-path>` before `work`. See [Teleport](docs/teleport.md) for options and app settings.

| Command | Result |
| --- | --- |
| `sandbar teleport register work` | Save the destination, then connect. |
| `sandbar teleport connect work` | Connect or reuse its connection. |
| `sandbar teleport disconnect work` | Close the connection and keep registration. |
| `sandbar teleport ls` | List registered destinations and observed SSH state. |
| `sandbar teleport rm work` | Disconnect and remove the destination and its proxy trust. |
| `sandbar teleport info --json` | Show this machine's public peer metadata. |

A failed connect retains registration. Reconnect explicitly. Boot, login, and Caddy startup never connect automatically.

Browsers use the local Sandbar CA. The remote CA verifies only that destination's proxy transport. Registration does not import browser trust. An unavailable registered connection returns ordinary HTTP 502. Unknown destinations follow normal Caddy TLS and unmatched-host behavior.

## Build and contribute

See the [development guide](docs/development.md) for native builds, the isolated `.sandbox` router, and checks.
Automated checks use temporary state. Installed service, Chrome trust, trust removal, and new-login checks need separate acceptance.
Submit a [pull request](https://github.com/markjeee/sandbar/pulls) with relevant tests and development check results.
Sandbar uses the [MIT license](LICENSE).

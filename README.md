<!-- Editors: Use plain English. Keep this file within 100 lines. Put users first. Keep progress reports and detailed procedures out. -->
# Sandbar

Sandbar gives apps on this computer HTTPS names such as `https://app.sandbar.localhost`.
Add, change, and remove app names while Caddy runs.
Sandbar exits after each command. The selected Caddy service keeps running.

## Install

Use Linux amd64 with apt Caddy and systemd, or macOS arm64 with the current user's Homebrew Caddy service.
Install [Caddy](https://caddyserver.com/docs/install) v2.11.7 or a later v2 release separately.
Linux setup also needs Polkit and sudo. Ubuntu 24.04 is the Linux acceptance target.

Published `v0.1.0-beta.2` supports Linux amd64 only:

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.2/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
```

For macOS, build the unreleased checkout with Go 1.27.2 or later:

```sh
sh ./install.sh
```

macOS installs a regular executable at `/usr/local/bin/sandbar`. Linux defaults to `~/.local/bin/sandbar`.
Use `--bin-dir <directory>` to select another destination.
The installer limits any macOS administrator request to executable publication.
It does not install Caddy, start services, change trust, or edit shell profiles.
See [installation and upgrades](docs/install.md) for prerequisites, permissions, and beta.1 migration.

## Set up Caddy

On macOS, preview and apply setup as your normal user:

```sh
sandbar setup --check
sandbar setup
```

On Linux, use an administrator once:

```sh
sudo "$HOME/.local/bin/sandbar" setup --check --user "$USER"
sudo "$HOME/.local/bin/sandbar" setup --user "$USER" --replace-default-site
```

`--replace-default-site` backs up and replaces only Caddy's recognized stock welcome site. Custom sites remain protected.
Linux setup grants access to **all Caddy routes and files Caddy can read**. Review [access and removal](docs/install.md#access-and-removal).
**After Linux setup, log out and back in. A new terminal pane does not refresh group membership.**
macOS setup starts the user service and registers login startup. It does not provide service before login.

Request certificate trust explicitly as your normal user, then check `https://sandbar.localhost` in Chrome:

```sh
sandbar trust
```

Command success does not prove browser trust. See the [browser guide](docs/browser-trust.md).

## Add an app

Run your app on `127.0.0.1:8000`, then give it a name:

```sh
sandbar add app.sandbar.localhost 8000
sandbar status
```

Open `https://app.sandbar.localhost` on this computer.
Caddy uses ports 80 and 443. App backends must use other ports. HTTP redirects to HTTPS.
Changes apply without restarting Caddy. When stopped, they are saved for its next start.

| Command | Result |
| --- | --- |
| `sandbar add --replace app.sandbar.localhost 8001` | Change an app's address. |
| `sandbar ls` | List app names and addresses. |
| `sandbar rm app.sandbar.localhost` | Remove an app name. |
| `sandbar reload` | Check and apply manual app-list edits. |
| `sandbar start` | Start Caddy. On macOS, register login startup. |
| `sandbar stop` | Stop every Caddy route. On macOS, unregister login startup. |
| `sandbar untrust` | Request removal of Sandbar's certificate trust. |
| `sandbar <command> --help` | Show options and examples. |

Linux stop keeps boot startup enabled. macOS start registers login startup again after stop.
See the [user reference](docs/reference.md) for paths, logs, status, and recovery.

## Build and contribute

See the [development guide](docs/development.md) for native builds, the isolated `.sandbox` router, and checks.
Automated macOS checks use temporary state. Real service, Chrome trust, trust removal, and new-login checks need separate installation acceptance.
Choose your tools and submit changes through a [pull request](https://github.com/markjeee/sandbar/pulls).
Include relevant tests and run the checks in the development guide.
Sandbar uses the [MIT license](LICENSE).

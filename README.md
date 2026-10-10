<!-- Editors: Use plain English. Keep this file within 100 lines. Put users first. Keep progress reports and detailed procedures out. -->
# Sandbar

Sandbar gives apps on this computer HTTPS names such as `https://app.sandbar.localhost`.
Add, change, and remove app names while Caddy runs.
Sandbar exits after each command. The standard Caddy service keeps running and starts at boot.

## Install

Use Linux amd64 with apt-packaged Caddy, systemd, Polkit, and sudo. Ubuntu 24.04 is the tested platform.
Install [Caddy](https://caddyserver.com/docs/install) v2.11.7 or later separately.

**The setup below requires current source. The published `v0.1.0-beta.1` uses a private router and has no `setup` command.**
With Go 1.27.2 or later, install from a checkout:

```sh
git clone https://github.com/markjeee/sandbar.git
cd sandbar
sh ./install.sh
export PATH="$HOME/.local/bin:$PATH"
```

The installer does not install Caddy, start services, change trust, or edit shell profiles.
See [installation and upgrades](docs/install.md) for the beta download, another destination, or migration from an existing router.

## Set up Caddy

Preview the changes, then connect Sandbar to Caddy:

```sh
sudo "$HOME/.local/bin/sandbar" setup --check --user "$USER"
sudo "$HOME/.local/bin/sandbar" setup --user "$USER" --replace-default-site
```

`--replace-default-site` backs up and replaces Caddy's stock welcome site. Custom sites remain protected.
Setup grants the named user access to **all Caddy routes and files Caddy can read**.
Review [access and removal](docs/install.md#access-and-removal) before granting it.
**Log out and log back in after setup. A new terminal tab or pane does not refresh group membership.**

Request certificate trust as your normal user, then check `https://sandbar.localhost` in your browser:

```sh
sandbar trust
```

Trust changes are explicit. Command success does not prove browser trust. See the [browser guide](docs/browser-trust.md).

## Add an app

Run your app on `127.0.0.1:8000`, then give it a name:

```sh
sandbar add app.sandbar.localhost 8000
sandbar status
```

Open `https://app.sandbar.localhost` on this computer.
Caddy uses fixed ports 80 and 443. App backends must use other ports. HTTP redirects to HTTPS.
Changes apply without restarting Caddy. When stopped, they are saved for its next start.

| Command | Result |
| --- | --- |
| `sandbar add --replace app.sandbar.localhost 8001` | Change an app's address. |
| `sandbar ls` | List app names and addresses. |
| `sandbar rm app.sandbar.localhost` | Remove an app name. |
| `sandbar reload` | Check and apply manual app-list edits. |
| `sandbar start` | Start Caddy. |
| `sandbar stop` | Stop Caddy and every route it serves. |
| `sandbar untrust` | Request removal of Sandbar's certificate trust. |
| `sandbar <command> --help` | Show options and examples. |

`stop` does not disable boot startup. Read service logs with `journalctl -u caddy.service`.
See the [user reference](docs/reference.md) for app addresses, configuration, status, and recovery.

## Build and contribute

Build with `CGO_ENABLED=0 go build -o sandbar .`. See the [development guide](docs/development.md) for private routers and checks.
Choose your tools and submit changes through a [pull request](https://github.com/markjeee/sandbar/pulls).
Include relevant tests and run the checks in the development guide.
Sandbar uses the [MIT license](LICENSE).

package main

import "runtime"

// Agents: Keep CLI help brief, concise, user friendly, and in simple plain English.
// Put technical details in command help or the user guides.
const mainHelp = `Sandbar gives apps on this computer local HTTPS names.

Usage: sandbar [--home <directory>] <command> [options]

Commands:
  setup     Connect Sandbar to the installed Caddy service
  init      Create an empty app list
  add       Give an app an HTTPS name
  rm        Remove an app name
  ls        List apps and their addresses
  reload    Apply changes made to the app list
  status    Check Caddy and app connections
  start     Start Caddy
  stop      Stop Caddy and all its routes
  trust     Trust Sandbar's HTTPS certificates
  untrust   Remove trust for Sandbar's certificate

Example: sandbar add app.sandbar.localhost 8000

Use sandbar <command> --help for options and examples.
Use sandbar --version to show the version.
Use --home for a separate development router.
See the README and docs for setup, development ports, recovery, and browser trust.
`

func topLevelHelp() string { return mainHelp }

func platformHelp(linux, darwin string) string {
	if runtime.GOOS == "darwin" {
		return darwin
	}
	return linux
}

func commandHelpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func helpText(command string) (string, bool) {
	text, ok := commandHelp[command]
	return text, ok
}

var commandHelp = map[string]string{
	"setup": platformHelp(`Connect Sandbar to apt-packaged Caddy and systemd on Linux amd64.

Usage: sandbar setup --user <name> [options]

Options:
  --check                  Preview changes without applying them
  --replace-default-site   Back up and replace Caddy's stock welcome site
  --migrate-config <file>   Use the old router's app list
  --migrate-state <dir>     Use the old router's certificate files

Example:
  sudo /absolute/path/to/sandbar setup --check --user alice
  sudo /absolute/path/to/sandbar setup --user alice --replace-default-site

Setup needs an administrator once. Start a new login session afterward.
The named user gains lasting access to all Caddy routes and files Caddy can read.
Setup enables Caddy at boot. It does not install Caddy or certificate trust.
Migration needs both paths and keeps the existing root certificate.
Installed use requires ports 80 and 443. Legacy routers with other ports cannot migrate.
Custom sites remain protected. Review conflicts before changing them.
Do not use --home or SANDBAR_HOME with setup. See docs/install.md for details.
`, `Connect Sandbar to the current user's Homebrew Caddy service on macOS arm64.

Usage: sandbar setup [options]

Options:
  --check                  Preview changes without applying them
  --http-port <port>       Installed HTTP redirect port
  --https-port <port>      Installed HTTPS port
  --replace-default-site   Back up and replace Caddy's recognized stock welcome site

Example:
  sandbar setup --check --http-port 8080 --https-port 8443
  sandbar setup --http-port 8080 --https-port 8443

Run as your normal user. Install Homebrew Caddy separately before setup.
Setup preserves supported unrelated sites and creates a missing Homebrew Caddyfile.
Setup starts Caddy and registers login startup. It does not install certificate trust.
Fresh defaults remain HTTP 80 and HTTPS 443. Omitted options retain saved ports.
Use high ports when the user service cannot bind privileged ports.
Setup saves selected ports for later start, reload, and repeated setup.
Port settings affect shared Caddy settings. Conflicting explicit settings are rejected.
Run sandbar trust explicitly afterward.
Custom sites remain protected. Review conflicts before changing them.
Do not use --home or SANDBAR_HOME with setup. See docs/install.md for details.
`),
	"init": `Create an empty app list, or add the first app.

Usage: sandbar init [--http-port <port>] [--https-port <port>] [<hostname> <app-address>]

Options:
  --http-port <port>    Development HTTP redirect port (default 80)
  --https-port <port>   Development HTTPS port (default 443)

Example: sandbar init
First development app: sandbar --home /tmp/sandbar-demo init app.sandbar.localhost 8000
Development: sandbar --home /tmp/sandbar-demo init --http-port 8080 --https-port 8443

Options must come before the hostname. Existing settings are kept.
Run setup first for installed use.
` + platformHelp("Installed Caddy always uses ports 80 and 443.", "Fresh installed defaults are HTTP 80 and HTTPS 443. Select other ports through macOS setup.") + `
Use --home for a separate development router with other ports.
`,
	"add": `Give an app on this computer an HTTPS name.

Usage: sandbar add [--replace] <hostname> <app-address>

Option:
  --replace   Change an existing app's address

Example: sandbar add app.sandbar.localhost 8000
Change it: sandbar add --replace app.sandbar.localhost localhost:8001

Use a name below .sandbar.localhost. The app address can be a port,
localhost:port, [::1]:port, or an HTTP(S) URL on this computer.
Do not include a path, password, query, or fragment in the app address.
App ports must differ from both Caddy ports. Put --replace before the hostname.
Changes apply while Caddy runs. When stopped, they are saved for its next start.
`,
	"rm": `Remove an app's HTTPS name. An unknown name is an error.

Usage: sandbar rm <hostname>
Example: sandbar rm app.sandbar.localhost

Changes apply while Caddy runs. When stopped, they are saved for its next start.
Removing the last app keeps the installed welcome page and certificates.
This command does not remove certificate trust.
`,
	"ls": `List app names, HTTPS URLs, and app addresses in name order.

Usage: sandbar ls
Example: sandbar ls

The built-in installed welcome page is separate from this app list.
`,
	"reload": `Check and apply manual changes to the app list while Caddy runs.

Usage: sandbar reload
Example: sandbar reload

` + platformHelp("Installed app list: /etc/sandbar/config.json\n", "Installed app list: ~/Library/Application Support/sandbar/config.json\n") + `A rejected change keeps your edits for correction and leaves active routes working.
Do not edit generated files. See the README for recovery and custom Caddy changes.
`,
	"status": `Check Caddy and each configured HTTPS app address.

Usage: sandbar status
Example: sandbar status

` + platformHelp("Reports service state, boot startup, access, pending changes, and saved recovery state.", "Reports service state, login startup, access, pending changes, and saved recovery state.") + `
App checks verify certificates and show HTTP codes or connection errors.
HTTP 5xx is a failure. Other HTTP codes show reachability, not app health.
This does not prove browser trust or name resolution. See docs/browser-trust.md.
`,
	"start": `Check configuration and start Caddy.

Usage: sandbar start
Example: sandbar start

` + platformHelp("Installed use starts caddy.service. Setup enables it at boot.", "Installed use starts Homebrew Caddy on saved ports and registers login startup.") + `
Use --home or SANDBAR_HOME to select a separate development router.
This command does not add certificate trust.
` + platformHelp("Installed logs: journalctl -u caddy.service", "Installed logs: <Homebrew prefix>/var/log/caddy.log (the command reports the path)") + `
`,
	"stop": `Stop Caddy. Installed use stops every route Caddy serves.

Usage: sandbar stop
Example: sandbar stop
Development: sandbar --home /tmp/sandbar-demo stop

An explicit development home stops only that development router.
Configuration, certificates, and certificate trust remain in place.
Stop remains available when the app list or recovery state is invalid.
` + platformHelp("This command does not disable Caddy's boot startup.", "Installed stop unregisters login startup. A later start registers it again.") + `
`,
	"trust": `Ask Caddy to add Sandbar's root certificate to trust stores.

Usage: sandbar trust
Example: sandbar trust

Run as your normal user while the selected Caddy router runs.
Caddy may request administrator access. Check the route in your browser afterward.
Command success does not prove browser trust. See docs/browser-trust.md.
` + platformHelp("Installed public root: /var/lib/sandbar/root.crt", "Installed public root: ~/Library/Application Support/sandbar/state/root.crt") + `
--home selects a development certificate. It does not isolate trust stores.
`,
	"untrust": `Ask Caddy to remove trust for the selected Sandbar root certificate.

Usage: sandbar untrust
Example: sandbar untrust

Works after stop and with an invalid app list. Keep the public root until removal ends.
Remove any manual browser imports too. See docs/browser-trust.md.
Configuration and certificate files remain in place.
--home selects a development certificate. It does not isolate trust stores.
`,
}

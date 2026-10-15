package main

import "runtime"

// Agents: Keep CLI help brief, concise, user friendly, and in simple plain English.
// Put technical details in command help or the user guides.
const mainHelp = `Sandbar gives apps on this computer local HTTPS names.

Usage: sandbar [--home <directory>] <command> [options]

Commands:
  setup     Connect Sandbar to the installed Caddy service
  init      Create an empty app list
  teleport  Connect to apps on another Sandbar machine
  add       Give an app an HTTPS name
  rm        Remove an app name
  ls        List apps and their addresses
  reload    Apply changes made to the app list
  config    Show the source path or its exact contents
  status    Check Caddy, apps, and Teleport connections
  doctor    Diagnose configuration, HTTPS, trust, and connections
  start     Start Caddy
  stop      Stop Caddy and all its routes
  trust     Trust Sandbar's HTTPS certificates
  untrust   Remove trust for Sandbar's certificate
  uninstall Remove the installed integration and keep the CLI

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
	"uninstall": `Remove the installed Sandbar integration and keep this executable.

Usage: sandbar uninstall (--check | --yes)

Options:
  --check   Preview removal without changing installed state
  --yes     Confirm removal of routes, identity, Teleport registrations, and CA

Example: sandbar uninstall --check
Remove: sandbar uninstall --yes

Run as your normal user. Do not select --home or SANDBAR_HOME.
Linux requests ordinary administrator authorization for protected inspection and cleanup.
macOS unloads the current user's Sandbar LaunchAgent and releases its sockets.
Unrelated sites in the selected Caddy service must be separated before removal.
Caddy, this CLI, unrelated files, backends, SSH keys, and remote machines remain.
Owned connections close first. Untrust failure preserves CA files, configuration, and backups.
Caddy untrust success does not prove removal of manual browser imports.
Failures report completed actions and retained paths. No automatic recovery runs.
Fresh setup creates new identity and CA material. Trust and peer registrations need updates.
See docs/install.md and docs/browser-trust.md for cleanup and recovery boundaries.
`,
	"teleport": teleportCommandHelp,
	"config": `Show the selected source path or its exact contents without changing state.

Usage: sandbar config (--path | --print)

Options:
  --path    Print the absolute source configuration path
  --print   Print the source file's exact bytes, including readable invalid JSON

Example: sandbar config --path
Development: sandbar --home /tmp/sandbar-demo config --print

Choose exactly one option. Extra arguments and unsupported options are errors.
--home takes priority over SANDBAR_HOME. Without either, use the installed source.
Path inspection works before setup. Printing missing or unreadable source fails.
Neither option needs Caddy or creates files, changes permissions, or repairs state.
This prints source, not generated or active Caddy configuration.
`,
	"doctor": `Diagnose the selected router without repairing state.

Usage: sandbar doctor
Example: sandbar doctor
Development: sandbar --home /tmp/sandbar-demo doctor

Accepts no arguments or options except help.
--home takes priority over SANDBAR_HOME. Without either, inspect installed use.
Checks source, Caddy, service, listeners, resolution, direct HTTPS, and trust.
Connected Teleport destinations also receive a forwarded welcome HTTPS check.
Each check is bounded. Results are a snapshot and can become stale.
Failures return nonzero. Disconnected or unknown destinations alone do not fail.
Disconnected destinations show an explicit connect command with the selected home.
Corrective commands require a separate user action. Doctor never connects or repairs.
Direct HTTPS bypasses proxies. System trust and resolution do not prove browser behavior.
Optional listener inspection can remain unknown. Doctor does not audit every network policy.
See docs/reference.md and docs/browser-trust.md for result meanings and manual checks.
`,
	"setup": platformHelp(`Connect Sandbar to apt-packaged Caddy and systemd on Linux amd64.

Usage: sandbar setup --user <name> [options]

Options:
  --machine <name>         Save the initial stable machine name
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
Machine names use the lowercase OS hostname first label by default.
Saved names survive OS renames. An established name cannot change.
Setup upgrades older source with its existing backup and validation path.
Do not use --home or SANDBAR_HOME with setup. See docs/install.md for details.
`, `Connect Homebrew Caddy to Sandbar's user LaunchAgent on macOS arm64.

Usage: sandbar setup [options]

Options:
  --machine <name>         Save the initial stable machine name
  --check                  Preview changes without applying them
  --http-port <port>       Installed HTTP redirect port
  --https-port <port>      Installed HTTPS port
  --replace-default-site   Back up and replace Caddy's recognized stock welcome site

Example:
  sandbar setup --check --http-port 80 --https-port 443
  sandbar setup --http-port 80 --https-port 443

Run as your normal user. Install Homebrew Caddy separately before setup.
Setup preserves supported unrelated sites and creates a missing Homebrew Caddyfile.
Setup starts Caddy and registers login startup. It does not install certificate trust.
Fresh defaults remain HTTP 80 and HTTPS 443. Omitted options retain saved ports.
Launchd opens loopback TCP/UDP sockets. Caddy runs as your user.
Setup transfers a verified Homebrew user job. Homebrew still supplies Caddy.
Use Sandbar for service commands after setup. Existing trust stays unchanged.
Setup saves selected ports for later start, reload, and repeated setup.
Port settings affect shared Caddy settings. Conflicting explicit settings are rejected.
For a new CA, request sandbar trust separately. Migration keeps existing trust.
Custom sites remain protected. Review conflicts before changing them.
Machine names use the lowercase OS hostname first label by default.
Saved names survive OS renames. An established name cannot change.
Setup upgrades older source with its existing backup and validation path.
Do not use --home or SANDBAR_HOME with setup. See docs/install.md for details.
`),
	"init": `Create an empty app list, or add the first app.

Usage: sandbar init [options] [<hostname> <app-address>]

Options:
  --machine <name>      Initial stable machine name
  --http-port <port>    Development HTTP redirect port (default 80)
  --https-port <port>   Development HTTPS port (default 443)

Example: sandbar init
First development app: sandbar --home /tmp/sandbar-demo init app.sandbar.localhost 8000
Development: sandbar --home /tmp/sandbar-demo init --http-port 8080 --https-port 8443

Options must come before the hostname. Existing settings are kept.
The initial machine name defaults to the lowercase OS hostname first label.
Use one ASCII DNS label of at most 55 characters. Saved identity cannot change.
Development init upgrades older source with validated routes and a private backup.
Machine aliases route apps locally. See docs/reference.md for upgrade recovery.
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
	"status": `Check Caddy, each configured HTTPS app address, and Teleport connections.

Usage: sandbar status
Example: sandbar status

` + platformHelp("Reports service state, boot startup, access, pending changes, and saved recovery state.", "Reports Caddy process state, login registration, socket ownership, access, and pending changes or recovery.") + `
App checks verify certificates and show HTTP codes or connection errors.
HTTP 5xx is a failure. Other HTTP codes show reachability, not app health.
Teleport reports sorted registered machines and current-user SSH connection state.
Connected does not prove remote app health. Disconnected shows a connect command.
Disconnected or unknown destinations alone do not fail status. Local failures still fail.
Status reads without creating files, changing permissions, or repairing state.
--home takes priority over SANDBAR_HOME. Without either, inspect installed use.
Observations can become stale. Use doctor for deeper checks.
This does not prove browser trust or name resolution. See docs/browser-trust.md.
`,
	"start": `Check configuration and start Caddy.

Usage: sandbar start
Example: sandbar start

` + platformHelp("Installed use starts caddy.service. Setup enables it at boot.", "Installed use starts Sandbar's Caddy LaunchAgent on saved ports and registers login startup.") + `
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
` + platformHelp("This command does not disable Caddy's boot startup.", "Installed stop unloads the job, releases TCP/UDP sockets, and unregisters login startup.\nA later start registers it again. Routes and the private restart template remain.") + `
`,
	"trust": `Ask Caddy to add Sandbar's root certificate to trust stores.

Usage: sandbar trust
Example: sandbar trust

Run as your normal user while the selected Caddy router runs.
Caddy may request administrator access. Check the route in your browser afterward.
Command success does not prove browser trust. See docs/browser-trust.md.
` + platformHelp("Installed public root: /var/lib/sandbar/root.crt", "Installed public root: <verified Caddy storage>/pki/authorities/sandbar/root.crt") + `
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

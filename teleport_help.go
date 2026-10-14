package main

func teleportHelp(args []string) string {
	if len(args) > 0 && args[0] == "register" {
		return teleportRegisterHelp
	}
	if len(args) > 0 && args[0] == "info" {
		return "Read prepared peer metadata without changing files, services, or trust.\n\nUsage: sandbar teleport info --json\nUse global --home to select an explicit development peer.\n"
	}
	return teleportCommandHelp
}

const teleportCommandHelp = `Reach a prepared Sandbar machine through local HTTPS names.

Usage: sandbar teleport <command> [options]

Commands:
  register [options] <ssh-host>   Save a prepared destination, then connect
  connect <machine>              Connect or check an existing connection
  disconnect <machine>           Close this destination's connection
  ls                             List names, browser URLs, and observed SSH state
  rm <machine>                   Disconnect and remove a destination
  info --json                    Read this machine's public peer metadata

Example: sandbar teleport register mark-work-rise
Later: sandbar teleport connect mark-work-rise

Both machines need Teleport-capable Sandbar and configured Caddy.
Use your existing SSH agent. Sandbar does not manage keys or forward the agent.
SSH files: <Sandbar configuration directory>/ssh/{config,known_hosts}.
The invoking user owns the background SSH connection and its private control socket.
Disconnect retains registration. A failed connect also retains registration.
List reports SSH state, not app health. Connections never start at boot or login.
Caddy start and stop do not manage SSH. Reconnect explicitly with connect.
Browsers use the local Sandbar CA. Destination trust stays in its proxy transport.
See docs/teleport.md for direct SSH scope, app URL settings, and normal 502 errors.
`
const teleportRegisterHelp = `Save a prepared destination and call the reusable connect command.

Usage: sandbar teleport register [options] <ssh-host>

Options:
  --host <hostname>          Override the resolved direct SSH host
  --user <name>              Override the resolved SSH user
  --port <port>              Override the resolved SSH port
  --remote-bin <path>        Absolute remote Sandbar binary path
  --remote-home <directory>  Absolute remote development home

Example: sandbar teleport register mark-work-rise
Development: sandbar --home .sandbox teleport register --remote-bin /srv/sandbar/sandbar --remote-home /srv/sandbar/.sandbox mark-work-rise

Configure remote Caddy and apps first. Both peers need Teleport-capable Sandbar.
SSH alias defaults come from ssh -G. Only direct host, user, and port are saved.
Jump hosts and proxy commands are unsupported. Personal SSH config stays unchanged.
Later SSH calls use <Sandbar configuration directory>/ssh/config and known_hosts.
OpenSSH checks host keys normally and can ask for first-connection confirmation.
Authentication uses the caller's existing SSH agent without private keys or agent forwarding.
Registration obtains the public remote CA through SSH. It does not change browser trust.
Successful registration leaves a connection open. Failed connect retains registration.
Retry with teleport connect <machine>. Different settings require remove and register.
The invoking user owns the connection. No reconnect runs at boot, login, or Caddy start.
`

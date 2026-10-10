# Sandbar

Sandbar gives local development apps HTTPS names such as `https://app.sandbar.localhost`.
Use one Caddy router for multiple local HTTP or HTTPS backends.
Add, replace, and remove routes while the router runs.
Sandbar exits after each command. Only Caddy stays running.

Sandbar targets Linux amd64, with native acceptance on Ubuntu 24.04.
macOS and Windows support remain outside this release.

## Install

Install [Caddy](https://caddyserver.com/docs/install) v2.11.7 or a later stable v2 release separately.
Caddy must be available in `PATH`.
Sandbar packages need no Go runtime.

`markjeee/sandbar` remains private for review of `v0.1.0-beta.1`.
The release installer below requires the repository to become public.
Public download verification remains pending until that visibility change.

```sh
curl -fsSL https://github.com/markjeee/sandbar/releases/download/v0.1.0-beta.1/install.sh | sh
```

From a checkout, install the current source with Go 1.27.2 or later:

```sh
sh ./install.sh
```

Both methods default to `~/.local/bin`. Make sure that directory is in `PATH`.
For the current shell session:

```sh
export PATH="$HOME/.local/bin:$PATH"
sandbar --version
```

Use `--bin-dir` to choose another destination.
The installer preserves an existing executable if downloading, verification, or building fails.
It does not install Caddy, start services, edit shell profiles, or change certificate trust.
See [installation details](docs/install.md) for destination options, checksums, and release packages.

## Quick start

Run your app on `127.0.0.1:8000` first, then create its route:

```sh
sandbar init
sandbar add app.sandbar.localhost 8000
sandbar start
sandbar status
```

The route is `https://app.sandbar.localhost`. HTTP port 80 redirects to HTTPS port 443.
These ports must be free. Stop DDEV or another competing router before using the same addresses and ports.
Caddy needs permission to bind them, which can require `CAP_NET_BIND_SERVICE` on Linux.
See [Caddy's low-port guidance](https://caddyserver.com/docs/quick-starts/reverse-proxy).
Sandbar does not change capabilities, elevate lifecycle commands, or choose alternate ports after a conflict.

For a fresh configuration without low-port permissions, replace `sandbar init` above with:

```sh
sandbar init --http-port 8080 --https-port 8443
```

Then use `https://app.sandbar.localhost:8443`.
`init` preserves existing configuration and rejects different settings. Flags must precede positional arguments.

`status` verifies HTTPS with Sandbar's own root certificate. Browser trust requires a separate, explicit step.
Read the [browser trust guide](docs/browser-trust.md) before running:

```sh
sandbar trust
```

Verify the route in your browser after trust setup.
Command success does not prove browser trust. `.localhost` names need no public domain registration, but client resolution and proxy behavior can differ.
Sandbar does not edit DNS or hosts files.
Your app can also need allowed-host and CSRF-origin settings for its new hostname.

## Everyday commands

| Command | Result |
| --- | --- |
| `sandbar add api.sandbar.localhost localhost:9000` | Add another route. |
| `sandbar add --replace app.sandbar.localhost 8001` | Change an existing route's upstream. |
| `sandbar ls` | List hostnames, HTTPS URLs, and normalized upstreams, sorted by hostname. |
| `sandbar rm api.sandbar.localhost` | Remove a configured route. |
| `sandbar reload` | Validate and apply manual `config.json` edits to a running router. |
| `sandbar status` | Report router state, pending changes, and HTTPS reachability. |
| `sandbar stop` | Stop the selected router and retain configuration, logs, and certificates. |
| `sandbar untrust` | Request removal of the selected home's CA trust. |
| `sandbar --help` | Show commands and options. |

`add` succeeds unchanged for identical normalized version 2 settings. Different upstreams require `--replace`.
`rm` rejects unknown hostnames. Removing the final route preserves the private admin endpoint and shared CA material.
Route removal never runs `untrust`.

`add` and `rm` validate candidates with Caddy before saving them.
They apply changes immediately when Caddy runs, without restarting it.
When stopped, they save validated changes without starting Caddy. Use `sandbar start` when ready.
A rejected `reload` retains edited source for correction and leaves active routes unchanged.

### Upstreams

| Input | Normalized upstream |
| --- | --- |
| `8000` | `http://127.0.0.1:8000` |
| `localhost:8000` | `http://localhost:8000` |
| `[::1]:8000` | `http://[::1]:8000` |
| `https://127.0.0.1:9443` | `https://127.0.0.1:9443` |

Only `localhost` and loopback IP addresses are allowed. IPv6 addresses must use brackets.
HTTP(S) URLs can omit their port when the default differs from both router ports.
Credentials, paths, trailing slashes, queries, and fragments are rejected.
Router ports must differ. Each upstream port must differ from both router ports.
HTTPS upstreams retain Caddy certificate verification. Custom upstream trust settings remain deferred.

### Read status results

`status` distinguishes running, stopped, and inaccessible private admin endpoints.
It reports source changes pending in generated output, differences from active configuration, and pending recovery.
Comparing generated and active configuration requires installed Caddy for `caddy adapt`.

Each route check sends HTTPS `HEAD /` through IPv4 loopback, with a three-second limit per request.
It uses the configured hostname for HTTP and TLS, verifies against this home's root, and bypasses proxy settings.
It does not follow redirects. Stopped routers report routes as unchecked.
HTTP codes appear separately from TLS and connection errors.
HTTP 5xx responses count as failures. Other HTTP responses establish reachability only, not application health.

The exit code is nonzero for stopped or inaccessible routers, pending or unknown configuration, pending recovery, or failed route checks.
Missing or invalid configuration and required root certificates remain errors.
An empty running router can report success without route checks.
Status does not prove browser trust, system DNS resolution, or operating-system listeners.

### Browser trust and removal

`trust` requires the selected Caddy instance to run. `untrust` uses its stored public root and works after stop.
Both commands use the caller's trust stores. **`--home` selects a CA and does not isolate trust stores.**
Caddy can request elevated access and attempt changes to user, system, Firefox, and Java stores.
A failure can leave partial changes. Success does not prove Chrome trust or complete trust removal.

Follow the [browser trust guide](docs/browser-trust.md) to verify setup and remove the exact certificate, including any manual imports.
Keep the public root available until removal is complete.
For disposable development tests, use the [isolated browser proof](docs/browser-proof.md).

## Configuration reference

`init` creates an empty version 2 configuration without requiring Caddy.
The existing `sandbar init <hostname> <upstream>` form still creates an initial route.
Repeating initialization with identical settings succeeds without rewriting the source.

Home selection uses `--home`, then `SANDBAR_HOME`, then Linux defaults:

- Configuration: `$XDG_CONFIG_HOME/sandbar/config.json`, or `~/.config/sandbar/config.json`.
- Runtime state: `$XDG_STATE_HOME/sandbar`, or `~/.local/state/sandbar`.
- With a home override: `<home>/config.json` and `<home>/state`.

Use the same home for every command:

```sh
sandbar --home /tmp/sandbar-demo init --http-port 8080 --https-port 8443
sandbar --home /tmp/sandbar-demo add app.sandbar.localhost 8000
sandbar --home /tmp/sandbar-demo start
```

Relative XDG paths are ignored. Explicit homes can be relative paths.
Keep home paths short enough for a Linux Unix socket.
Paths cannot contain control characters, braces, or vertical bars because Caddy treats these as syntax.
Directories have mode `0700`. Private regular files have mode `0600`.

Edit `config.json` as the source configuration. Use `reload` while running, or `start` while stopped, to apply edits.
Do not edit the generated `Caddyfile`.
Version 2 source separates router ports from routes:

```json
{
  "version": 2,
  "http_port": 80,
  "https_port": 443,
  "routes": [
    {"hostname": "app.sandbar.localhost", "upstream": "http://127.0.0.1:8000"}
  ]
}
```

An empty `routes` array is valid. Hostnames normalize to lowercase and must remain below `.sandbar.localhost`.
Duplicate hostnames after normalization, unknown fields, and invalid ports are rejected.
Version 1 source remains readable. A successful `add` or `rm` converts it to version 2.
Conversion first preserves its exact source in `config.v1.backup.json` beside `config.json`.
An identical version 1 addition also performs this conversion.

### Router state and recovery

Caddy uses internal TLS, a private Unix admin socket, and private certificate storage.
HTTP and HTTPS bind only to IPv4 loopback and available IPv6 loopback.
HTTP/3 is disabled. HTTP serves redirects only for configured hostnames.
Sandbar uses Caddy's [standard commands](https://caddyserver.com/docs/command-line) and installs no system service.
Startup failures include Caddy diagnostics and the log path.
An active or inaccessible admin socket prevents another start. Missing or stale sockets that refuse connections allow startup.
Repeated stop retains Caddy's result. A failed command remains an error.

A per-home lock serializes commands. Route changes flush a private transaction journal before reload or committed file replacement.
Recovery runs before initialization, route mutations, and startup.
After interrupted reloads, recovery inspects active Caddy configuration to complete confirmed candidate state or restore previous state.
Unknown active state and conflicting manual edits block recovery and preserve recovery files.

Recovery files stay under the selected state's `transaction/` directory until recovery succeeds:

- `journal.json` records the transaction phase and exact configuration bytes.
- `previous.config.json` and `candidate.config.json` preserve source copies.
- `previous.Caddyfile` and `candidate.Caddyfile` preserve generated copies when present.
- `previous.active.json` and `candidate.active.json` preserve adapted Caddy configuration when present.

Errors name the conflict and recovery directory. Keep recovery files while comparing manual edits with both recorded states.
Correct the reported conflict without discarding needed edits, then retry the route command or `start`.
`status` reports pending recovery without changing it.
`stop` and `untrust` remain available with invalid source or recovery state.

## Development and contributions

Sandbar uses Go's standard library and keeps implementation in this repository.
Use Go 1.27.2 or later. Read the affected code and tests before changing behavior.
Include relevant tests and run the shared checks below before submitting a change.
Do not use real trust stores, privileged ports, or personal Sandbar homes for automated tests.
Sandbar is distributed under the [MIT license](LICENSE).

### Build

To build an executable in the checkout:

```sh
CGO_ENABLED=0 go build -o sandbar .
```

Use `sh ./install.sh` to build and install the checkout version for `sandbar` commands in `PATH`.

### Native development sandbox

`scripts/dev` builds and uses a separate `.sandbox/sandbar` executable and home in this checkout:

```sh
scripts/dev init
scripts/dev start
scripts/dev stop
```

Run a backend on `127.0.0.1:18000` first.
The sandbox routes `https://dev.sandbar.localhost:18443`, with HTTP redirects on port `18080`.
The launcher always passes `--home`, so `SANDBAR_HOME` cannot select your normal instance.
`init` and `start` build current source. `start` checks the fixed settings before invoking Caddy.
`stop` uses the existing executable, so build errors do not prevent shutdown.
The launcher accepts only these three commands.

Configuration, logs, sockets, and CA material remain in ignored `.sandbox/`.
Stop the sandbox before moving the checkout or editing its source configuration.
This isolates state and ports. Other apps can still occupy the selected ports.

### Isolated curl proof

Use an installed `sandbar`, Python 3, and curl. Ports 18000, 8080, and 8443 must be free.
This proof changes no system DNS, hosts file, or trust store:

```sh
proof_home=$(mktemp -d /tmp/sandbar-proof.XXXXXX)
mkdir "$proof_home/backend"
printf 'sandbar backend\n' > "$proof_home/backend/index.html"
python3 -m http.server 18000 --bind 127.0.0.1 --directory "$proof_home/backend" > "$proof_home/backend.log" 2>&1 &
backend_pid=$!

sandbar --home "$proof_home" init --http-port 8080 --https-port 8443 app.sandbar.localhost 18000
sandbar --home "$proof_home" start
curl --noproxy '*' --location --dump-header - --retry 5 --retry-delay 1 --retry-all-errors \
  --resolve app.sandbar.localhost:8080:127.0.0.1 \
  --resolve app.sandbar.localhost:8443:127.0.0.1 \
  --cacert "$proof_home/state/caddy/pki/authorities/local/root.crt" \
  http://app.sandbar.localhost:8080/
sandbar --home "$proof_home" stop
kill "$backend_pid"
```

Expect HTTP 308, then verified HTTPS 200 and `sandbar backend`.
`--resolve` preserves the hostname for HTTP and TLS while selecting loopback.
`--cacert` verifies the certificate. `--noproxy '*'` bypasses proxy settings.
Caddy can finish starting before its first certificate is ready. The curl retries cover that brief interval.
Sandbar does not poll readiness or retry Caddy commands.
The disposable home remains available for inspection after the proof.

### Checks

Run on Linux with Go 1.27.2 or later and a C compiler:

```sh
scripts/check
scripts/check --integration
```

Both commands check formatting, shell syntax, installers, module consistency, vet, Staticcheck, shuffled race tests, fuzzing, known vulnerabilities, and static builds.
The second also runs real Caddy acceptance. It requires installed Caddy and `ss` from `iproute2`.
CI uses the same command with `--integration`.

Pinned tools build into `.sandbox/tools`. Initial setup and vulnerability scanning need network access.
Staticcheck v0.8.1 uses x/tools v0.50.0 for Go 1.27.2 export data. Govulncheck uses v1.8.0.
Reports and the validation executable stay in `.sandbox/check`.
Coverage counts code called inside the test process, excluding separate CLI processes.
Integration subprocess builds also use race detection.

```sh
go tool cover -html=.sandbox/check/coverage.out
go test -run='^$' -fuzz='^FuzzConfig$' -fuzztime=1m -parallel=2 .
```

Keep failing fuzz inputs under `testdata/fuzz/FuzzConfig` when fixing discovered bugs.
Tests that change process environment or exercise the router lock stay sequential.
Pure tests can run in parallel when their state is independent.
Native tests use temporary homes and high ports, then stop only the Caddy instances they create.
Trust-command tests use fake Caddy. Browser acceptance uses the separate [isolated browser proof](docs/browser-proof.md).
See [release preparation](docs/install.md#release-preparation) for packaging and installer checks.

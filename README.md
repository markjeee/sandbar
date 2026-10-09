# Sandbar

Sandbar is a standalone Linux CLI for local HTTPS routes through Caddy.
It connects one `<name>.sandbar.localhost` hostname to an HTTP backend on `127.0.0.1`.
Sandbar exits after each command. Only Caddy stays running.

## Build

Use Go 1.27. Sandbar uses only the Go standard library.

```sh
CGO_ENABLED=0 go build -o sandbar .
./sandbar --help
```

## Configuration

```sh
./sandbar init app.sandbar.localhost 8000
```

HTTP port 80 redirects to HTTPS port 443. The HTTPS URL is `https://app.sandbar.localhost`.
The upstream, HTTP, and HTTPS ports must differ.
Flags must precede positional arguments.

```sh
./sandbar --home /tmp/sandbar-demo init --http-port 8080 --https-port 8443 app.sandbar.localhost 8000
```

Home selection uses `--home`, then `SANDBAR_HOME`, then Linux defaults:

- Configuration: `$XDG_CONFIG_HOME/sandbar/config.json`, or `~/.config/sandbar/config.json`.
- Runtime state: `$XDG_STATE_HOME/sandbar`, or `~/.local/state/sandbar`.
- With a home override: `<home>/config.json` and `<home>/state`.

Relative XDG paths are ignored. Explicit homes can be relative paths.
Use the same home for every command. Keep its path short enough for a Linux Unix socket.
Home paths cannot contain control characters, braces, or vertical bars because Caddy treats these as syntax.
Directories have mode `0700`. Private regular files have mode `0600`.

The source has five fields:

```json
{
  "version": 1,
  "hostname": "app.sandbar.localhost",
  "upstream_port": 8000,
  "http_port": 80,
  "https_port": 443
}
```

`init` needs no Caddy executable. Repeating identical initialization succeeds without rewriting the source.
Different settings return an error and preserve the existing file.
Edit `config.json` while stopped. Unknown fields, invalid hostnames, and invalid ports are rejected.
Names below `.sandbar.localhost` need no public domain registration.

## Caddy

Install Caddy v2.11.7 or a later stable v2 release separately.
Sandbar uses Caddy's [standard commands](https://caddyserver.com/docs/command-line).
It does not embed Caddy or install a system service.

`start` generates and validates a private `Caddyfile` before replacing the previous generated file.
The generated file belongs to Sandbar. It is not a source configuration interface.
Caddy uses internal TLS, a private Unix admin socket, and private certificate storage.
HTTP and HTTPS bind only to IPv4 loopback and available IPv6 loopback.
HTTP/3 is disabled. HTTP serves redirects only for the configured hostname.

```sh
./sandbar start
./sandbar stop
```

Both commands forward Caddy's result. Startup failures include Caddy diagnostics and the log path.
Before startup, Sandbar checks the private admin socket once. An active or inaccessible socket prevents startup.
A missing socket or a stale socket that refuses connections allows startup.
This prevents a second Caddy instance from replacing the first instance’s admin socket.
The check sends no admin API request. It has a one-second limit and does not retry.
Repeated stop retains Caddy’s behavior. A failed command remains an error.
`stop` addresses only the selected home's admin socket, even if the source file was edited.
It retains configuration, logs, and certificate material.

Ports 80 and 443 need operating-system permission.
On Linux, Caddy can require `CAP_NET_BIND_SERVICE`. See [Caddy's low-port guidance](https://caddyserver.com/docs/quick-starts/reverse-proxy).
Sandbar lifecycle commands never change capabilities or elevate privileges.
Stop DDEV or another competing router before using the same addresses and ports.
Sandbar does not stop other routers or select alternate ports after a conflict.

## Browser trust

Use `trust` and `untrust` explicitly for the CA belonging to the selected Sandbar home:

```sh
./sandbar trust
./sandbar untrust
```

Both commands accept no command arguments and use the same home precedence as lifecycle commands.
`trust` needs the selected Caddy instance running. `untrust` uses its stored public root and works after stop.
Trust stores belong to the caller's environment. **`--home` selects a CA and does not isolate trust stores.**
Caddy can request elevated access and can attempt changes to user, system, Firefox, and Java stores.
A failure can leave partial changes. Command success does not prove Chrome trust or complete trust removal.
See [Ubuntu Chrome setup and exact-certificate cleanup](docs/browser-trust.md) before requesting trust changes.
For development, use the [isolated Chrome MCP proof](docs/browser-proof.md), which changes only disposable NSS state.

## Native development sandbox

Use `scripts/dev` for manual development. It uses the installed Go and Caddy binaries with a dedicated home in this checkout.
The launcher always passes `--home`, so an exported `SANDBAR_HOME` cannot select your normal instance.

| Setting | Development value |
| --- | --- |
| Home | `.sandbox/` in this checkout |
| Hostname | `dev.sandbar.localhost` |
| HTTP redirect port | `18080` |
| HTTPS port | `18443` |
| HTTP backend | `127.0.0.1:18000` |

```sh
scripts/dev init
scripts/dev start
scripts/dev stop
```

`init` and `start` build `.sandbox/sandbar` from the current source.
`start` also checks that the existing configuration matches these fixed settings before invoking Caddy.
`stop` uses the existing executable, so a source build error does not prevent shutdown.
The launcher accepts only these three commands. The normal CLI still defaults to ports 80 and 443.

Configuration, generated files, logs, the admin socket, and CA material stay in `.sandbox/`, which Git ignores.
Stop the sandbox before moving the checkout or editing its source configuration.
Keep the fixed settings when using the launcher. Use the direct CLI with a separate home for other configurations.
The host Caddy service and its configuration are not used by this launcher.
This is state and port isolation, not a container or an operating-system security boundary.
Another application can still occupy the selected high ports. A conflict remains an error.

For a disposable backend, run these commands in one terminal:

```sh
scripts/dev init
mkdir -p .sandbox/backend
printf 'sandbar development backend\n' > .sandbox/backend/index.html
python3 -m http.server 18000 --bind 127.0.0.1 --directory .sandbox/backend
```

In another terminal, start and verify the route:

```sh
scripts/dev start
curl --noproxy '*' --location --dump-header - --retry 5 --retry-delay 1 --retry-all-errors \
  --resolve dev.sandbar.localhost:18080:127.0.0.1 \
  --resolve dev.sandbar.localhost:18443:127.0.0.1 \
  --cacert .sandbox/state/caddy/pki/authorities/local/root.crt \
  http://dev.sandbar.localhost:18080/
scripts/dev stop
```

Stop the backend with Ctrl+C in its terminal. Sandbox configuration and certificates remain available for the next session.
Automated integration tests continue to use disposable homes and dynamically allocated high ports.

## Isolated curl proof

Use Python 3 for a disposable backend and curl for the request.
NetBox is an optional example name in this proof. The backend is generic and needs no NetBox installation.
Run these commands from this checkout after building `./sandbar`.
Ports 18000, 8080, and 8443 must be free. Use another upstream port if 18000 is occupied.

```sh
export SANDBAR_HOME="$(mktemp -d /tmp/sandbar-proof.XXXXXX)"
mkdir "$SANDBAR_HOME/backend"
printf 'sandbar backend\n' > "$SANDBAR_HOME/backend/index.html"
python3 -m http.server 18000 --bind 127.0.0.1 --directory "$SANDBAR_HOME/backend" > "$SANDBAR_HOME/backend.log" 2>&1 &
backend_pid=$!

./sandbar init --http-port 8080 --https-port 8443 netbox.sandbar.localhost 18000
./sandbar start
curl --noproxy '*' --location --dump-header - --retry 5 --retry-delay 1 --retry-all-errors \
  --resolve netbox.sandbar.localhost:8080:127.0.0.1 \
  --resolve netbox.sandbar.localhost:8443:127.0.0.1 \
  --cacert "$SANDBAR_HOME/state/caddy/pki/authorities/local/root.crt" \
  http://netbox.sandbar.localhost:8080/
./sandbar stop
kill "$backend_pid"
unset SANDBAR_HOME
```

Expect HTTP 308 with `Location: https://netbox.sandbar.localhost:8443/`, followed by HTTPS 200 and `sandbar backend`.
The CA and log paths are also printed by `start`.
Caddy can finish starting before its first certificate is ready. The curl retries cover that brief interval.
Sandbar does not poll readiness or retry Caddy commands.
This proof changes no system DNS, hosts file, or trust store.
`--resolve` preserves the hostname for HTTP and TLS while selecting loopback explicitly.
`--cacert` verifies the certificate. The `.localhost` suffix does not establish certificate trust.
`--noproxy '*'` keeps proxy environment settings out of the proof.

## Checks

Run the shared check command on Linux with Go 1.27 and a C compiler:

```sh
scripts/check
scripts/check --integration
```

The first command runs the fast tests and fuzzing. The second also runs real Caddy acceptance.
Native acceptance requires installed Caddy and `ss` from `iproute2`.
Both commands run these checks:

- `gofmt` and shell syntax, without rewriting source files.
- `go mod tidy -diff` and `go vet`.
- Staticcheck v0.8.1 with its default checks.
- Uncached, shuffled race tests with a three-minute limit and an in-process coverage report.
- Configuration fuzzing for ten seconds with two workers.
- govulncheck v1.8.0 for reachable known Go vulnerabilities, including standard library vulnerabilities.
- A static Linux build with `CGO_ENABLED=0`.

The script installs the pinned development tools into ignored `.sandbox/tools` using Go's normal module cache.
Initial installation needs network access. Vulnerability scanning also needs access to the Go vulnerability database.
A failed tool installation or scan fails the check. Sandbar itself retains no external Go module dependencies.
CI runs the same command with `--integration` and saves the coverage report.

Check reports and the final validation executable stay in `.sandbox/check`.
Integration CLI builds use temporary directories. Neither replaces the manual development executable or its configuration.
The race flag also reaches CLI subprocess builds during integration tests.
Coverage reports count code called inside the test process. They do not include code executed by separate CLI processes.
Use coverage to find untested behavior, without an arbitrary percentage target:

```sh
go tool cover -html=.sandbox/check/coverage.out
```

Fuzz seeds run during ordinary `go test` calls. For a longer focused run:

```sh
go test -run='^$' -fuzz='^FuzzConfig$' -fuzztime=1m -parallel=2 .
```

Retain a failing fuzz input under `testdata/fuzz/FuzzConfig` when fixing a discovered bug.
Tests that change process environment or exercise the router lock stay sequential.
Pure tests can run in parallel when their state is independent.

Native tests use temporary homes and high ports. They stop only the Caddy instances they create.
They verify certificate trust, redirects, forwarded headers, private state, loopback listeners, and shutdown.
IPv6 and non-loopback checks report explicit skips only when the required interface is unavailable.
The Ubuntu CI job pins Caddy v2.11.7 and Go 1.27.1.
macOS support remains deferred. Chrome acceptance follows the separate [isolated browser proof](docs/browser-proof.md).
Trust-command tests use fake Caddy. They do not change personal or system trust stores.

These choices follow [Go security guidance](https://go.dev/doc/security/best-practices),
[Go fuzzing guidance](https://go.dev/doc/security/fuzz/), and [Staticcheck usage](https://staticcheck.dev/docs/getting-started/).

### Verified environment

On 2026-10-08, local checks passed on Ubuntu 24.04.5 LTS, Linux amd64, with Go 1.27.1 and Caddy v2.11.7.
The shared `scripts/check --integration` command passed formatting, module consistency, vet, Staticcheck, shuffled race tests, native acceptance, and the static Linux build.
In-process statement coverage was 90.1%. The ten-second fuzz run completed 84,230 executions without a failure.
Govulncheck found no known vulnerabilities. All four Caddyfile fixtures passed real Caddy validation.
IPv6 and non-loopback checks both ran. The curl proof returned HTTP 308, then verified HTTPS 200 from the disposable backend.
The GitHub Actions job was added but has not run remotely.

### Phase 2 verification

On 2026-10-08, local Phase 2 checks passed on Ubuntu 24.04 with Caddy v2.11.7, native Chrome 154.0.8037.97, and Chrome DevTools MCP 1.10.1.
`scripts/check --integration` passed formatting, module checks, vet, Staticcheck, shuffled race tests, native acceptance, fuzzing, govulncheck, and the static Linux build.
In-process coverage was 90.6%. Fuzzing completed 158,044 executions without failure. Govulncheck found no known vulnerabilities.

Fresh Chrome processes rejected the target before import, followed HTTP 308 to HTTPS 200 after import, and rejected it after removal.
The redirect retained the path and query. A distinct control root with the same subject remained trusted and its route still worked.
Watched personal and system certificate-file hashes stayed unchanged. Temporary profiles, NSS state, CA keys, and router state were removed.

CLI trust delegation used fake Caddy tests. Real browser verification used direct imports into a disposable NSS database.
Real system-store installation, removal, and privilege prompts remain untested. Remote CI has not run for Phase 2.

# Development and contributions

Choose your tools and submit changes through a [pull request](https://github.com/markjeee/sandbar/pulls).
Describe what changed and how you checked it.

Sandbar uses Go's standard library and keeps implementation in this repository.
Use Go 1.27.2 or later. Read the affected code and tests before changing behavior.
Include relevant tests and run the shared checks below before submitting a change.
Keep default automated tests away from real trust stores, privileged ports, and personal Sandbar homes. Use guarded disposable fixtures for service acceptance.
Sandbar is distributed under the [MIT license](../LICENSE).

## Platform integration

Package layout, service control, and access policy stay separate from shared route and recovery logic.
The integration supplies verified paths, shared service outcomes, and filesystem operations where needed.
Shared parsing, route generation, HTTPS probes, and recovery decisions must not depend on apt or systemctl output.
Later packages or platforms need installation checks, service operations, permission rules, and native acceptance before claiming support.
Use fake operations and alternate paths for shared tests. Do not add speculative stubs or a plugin framework.

## Private development homes

`--home` takes priority over `SANDBAR_HOME`. Both explicitly select development operation.
Binary location does not select the mode. Private routers leave installed services and routes unchanged.
Without a home override, the current source version uses the installed service rather than XDG user paths.
With a home override, files are `<home>/config.json` and `<home>/state`.
Use the same home for every command:

```sh
sandbar --home /tmp/sandbar-demo init --http-port 8080 --https-port 8443
sandbar --home /tmp/sandbar-demo add app.sandbar.localhost 8000
sandbar --home /tmp/sandbar-demo start
sandbar --home /tmp/sandbar-demo stop
```

Explicit homes can use relative paths. Keep paths short enough for a Linux Unix socket.
Paths cannot contain control characters, braces, or vertical bars because Caddy treats these as syntax.
Directories have mode `0700`. Private regular files have mode `0600`.
Development routers do not serve the installed welcome page.
`--home` selects a CA and does not isolate user or system trust stores.

## Build

To build an executable in the checkout:

```sh
CGO_ENABLED=0 go build -o sandbar .
```

Use `sh ./install.sh` to build and install the checkout version for `sandbar` commands in `PATH`.

## Native development sandbox

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

## Isolated curl proof

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
Private development startup does not poll readiness or retry Caddy commands.
The disposable home remains available for inspection after the proof.

## Checks

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
Trust-command tests use fake Caddy. Browser acceptance uses the separate [isolated browser proof](browser-proof.md).
See [release preparation](install.md#release-preparation) for packaging and installer checks.

## Disposable service acceptance

`scripts/check-service` changes service configuration, access rules, and test accounts.
Run it only in a fresh disposable Ubuntu 24.04 amd64 VM with actual systemd and packaged Caddy.
It is separate from `scripts/check --integration` and the private browser proof.
Never use a personal machine or real trust stores for this fixture.
Install apt Caddy v2.11.7 or later, sudo, Polkit, ripgrep, iproute2, curl, OpenSSL, and Python 3 first.

Build the checkout executable, then make it readable and executable by the fixture users.
In the disposable VM only:

```sh
CGO_ENABLED=1 go build -race -o /tmp/sandbar-service-check .
sudo install -m 0755 /tmp/sandbar-service-check /usr/local/bin/sandbar-service-check
sudo touch /run/sandbar-service-acceptance
sudo env SANDBAR_SERVICE_ACCEPTANCE=disposable-ubuntu-24.04 \
  scripts/check-service /usr/local/bin/sandbar-service-check
```

The marker and environment value are both required. The script rejects existing installed Sandbar state and fixture accounts.
It checks real group, Polkit, and sudo access using users without general sudo membership.
It checks stock replacement, welcome HTTPS and redirects, live app changes, rejection, stable PID, shared users, and service restart.
It leaves the configured disposable VM and evidence in `/var/tmp/sandbar-service-acceptance` for inspection.
It stops only its test backend processes on exit. Discard the VM after acceptance.

To check boot startup, reboot that disposable VM yourself.
After reconnecting, recreate the `/run` marker and run the same command with `--after-reboot`.
That mode requires a changed boot ID and checks the retained root, welcome page, unrelated site, and removed apps.
Enablement alone does not establish reboot acceptance.
Migration, rollback, development isolation, and fresh-browser trust still need their separate acceptance checks.
CI runs the initial service fixture in a separate Ubuntu job. It does not claim reboot or browser acceptance.

`scripts/check-migration` is a separate fixture for a fresh disposable VM with the same guard and prerequisites.
It also needs `libcap2-bin` and a working systemd user manager.
Run it with the same executable path instead of `scripts/check-service`:

```sh
sudo env SANDBAR_SERVICE_ACCEPTANCE=disposable-ubuntu-24.04 \
  scripts/check-migration /usr/local/bin/sandbar-service-check
```

It recreates an ordinary user's earlier private router on ports 80 and 443.
It grants a temporary Caddy file capability only inside the disposable fixture to reproduce the beta installation.
Installed setup does not grant that capability. The fixture removes it after successful migration.
It tests missing keys, CA conflicts, pending legacy recovery, validation before shutdown, and real startup and route-check rollback.
It verifies the old root, signing material, unrelated service CA and site, development router, and matching temporary-unit retirement.
It exercises protected backup extraction without automatic migration resumption.
Evidence remains in `/var/tmp/sandbar-migration-acceptance`.
The backend and standard service stay available for separate fresh-browser acceptance. Discard the VM after inspection.

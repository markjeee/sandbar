# Development and contributions

Choose your tools and submit changes through a [pull request](https://github.com/markjeee/sandbar/pulls).
Describe what changed and how you checked it.

Sandbar uses Go's standard library and keeps implementation in this repository.
Use Go 1.27.2 or later. Read the affected code and tests before changing behavior.
Include relevant tests and run the shared checks below before submitting a change.
Keep automated tests away from real trust stores, privileged ports, and installed Sandbar state.
Linux service acceptance uses guarded disposable fixtures. macOS installation acceptance runs later, when requested.
Sandbar is distributed under the [MIT license](../LICENSE).

## Native prerequisites

Use Linux amd64 or macOS arm64 with Go 1.27.2 or later and a native C compiler for race checks.
Install Caddy v2.11.7 or a later v2 release separately.
Linux integration needs `ss` from `iproute2`. macOS integration needs `lsof` and native process inspection tools.
macOS source builds require cgo, clang, and the macOS SDK from Xcode or Command Line Tools.
Run `xcode-select --install` if these tools are missing. Scripts check both clang and the SDK before building.
Homebrew supplies installed Caddy. Sandbar owns its current-user LaunchAgent after explicit setup.
Private development does not register a LaunchAgent.
macOS integration also requires curl with HTTP/2 and HTTP/3 support:

```sh
brew install curl
export PATH="$(brew --prefix curl)/bin:$PATH"
curl --version
```

The Features line must include `HTTP2` and `HTTP3`. Apple's system curl does not satisfy this test prerequisite.
This curl is a test client. Installed Sandbar needs no curl, Go, clang, Python, or extra bridge executable.
The curl proof also needs Python 3 and curl.
Run Mac builds and tests natively. Keep Linux builds and tests on Linux CI or another Linux machine.

## Platform integration

Package layout, service control, and access policy stay separate from shared route and recovery logic.
The integration supplies verified paths, shared service outcomes, and filesystem operations where needed.
Shared parsing, route generation, HTTPS probes, and recovery decisions must not depend on apt or systemctl output.
Later packages or platforms need installation checks, service operations, permission rules, and native acceptance before claiming support.
Use fake operations and alternate paths for shared tests. Do not add speculative stubs or a plugin framework.

## Private development homes

`--home` takes priority over `SANDBAR_HOME`. Both explicitly select development operation.
Binary location does not select the mode. Private routers leave installed services and routes unchanged.
Without a home override, beta.2 and later use the installed service rather than XDG user paths.
With a home override, files are `<home>/config.json` and `<home>/state`.
Use the same home for every command:

```sh
sandbar --home /tmp/sandbar-demo init --http-port 8080 --https-port 8443
sandbar --home /tmp/sandbar-demo add app.sandbar.localhost 8000
sandbar --home /tmp/sandbar-demo start
sandbar --home /tmp/sandbar-demo stop
```

Explicit homes can use relative paths. Keep paths short enough for the platform Unix socket limit. Darwin has a smaller limit than Linux.
Paths cannot contain control characters, braces, or vertical bars because Caddy treats these as syntax.
Directories have mode `0700`. Private regular files have mode `0600`.
Development routers do not serve the installed `sandbar.localhost` welcome page.
Version 3 homes serve their own `sandbar-<machine>.localhost` welcome page.
`--home` selects a CA and does not isolate user or system trust stores.

## Build

Use Go 1.27.2 or later. Clone the repository and install its source:

```sh
git clone https://github.com/markjeee/sandbar.git
cd sandbar
sh ./install.sh
```

To build an executable in the checkout without installing:

```sh
# macOS arm64, with SDK clang available
CGO_ENABLED=1 CC="$(xcrun --find clang)" SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" go build -o sandbar .
# Linux amd64, on Linux only
# CGO_ENABLED=0 go build -o sandbar .
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

Both platforms use the same ignored layout:

```text
sandbar/
├── scripts/                 # Shared development, checks, and packaging
└── .sandbox/
    ├── sandbar              # Native development executable
    ├── config.json          # Persistent manual development routes
    ├── state/               # Development Caddyfile, socket, logs, and CA
    ├── check/               # Validation executable, coverage, reports
    ├── tools/               # Pinned analysis tools
    └── release/<version>/   # Local candidate packages
```

The manual development sandbox persists between runs.
Individual automated tests use fresh OS temporary directories, using existing helpers and short paths when sockets require them.
Their cleanup stops only test-owned processes and removes only test-owned temporary files.
Tests leave persistent `.sandbox` routes and state, installed configuration, service registration, and trust stores intact.
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

## Two-machine Teleport proof

Use mark-pro4 as the macOS arm64 client and mark-work-rise as the Linux amd64 peer.
Both checkouts must contain the same revision and a Teleport-capable build.
Install native Go, Caddy, and Python 3 on each machine first.
The remote installed binary path is `/home/markj/.local/bin/sandbar`; installed acceptance requires an authorized Teleport-capable upgrade.
This private proof uses each checkout's own native binary instead.

Use the private `.sandbox/teleport` child home on each machine.
This leaves the persistent manual `.sandbox/config.json` and installed service state intact.
HTTP 18080, HTTPS 18443, and remote backend 18000 must be free.
Stop an existing manual sandbox explicitly before reusing its ports.
Keep checkout paths short enough for the private admin socket. On macOS the socket path must be at most 103 bytes.
Use an unused proof home, or continue the same proof without changing its saved machine identity.
The proof changes no personal trust stores and does not run `trust` or `setup`.

Run in a terminal on **mark-work-rise**, inside its Sandbar checkout:

```sh
proof_home="$PWD/.sandbox/teleport"
proof_bin="$proof_home/sandbar"
mkdir -p "$proof_home"
CGO_ENABLED=0 go build -o "$proof_bin" .
python3 -u - <<'PYBACKEND' > "$proof_home/backend.log" 2>&1 &
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"host": self.headers.get("Host"),
                           "forwarded_host": self.headers.get("X-Forwarded-Host"),
                           "scheme": self.headers.get("X-Forwarded-Proto"),
                           "uri": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
HTTPServer(("127.0.0.1", 18000), Echo).serve_forever()
PYBACKEND
proof_backend_pid=$!
"$proof_bin" --home "$proof_home" init --machine mark-work-rise --http-port 18080 --https-port 18443
"$proof_bin" --home "$proof_home" add teleport.sandbar.localhost 18000
"$proof_bin" --home "$proof_home" add api.teleport.sandbar.localhost 18000
"$proof_bin" --home "$proof_home" start
"$proof_bin" --home "$proof_home" teleport info --json
sha256sum "$proof_home/state/caddy/pki/authorities/local/root.crt"
ss -lntp '( sport = :18080 or sport = :18443 )'
```

Keep that terminal open for its backend PID and cleanup.
Record the absolute `proof_home` and `proof_bin` values for registration from the client.
Check direct access on **mark-work-rise**, using its own public root:

```sh
for host in teleport.sandbar-mark-work-rise.localhost api.teleport.sandbar-mark-work-rise.localhost; do
  curl --noproxy '*' --fail --retry 5 --retry-delay 1 --retry-all-errors \
    --resolve "$host:18443:127.0.0.1" \
    --cacert "$proof_home/state/caddy/pki/authorities/local/root.crt" \
    "https://$host:18443/path?q=1"
done
```

Each JSON response must preserve the exact hostname, port `18443`, `/path?q=1`, and HTTPS scheme.
Run in a terminal on **mark-pro4**, inside its Sandbar checkout:

```sh
proof_home="$PWD/.sandbox/teleport"
proof_bin="$proof_home/sandbar"
mkdir -p "$proof_home"
CGO_ENABLED=1 CC="$(xcrun --find clang)" SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" go build -o "$proof_bin" .
"$proof_bin" --home "$proof_home" init --machine mark-pro4 --http-port 18080 --https-port 18443
"$proof_bin" --home "$proof_home" start
shasum -a 256 "$proof_home/state/caddy/pki/authorities/local/root.crt"
ssh-add -l
```

Set these values on **mark-pro4** to the absolute remote paths recorded above:

```sh
remote_proof_home=/absolute/remote/checkout/.sandbox/teleport
remote_proof_bin="$remote_proof_home/sandbar"
"$proof_bin" --home "$proof_home" teleport register \
  --remote-bin "$remote_proof_bin" --remote-home "$remote_proof_home" mark-work-rise
"$proof_bin" --home "$proof_home" teleport ls
/usr/sbin/lsof -nP -iTCP:18080 -iTCP:18443 -sTCP:LISTEN
for host in teleport.sandbar-mark-work-rise.localhost api.teleport.sandbar-mark-work-rise.localhost; do
  curl --noproxy '*' --fail --retry 5 --retry-delay 1 --retry-all-errors \
    --resolve "$host:18443:127.0.0.1" \
    --cacert "$proof_home/state/caddy/pki/authorities/local/root.crt" \
    "https://$host:18443/path?q=1"
done
```

Confirm the same complete app URLs and echoed Host values through both paths.
Registration obtains the peer root over verified SSH, then calls connect.
Only the client root verifies browser-facing TLS on mark-pro4.
Do not import the remote root into browser or system trust.

On **mark-pro4**, exercise connection lifetime and keep registration after disconnect:

```sh
"$proof_bin" --home "$proof_home" teleport disconnect mark-work-rise
curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}\n' \
  --resolve teleport.sandbar-mark-work-rise.localhost:18443:127.0.0.1 \
  --cacert "$proof_home/state/caddy/pki/authorities/local/root.crt" \
  'https://teleport.sandbar-mark-work-rise.localhost:18443/path?q=1'
"$proof_bin" --home "$proof_home" teleport connect mark-work-rise
"$proof_bin" --home "$proof_home" teleport ls
```

Expect ordinary HTTP 502 while disconnected. Repeat the verified requests after reconnect.
Add another remote canonical app on mark-work-rise and confirm its alias works without re-registering on mark-pro4.
Record source and CA hashes before and after registration. Registration must not change remote configuration, CA, or trust.

Cleanup on **mark-pro4**:

```sh
"$proof_bin" --home "$proof_home" teleport rm mark-work-rise
"$proof_bin" --home "$proof_home" stop
shasum -a 256 "$proof_home/state/caddy/pki/authorities/local/root.crt"
```

Cleanup in the original **mark-work-rise** terminal:

```sh
"$proof_bin" --home "$proof_home" stop
kill "$proof_backend_pid"
wait "$proof_backend_pid" || true
sha256sum "$proof_home/state/caddy/pki/authorities/local/root.crt"
```

Keep proof-owned files for inspection, or remove only each checkout's `.sandbox/teleport` child afterward.
Do not remove the parent `.sandbox`, stop installed Caddy, or remove trust as proof cleanup.
Installed acceptance is separate. After authorized upgrades and app setup, use the same machine-qualified URL on HTTPS 443 without a port.
For the installed remote metadata prerequisite, use `/home/markj/.local/bin/sandbar teleport info --json` through verified SSH.

## Checks

Run natively on Linux amd64 or macOS arm64 with the prerequisites above:

```sh
scripts/check
scripts/check --integration
```

Both commands check formatting, shell syntax, installers, module consistency, vet, Staticcheck, shuffled race tests, fuzzing, known vulnerabilities, and native builds.
macOS builds include cgo. Linux release builds retain `CGO_ENABLED=0`.
The second also runs real Caddy routing, setup configuration acceptance, and macOS inherited-listener checks.
macOS integration rejects a PATH curl without HTTP/2 and HTTP/3 support. CI installs Homebrew curl and checks the same features.
The high-port handoff tests supply TCP/UDP descriptors directly and force all three HTTPS protocols with isolated roots.
It uses `ss` on Linux or machine-readable `lsof` output on macOS for independent listener evidence.
CI uses the same command with `--integration`, with a native architecture assertion for each platform.
Record local macOS, macOS CI, and Linux CI results separately against the same revision.
A configured CI job is not evidence that the remote checks passed.

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
Trust-command tests use fake Caddy and preserve personal trust stores.
Linux browser acceptance uses the separate [isolated browser proof](browser-proof.md).
macOS browser acceptance follows explicit installation and trust requests below.
See [release preparation](install.md#release-preparation) for beta.4 packaging and installer checks.
Run `scripts/release` for authored beta.4 notes, or use `--version <candidate-version>` for unpublished candidate notes.
Public releases use the same committed revision on both native platforms and one combined checksum manifest.
Verify downloads with temporary `--bin-dir` destinations. Keep setup, trust, and installed service changes separate.

## Test layers

Use these three layers alongside the persistent manual development sandbox:

| Layer | Runs | State and effects |
| --- | --- | --- |
| Automated integration | Native Sandbar, real Caddy and backends, verified TLS | Fresh temporary homes, high ports, test-owned cleanup |
| Automated setup | Actual setup logic, real `caddy adapt` and `caddy validate`, simulated service operations | Temporary installation paths and isolated Caddy storage |
| Installation acceptance | Installed Sandbar and its actual user LaunchAgent | Normal installed paths, when the Developer requests installation |

Setup fixtures cover preview, fresh and repeated setup, conflicts, backups, ordinary rollback, and preserved unrelated configuration.
They validate default and explicitly selected installed ports without binding privileged ports or registering the real service.
TLS clients use the selected temporary CA directly. They never disable certificate verification or import it into personal stores.
Passing required native checks establishes readiness for installation. It does not prove installed service operation or browser trust.
No disposable macOS VM or spare Mac is required for development completion.

## macOS installation acceptance

Run this checklist only when installation and its service changes are requested.
Record each result separately as pending or verified. Do not infer it from mocks or private-router tests.

1. Record the original CA fingerprint, routes, and service state. Preview `sandbar setup --check --http-port 80 --https-port 443`.
2. Review job paths, socket plan, backups, conflicts, and service transfer. Apply `sandbar setup --http-port 80 --https-port 443` as the normal user.
3. Verify `local.sandbar.caddy` owns TCP 80, TCP 443, and UDP 443 on both available loopback families. Confirm Caddy runs as your user.
4. Check HTTP 308 redirects with preserved path/query and HTTPS port 443. Force verified HTTP/1.1, HTTP/2, and HTTP/3 with curl. Check HTTP/3 advertisement.
5. Start a generic backend and verify a configured app route with the selected root and normal TLS verification.
6. Change and remove routes while Caddy runs. Confirm its PID stays unchanged and unrelated sites keep working.
7. Stop and start through Sandbar. Confirm TCP/UDP listener closure and that traffic cannot restart the stopped job. Verify restored routes, ports, CA fingerprint, and login registration. Repeat setup without port options and verify retained ports.
8. Keep existing trust unchanged. Follow the [macOS Chrome checklist](browser-trust.md#macos-browser-acceptance) in a fresh browser process.
9. Verify startup after an actual later login. Registration alone is insufficient. Do not force logout during development.
10. Run exact-root trust removal only when separately requested, then verify certificate rejection in a fresh Chrome process with Caddy running.

Keep real service, browser trust, trust removal, and actual new-login acceptance pending until checked.
Do not remove the installed CA as automatic test cleanup.
Use ordinary setup backups and reported diagnostics for recovery. Preserve unrelated Caddy configuration and CA material.

## Disposable service acceptance

`scripts/check-service` changes service configuration, access rules, and test accounts.
Run it only in a fresh disposable Ubuntu 24.04 amd64 VM with actual systemd and packaged Caddy.
It is separate from `scripts/check --integration` and the private browser proof.
Never target a personal machine, a live developer installation, or personal trust stores with this fixture.
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

After the ordinary fixture, run uninstall acceptance only in that same marked disposable VM.
If you want reboot acceptance, complete `--after-reboot` first. Uninstall stops and disables Caddy and removes the fixture installation.
Recreate the `/run` marker after a reboot. Keep the required environment guard:

```sh
sudo env SANDBAR_SERVICE_ACCEPTANCE=disposable-ubuntu-24.04 \
  scripts/check-service /usr/local/bin/sandbar-service-check --uninstall
```

This mode checks shared-site refusal before separating only the fixture's unrelated site.
It checks ownership and group-member refusal, read-only preview, confirmed cleanup, retained executables and unrelated resources, and repeat removal.
It trusts and untrusts the fixture root inside the disposable VM. This is not browser acceptance.
A temporary fixture-only administrator sudo rule models normal approval for the test account and is removed when the script exits.
That rule is separate from Sandbar's installed validation policy. Do not copy it into an installed developer environment.
Uninstall evidence stays in `/var/tmp/sandbar-service-acceptance`. Discard the VM after inspection.

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

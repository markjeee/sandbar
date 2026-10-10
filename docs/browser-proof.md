# Isolated Chrome browser proof

This guide checks real Caddy routing and Chrome trust on Ubuntu 24.04 with native Google Chrome.
It uses generic backend content, temporary Sandbar homes, high ports, and Chrome DevTools MCP.
Run it as a normal user with the checkout version installed as `sandbar` in PATH.
Stop at any unexpected failure. Keep test state until its processes stop.

**Do not run real `sandbar trust`, `sandbar untrust`, or Caddy trust commands during this proof.**
A temporary Sandbar home and browser profile do not isolate system trust stores.
Use direct NSS import and removal only against the temporary database below.
Command delegation is covered separately by fake-Caddy tests.
This browser proof does not validate real system-store mutation or Caddy privilege prompts.

Prerequisites are Caddy, Python 3, curl, OpenSSL, Node.js, native Chrome, and an installed Chrome DevTools MCP package.
Use NSS `certutil` if available. The setup can extract Ubuntu's `libnss3-tools` package without installing it.
Download needs network access. No package installation or elevated privileges are part of this proof.
Use [Chrome DevTools MCP](https://github.com/ChromeDevTools/chrome-devtools-mcp) 1.10.1 for the tool names and output below.
Record any version difference before adjusting the checks.

## Record certificate-store state

Pause unrelated browser activity during the proof to avoid unrelated NSS writes.
Define this read-only manifest command before setup:

```sh
trust_manifest() {
  python3 - <<'PYTHON'
import hashlib, json, os
from pathlib import Path
home = Path.home()
roots = [home / '.pki/nssdb', home / '.local/share/pki/nssdb',
         Path('/etc/ssl/certs'), Path('/usr/local/share/ca-certificates'),
         Path('/usr/share/ca-certificates')]
xdg = os.environ.get('XDG_DATA_HOME')
if xdg and Path(xdg).is_absolute():
    roots.append(Path(xdg) / 'pki/nssdb')
manifest = {}
for root in roots:
    manifest[str(root)] = 'present' if root.exists() else 'absent'
    if root.exists():
        for path in sorted(root.rglob('*')):
            if path.is_file():
                manifest[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
print(json.dumps(manifest, sort_keys=True, indent=2))
PYTHON
}
```

A read failure stops the comparison. Do not claim preservation without both manifests.

## Prepare disposable state

Keep this shell open until cleanup. Do not export a replacement for your shell's `HOME`.
Use separate environment values only when launching the dedicated MCP server.

```sh
proof_dir="$(mktemp -d /tmp/sb-browser.XXXXXX)"
trust_manifest > "$proof_dir.before.json"
browser_home="$proof_dir/browser-home"
proof_db="$browser_home/.pki/nssdb"
mkdir -p "$proof_db" "$proof_dir/backend"
printf '<!doctype html><title>Sandbar browser proof</title><h1>Generic Sandbar backend</h1>\n' > "$proof_dir/backend/check.html"
# Hold five sockets together so each allocated port differs. Caddy still reports binding conflicts.
set -- $(python3 -c 'import socket; s=[socket.socket() for _ in range(5)]; [x.bind(("127.0.0.1",0)) for x in s]; print(*(x.getsockname()[1] for x in s))')
backend_port="$1"; http_port="$2"; https_port="$3"; control_http_port="$4"; control_https_port="$5"
python3 -m http.server "$backend_port" --bind 127.0.0.1 --directory "$proof_dir/backend" > "$proof_dir/backend.log" 2>&1 &
backend_pid=$!

proof_certutil="$(command -v certutil || true)"
if [ -z "$proof_certutil" ]; then
  (cd "$proof_dir" && apt-get download libnss3-tools)
  dpkg-deb -x "$proof_dir"/libnss3-tools_*.deb "$proof_dir/nss-tools"
  proof_certutil="$proof_dir/nss-tools/usr/bin/certutil"
fi
"$proof_certutil" -N --empty-password -d "sql:$proof_db"

sandbar --home "$proof_dir/target" init --http-port "$http_port" --https-port "$https_port" app.sandbar.localhost "$backend_port"
sandbar --home "$proof_dir/target" start
sandbar --home "$proof_dir/control" init --http-port "$control_http_port" --https-port "$control_https_port" app.sandbar.localhost "$backend_port"
sandbar --home "$proof_dir/control" start
target_root="$proof_dir/target/state/caddy/pki/authorities/local/root.crt"
control_root="$proof_dir/control/state/caddy/pki/authorities/local/root.crt"
openssl x509 -in "$target_root" -noout -subject -sha256 -fingerprint
openssl x509 -in "$control_root" -noout -subject -sha256 -fingerprint
```

Record the root fingerprints. They must differ despite sharing a subject display name.
Import the second root as a control before testing the first route:

```sh
"$proof_certutil" -A -d "sql:$proof_db" -t 'C,,' -n sandbar-control -i "$control_root"
"$proof_certutil" -L -d "sql:$proof_db" -n sandbar-control -a > "$proof_dir/control-before.pem"
curl --noproxy '*' --fail --retry 5 --retry-delay 1 --retry-all-errors \
  --resolve "app.sandbar.localhost:$https_port:127.0.0.1" --cacert "$target_root" \
  "https://app.sandbar.localhost:$https_port/check.html?phase=ready"
```

The curl request waits for the first leaf certificate without changing browser resolution or trust.
Its resolution override is confined to curl. Browser checks use normal `.localhost` resolution.

## Launch a dedicated MCP server

Set `mcp_entry` to the installed package's `build/src/bin/chrome-devtools-mcp.js`.
Set `chrome_bin` to the native Chrome executable, usually `/opt/google/chrome/chrome`.
Generate a temporary client configuration for each phase, using a different `phase` value:

```sh
mcp_entry='/replace/with/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js'
chrome_bin='/opt/google/chrome/chrome'
phase='before-trust'
python3 - "$browser_home" "$proof_dir/profile-$phase" "$chrome_bin" "$mcp_entry" <<'PY'
import json, sys
home, profile, chrome, entry = sys.argv[1:]
args = ['HOME=' + home, 'XDG_CONFIG_HOME=' + home + '/.config',
        'XDG_DATA_HOME=' + home + '/.local/share', 'XDG_CACHE_HOME=' + home + '/.cache',
        'XDG_STATE_HOME=' + home + '/.local/state', 'CHROME_DEVTOOLS_MCP_NO_UPDATE_CHECKS=1',
        'node', entry, '--headless', '--executablePath=' + chrome,
        '--userDataDir=' + profile, '--no-usage-statistics', '--no-performance-crux',
        '--no-page-id-routing']
print(json.dumps({'mcpServers': {'sandbar-proof': {'command': 'env', 'args': args}}}, indent=2))
PY
```

Use this configuration in a separate MCP client session, with no connection to an existing personal browser.
Do not use the existing shared browser MCP session unless its process home and NSS database match this temporary setup.
The explicit `.pki/nssdb` database is created before Chrome starts, so Chrome uses it instead of the newer default location.
A different `--userDataDir` alone does not isolate certificate trust.

Call these MCP tools, substituting the numeric ports and phase:

1. `list_pages` to start the dedicated browser.
2. `navigate_page` with `{"url":"http://app.sandbar.localhost:<http-port>/check.html?phase=<phase>"}`.
3. `take_snapshot` to inspect the page or certificate error.
4. `list_network_requests` to find the HTTPS request's `reqid`.
5. For successful navigation, `get_network_request` with `{"reqid":<HTTPS-request-id>}`.

`list_network_requests` can show only the final HTTPS response.
`get_network_request` includes the HTTP 308 redirect chain.
Record the final HTTPS URL, 200 response, generic content, and unchanged `/check.html?phase=<phase>`.
Never use DNS overrides, certificate-error bypasses, or warning-page exceptions in the browser.

## Check each trust transition

For `before-trust`, expect `NET::ERR_CERT_AUTHORITY_INVALID` for the target route.
Stop that dedicated MCP server and its Chrome process before changing the database.
Record the process ID and confirm that process exits. Close only processes created for this proof.

```sh
"$proof_certutil" -A -d "sql:$proof_db" -t 'C,,' -n sandbar-target -i "$target_root"
```

Set `phase='trusted'`. Generate a new configuration with a fresh profile and start a fresh Chrome process.
Expect HTTP 308, HTTPS 200, and the generic backend page.
Confirm the path and query survive the redirect in request details.
Stop the dedicated MCP server and Chrome process again, then remove only the target:

```sh
"$proof_certutil" -D -d "sql:$proof_db" -n sandbar-target
"$proof_certutil" -L -d "sql:$proof_db" -n sandbar-control -a > "$proof_dir/control-after.pem"
cmp "$proof_dir/control-before.pem" "$proof_dir/control-after.pem"
"$proof_certutil" -L -d "sql:$proof_db"
```

Confirm `sandbar-target` is absent and `sandbar-control` retains `C,,` trust.
Set `phase='after-removal'` and use a fresh Chrome process and profile.
Expect certificate rejection again for the target route.
Stop that process, then use another fresh process with `phase='control-retained'` and the control HTTP port.
Expect HTTP 308 and HTTPS 200 through the control HTTPS port.
This checks that removing one root preserves a different root with the same display name.

## Evidence and cleanup

Compare the SHA-256 manifests after cleanup. They include absent directories and opaque NSS database hashes.
A file change, addition, or removal fails the comparison. Do not copy personal databases or private keys into logs.

Record Ubuntu, Chrome, Caddy, Node.js, and MCP versions, command results, browser process IDs, and each acceptance result.
Keep certificate fingerprints and request details. Do not retain temporary private keys.
Report skipped checks and distinguish real browser evidence from simulated CLI delegation.

Stop the final dedicated MCP server and every Chrome process it created before cleanup.
Then stop only the two test routers and the recorded backend process:

```sh
cleanup_proof() {
  sandbar --home "$proof_dir/control" stop || return
  sandbar --home "$proof_dir/target" stop || return
  kill "$backend_pid" || return
  wait "$backend_pid" 2>/dev/null || true
  rm -rf -- "$proof_dir" || return
  test ! -e "$proof_dir" || return
  trust_manifest > "$proof_dir.after.json" || return
  cmp "$proof_dir.before.json" "$proof_dir.after.json" || return
  rm -- "$proof_dir.before.json" "$proof_dir.after.json"
}
cleanup_proof
```

If shutdown fails, resolve it before deleting the test state.
Use the recorded process IDs and paths to inspect only this proof's processes.
Confirm no test browser, backend, or Caddy process remains, and compare the certificate-store manifests.
Successful cleanup removes temporary profiles, NSS databases, root keys, and router state.

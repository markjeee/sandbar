package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// All SSH fixtures run a temporary shell program, never a real SSH transport.
// Only the optional -G parser check invokes system SSH with a private -F file.
func fakeTeleportSSH(t *testing.T, info teleportInfo) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' "$@" >> "$FAKE_SSH_CALLS"
printf '%s\n' __SSH_END__ >> "$FAKE_SSH_CALLS"
if [ "$1" = -G ]; then
 printf '%s\n' "$FAKE_SSH_G"
 exit 0
fi
operation=
socket=
master=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -O) operation=$2; shift ;;
  -S) socket=$2; shift ;;
  -M) master=yes ;;
 esac
 shift
done
case "$operation" in
 check) [ -f "$socket.fixture" ]; exit $? ;;
 exit) /bin/rm -f "$socket.fixture"; exit 0 ;;
esac
if [ "$master" = yes ]; then
 if [ -n "$FAKE_SSH_START_FAIL" ]; then
  printf '%s\n' 'fixture forwarding bind failure' >&2
  exit 255
 fi
 printf '%s\n' active > "$socket.fixture"
 if [ -n "$FAKE_SSH_BACKGROUND" ]; then
  /bin/sleep 10 &
  printf '%s\n' "$!" > "$socket.child"
 fi
 exit 0
fi
if [ -n "$FAKE_SSH_PEER_FAIL" ]; then
 printf '%s\n' 'fixture incompatible peer' >&2
 exit 127
fi
/bin/cat "$FAKE_SSH_INFO"
`
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	infoPath := filepath.Join(dir, "info.json")
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_SSH_CALLS", calls)
	t.Setenv("FAKE_SSH_INFO", infoPath)
	t.Setenv("FAKE_SSH_G", "hostname 127.0.0.1\nuser developer\nport 22\nidentityfile /private/do-not-copy\nidentityagent /private/do-not-copy-agent\nproxyjump none\nproxycommand none")
	t.Setenv("SSH_AUTH_SOCK", filepath.Join(dir, "existing-agent.sock"))
	for _, name := range []string{"FAKE_SSH_START_FAIL", "FAKE_SSH_PEER_FAIL", "FAKE_SSH_BACKGROUND"} {
		t.Setenv(name, "")
	}
	return calls
}

func sshFixturePeer(t *testing.T) (teleportDestination, teleportInfo) {
	t.Helper()
	server, _, root := statusHTTPS(t, machineHostname("remote"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != machineHostname("remote") {
			t.Errorf("SNI %s", r.TLS.ServerName)
		}
		if !strings.HasPrefix(r.Host, machineHostname("remote")+":") {
			t.Errorf("Host %s", r.Host)
		}
		_, _ = io.WriteString(w, "Sandbar welcome")
	}))
	d := teleportDestination{Machine: "remote", Host: "127.0.0.1", User: "developer", Port: 22, HTTPSPort: 18443, LocalPort: server.HTTPSPort, RootPEM: string(root)}
	return d, teleportInfo{Protocol: 1, Machine: d.Machine, HTTPSPort: d.HTTPSPort, RootPEM: d.RootPEM}
}

func sshFixturePaths(t *testing.T, destinations ...teleportDestination) (paths, config) {
	t.Helper()
	p := testPaths(t, shortHome(t))
	if err := privateDir(p.state); err != nil {
		t.Fatal(err)
	}
	c := config{Version: 3, Machine: "local", HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}, Teleports: destinations}
	if err := writeConfig(p.config, c); err != nil {
		t.Fatal(err)
	}
	return p, c
}

func readSSHCalls(t *testing.T, path string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var result [][]string
	for _, group := range strings.Split(string(data), "__SSH_END__\n") {
		if group != "" {
			result = append(result, strings.Split(strings.TrimSuffix(group, "\n"), "\n"))
		}
	}
	return result
}

func countSSHArgument(t *testing.T, calls, argument string) int {
	t.Helper()
	count := 0
	for _, args := range readSSHCalls(t, calls) {
		for _, arg := range args {
			if arg == argument {
				count++
			}
		}
	}
	return count
}

func TestTeleportSSHPrivateConfiguration(t *testing.T) {
	d, info := sshFixturePeer(t)
	p, _ := sshFixturePaths(t, d)
	fakeTeleportSSH(t, info)
	cfg, err := prepareTeleportSSH(p, []teleportDestination{d})
	if err != nil {
		t.Fatal(err)
	}
	text := string(readTestFile(t, cfg))
	for _, want := range []string{"IdentityAgent SSH_AUTH_SOCK", "IdentityFile none", "IdentitiesOnly no", "PreferredAuthentications publickey", "ForwardAgent no", "StrictHostKeyChecking ask", "GlobalKnownHostsFile /dev/null", "UserKnownHostsFile \"" + filepath.Join(filepath.Dir(p.config), "ssh/known_hosts") + "\"", "ExitOnForwardFailure yes", "ServerAliveInterval 15", "ServerAliveCountMax 3"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, forbidden := range []string{"/private/do-not-copy", "ProxyCommand", "ProxyJump", "~/.ssh"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("copied %s", forbidden)
		}
	}
	for path, mode := range map[string]os.FileMode{filepath.Dir(cfg): 0700, cfg: 0600, filepath.Join(filepath.Dir(cfg), "known_hosts"): 0600} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != mode {
			t.Fatalf("%s mode: %v %v", path, st, err)
		}
	}
	// Reject weak pre-existing files and symlinks instead of following them.
	known := filepath.Join(filepath.Dir(cfg), "known_hosts")
	if err := os.Chmod(known, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareTeleportSSH(p, []teleportDestination{d}); err == nil {
		t.Fatal("accepted public known_hosts")
	}
	if err := os.Remove(known); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "other"), known); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareTeleportSSH(p, []teleportDestination{d}); err == nil {
		t.Fatal("followed known_hosts symlink")
	}
}

func TestTeleportSSHResolutionAndArgumentQuoting(t *testing.T) {
	_, info := sshFixturePeer(t)
	calls := fakeTeleportSSH(t, info)
	got, err := resolveTeleportSSH("work-alias", "::1", "other-user", 2222, io.Discard)
	if err != nil || got.Host != "::1" || got.User != "other-user" || got.Port != 2222 {
		t.Fatalf("%+v %v", got, err)
	}
	args := readSSHCalls(t, calls)
	if !reflect.DeepEqual(args[0], []string{"-G", "--", "work-alias"}) {
		t.Fatalf("ssh -G args %q", args[0])
	}
	for _, proxy := range []string{"proxycommand /usr/bin/ssh -W %h:%p jump", "proxyjump jump-host"} {
		t.Setenv("FAKE_SSH_G", "hostname remote\nuser dev\nport 22\n"+proxy)
		if _, err := resolveTeleportSSH("work", "", "", 0, io.Discard); err == nil {
			t.Fatalf("accepted %s", proxy)
		}
	}
	for _, bad := range []string{"-option", "bad\nhost", "bad%h", "bad\\host", "bad\"host", "bad host"} {
		if err := validateSSHEndpoint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	d := teleportDestination{RemoteBin: "/tmp/it's a binary;$(touch ignored)", RemoteHome: "/tmp/a 'quoted' home"}
	// A shell parses the generated command into arguments but does not run it.
	command := teleportRemoteCommand(d)
	parsed := exec.Command("/bin/sh", "-c", "set -- "+command+"; printf '%s\\n' \"$@\"")
	output, err := parsed.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{d.RemoteBin, "--home", d.RemoteHome, "teleport", "info", "--json"}
	if got := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n"); !reflect.DeepEqual(got, want) {
		t.Fatalf("quoted args %q want %q", got, want)
	}
}

func TestTeleportSSHLongRuntimePath(t *testing.T) {
	d, _ := sshFixturePeer(t)
	home := filepath.Join(t.TempDir(), strings.Repeat("long-path-", 18), "Sandbar Application Support")
	p := paths{config: filepath.Join(home, "config.json"), state: filepath.Join(home, "state")}
	socket, log, err := teleportRuntime(p, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(socket)) })
	if len(socket) > socketPathLimit || !strings.HasPrefix(socket, "/tmp/sandbar-") {
		t.Fatalf("long control path %s", socket)
	}
	if !strings.HasPrefix(log, p.state) {
		t.Fatalf("log outside selected state %s", log)
	}
	if err := os.Chmod(filepath.Dir(socket), 0755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := teleportRuntime(p, d); err == nil {
		t.Fatal("accepted public runtime directory")
	}
}

func TestTeleportSSHRuntimeTemporarySocketBudget(t *testing.T) {
	for _, extra := range []int{0, 1} {
		t.Run(strconv.Itoa(extra), func(t *testing.T) {
			home := shortHome(t)
			d := teleportDestination{Machine: "remote"}
			// The overflow case fits the old final-path check but cannot fit the
			// temporary path OpenSSH actually binds while creating its master socket.
			targetLength := socketPathLimit - sshControlSocketSuffixLength + extra
			tail := filepath.Join("teleport", teleportID(d.Machine), "control.sock")
			padding := targetLength - len(home) - len(tail) - 2
			if padding < 1 {
				t.Fatal("fixture home leaves no room for a boundary path")
			}
			state := filepath.Join(home, strings.Repeat("a", padding))
			p := paths{config: filepath.Join(home, "config.json"), state: state}
			original := filepath.Join(state, tail)
			if len(original) != targetLength || len(original) > socketPathLimit {
				t.Fatalf("fixture path length %d, want %d", len(original), targetLength)
			}
			socket, log, err := teleportRuntime(p, d)
			if err != nil {
				t.Fatal(err)
			}
			if socket != original {
				t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(socket)) })
			}
			if (socket != original) != (extra > 0) {
				t.Fatalf("fallback for final path length %d: %s", targetLength, socket)
			}
			if log != filepath.Join(filepath.Dir(original), "ssh.log") {
				t.Fatalf("log moved outside selected state: %s", log)
			}
			suffix := "." + strings.Repeat("x", 16)
			listener, err := net.Listen("unix", socket+suffix)
			if err != nil {
				t.Fatalf("selected path cannot bind OpenSSH's temporary socket: %v", err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			if extra > 0 {
				invalid, err := net.Listen("unix", original+suffix)
				if err == nil {
					invalid.Close()
					t.Fatal("overflow fixture unexpectedly bound its temporary socket")
				}
			}
		})
	}
}

func TestTeleportSSHPeerMetadataValidation(t *testing.T) {
	d, info := sshFixturePeer(t)
	p, _ := sshFixturePaths(t, d)
	fakeTeleportSSH(t, info)
	cfg, err := prepareTeleportSSH(p, []teleportDestination{d})
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*teleportInfo){func(i *teleportInfo) { i.Protocol = 2 }, func(i *teleportInfo) { i.Machine = "BAD.Name" }, func(i *teleportInfo) { i.HTTPSPort = 0 }, func(i *teleportInfo) { i.RootPEM = "invalid" }} {
		changed := info
		mutate(&changed)
		data, _ := json.Marshal(changed)
		if err := os.WriteFile(os.Getenv("FAKE_SSH_INFO"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTeleportPeer(cfg, d, io.Discard); err == nil {
			t.Fatalf("accepted %+v", changed)
		}
	}
	for _, data := range []string{"{} {}", "not-json", `{"protocol":1,"private_key":"forbidden"}`} {
		if err := os.WriteFile(os.Getenv("FAKE_SSH_INFO"), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTeleportPeer(cfg, d, io.Discard); err == nil {
			t.Fatal("accepted invalid metadata")
		}
	}
}

func TestTeleportSSHConnectAndDisconnect(t *testing.T) {
	d, info := sshFixturePeer(t)
	p, c := sshFixturePaths(t, d)
	calls := fakeTeleportSSH(t, info)
	for range 2 {
		if err := connectTeleport(p, c, d, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if count := countSSHArgument(t, calls, "-M"); count != 1 {
		t.Fatalf("masters %d", count)
	}
	socket, _, err := teleportRuntime(p, d)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(socket), "unrelated.fixture")
	if err := os.WriteFile(other, []byte("active"), 0600); err != nil {
		t.Fatal(err)
	}
	var listing bytes.Buffer
	if err := listTeleports(p, c, &listing); err != nil || !strings.Contains(listing.String(), "\tconnected") {
		t.Fatalf("list %s %v", listing.String(), err)
	}
	for range 2 {
		if err := disconnectTeleport(p, c, d, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if count := countSSHArgument(t, calls, "exit"); count != 1 {
		t.Fatalf("exits %d", count)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("unrelated session removed")
	}
	listing.Reset()
	if err := listTeleports(p, c, &listing); err != nil || !strings.Contains(listing.String(), "\tdisconnected") {
		t.Fatalf("list %s %v", listing.String(), err)
	}
	saved, err := readConfig(p.config)
	if err != nil || len(saved.Teleports) != 1 {
		t.Fatal("disconnect removed registration")
	}
	for _, args := range readSSHCalls(t, calls) {
		if args[0] != "-F" {
			t.Fatalf("personal SSH config used: %q", args)
		}
	}
}

func TestTeleportSSHConnectFailureRetention(t *testing.T) {
	d, info := sshFixturePeer(t)
	p, c := sshFixturePaths(t, d)
	calls := fakeTeleportSSH(t, info)
	source := readTestFile(t, p.config)
	changed := info
	changed.HTTPSPort++
	data, _ := json.Marshal(changed)
	if err := os.WriteFile(os.Getenv("FAKE_SSH_INFO"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := connectTeleport(p, c, d, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("metadata mismatch %v", err)
	}
	if countSSHArgument(t, calls, "-M") != 0 {
		t.Fatal("opened tunnel with changed metadata")
	}
	data, _ = json.Marshal(info)
	if err := os.WriteFile(os.Getenv("FAKE_SSH_INFO"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SSH_START_FAIL", "yes")
	var diagnostic bytes.Buffer
	if err := connectTeleport(p, c, d, io.Discard, &diagnostic); err == nil || !strings.Contains(diagnostic.String(), "bind failure") {
		t.Fatalf("bind error %v %s", err, diagnostic.String())
	}
	t.Setenv("FAKE_SSH_START_FAIL", "")
	// Probe a closed port while retaining the saved peer's valid CA and identity.
	d.LocalPort = 1
	if err := connectTeleport(p, c, d, io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "verify forwarded welcome") {
		t.Fatalf("readiness %v", err)
	}
	socket, _, _ := teleportRuntime(p, d)
	if _, err := os.Stat(socket + ".fixture"); !os.IsNotExist(err) {
		t.Fatal("failed readiness retained new master")
	}
	if !bytes.Equal(source, readTestFile(t, p.config)) {
		t.Fatal("connect failure rewrote registration")
	}
}

func TestTeleportSSHBackgroundDescriptors(t *testing.T) {
	d, info := sshFixturePeer(t)
	p, c := sshFixturePaths(t, d)
	fakeTeleportSSH(t, info)
	t.Setenv("FAKE_SSH_BACKGROUND", "yes")
	cfg, err := prepareTeleportSSH(p, c.Teleports)
	if err != nil {
		t.Fatal(err)
	}
	socket, log, err := teleportRuntime(p, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		data, err := os.ReadFile(socket + ".child")
		if err != nil {
			t.Error(err)
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Error(err)
			return
		}
		child, err := os.FindProcess(pid)
		if err != nil {
			t.Error(err)
			return
		}
		if err := child.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
	})
	start := time.Now()
	if err := startTeleportMaster(cfg, socket, log, d, io.Discard); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waited for background inherited descriptors: %v", elapsed)
	}
	if err := disconnectTeleport(p, c, d, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestTeleportSSHWelcomeVerification(t *testing.T) {
	d, _ := sshFixturePeer(t)
	if err := probeTeleportWelcome(d); err != nil {
		t.Fatal(err)
	}
	wrong := d
	wrong.Machine = "other"
	if err := probeTeleportWelcome(wrong); err == nil {
		t.Fatal("accepted wrong TLS name")
	}
	_, wrongRoot := statusCertificate(t, machineHostname("remote"))
	wrong = d
	wrong.RootPEM = string(wrongRoot)
	if err := probeTeleportWelcome(wrong); err == nil {
		t.Fatal("accepted wrong root")
	}
	server, _, root := statusHTTPS(t, machineHostname("remote"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusFound) }))
	wrong = d
	wrong.LocalPort = server.HTTPSPort
	wrong.RootPEM = string(root)
	if err := probeTeleportWelcome(wrong); err == nil || !strings.Contains(err.Error(), strconv.Itoa(http.StatusFound)) {
		t.Fatalf("redirect readiness %v", err)
	}
}

func TestTeleportSSHConfigParser(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("system OpenSSH is unavailable")
	}
	home := filepath.Join(t.TempDir(), "Sandbar with % percent and ' quotes")
	p := paths{config: filepath.Join(home, "config.json"), state: filepath.Join(home, "state")}
	d := teleportDestination{Host: "127.0.0.1", User: "developer", Port: 2222}
	cfg, err := prepareTeleportSSH(p, []teleportDestination{d})
	if err != nil {
		t.Fatal(err)
	}
	agent := filepath.Join(t.TempDir(), "selected-agent.sock")
	t.Setenv("SSH_AUTH_SOCK", agent)
	cmd := exec.Command(ssh, "-G", "-F", cfg, teleportAlias(d))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("parse internal SSH config: %v %s", err, output)
	}
	text := string(output)
	for _, want := range []string{"hostname 127.0.0.1\n", "user developer\n", "port 2222\n", "identityfile none\n", "identityagent SSH_AUTH_SOCK\n", "forwardagent no\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in %s", want, text)
		}
	}
	// -G expands percent tokens, so its effective path must match the selected
	// private file exactly, including spaces and the literal percent sign.
	if !strings.Contains(text, "userknownhostsfile "+filepath.Join(home, "ssh/known_hosts")) {
		t.Fatalf("known_hosts path changed: %s", text)
	}
}

func TestTeleportSSHRuntimeInstalledLinuxLayout(t *testing.T) {
	// Inspect the Linux layout using temporary paths. This test does not run Linux
	// service commands or build a Linux executable on another operating system.
	d, info := sshFixturePeer(t)
	p, c := sshFixturePaths(t, d)
	p.installed = &installation{ID: "apt-systemd-v1"}
	fakeTeleportSSH(t, info)
	socket, log, err := teleportRuntime(p, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(log, filepath.Join(p.state, "work/teleport")) {
		t.Fatalf("runtime did not use writable installed work path: %s", log)
	}
	cfg, err := prepareTeleportSSH(p, c.Teleports)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(cfg) != filepath.Join(filepath.Dir(p.config), "ssh") {
		t.Fatalf("SSH config left configuration directory: %s", cfg)
	}
	if len(socket) > socketPathLimit {
		t.Fatalf("control path exceeds socket limit: %s", socket)
	}
}

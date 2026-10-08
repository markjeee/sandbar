package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func shortHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func initialized(t *testing.T) paths {
	t.Helper()
	home := shortHome(t)
	if code, _, errOut := cli(t, "--home", home, "init", "--http-port", "8080", "--https-port", "8443", "netbox.sandbar.localhost", "8000"); code != 0 {
		t.Fatal(errOut)
	}
	p := testPaths(t, home)
	return p
}

func fakeCaddy(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	script := `#!/bin/sh
printf '%s\n' "$@" >> "$FAKE_CALLS"
printf '%s\n' -- >> "$FAKE_CALLS"
case "$1" in
  version) printf '%s\n' "$FAKE_VERSION"; exit "${FAKE_VERSION_EXIT:-0}" ;;
  validate) printf '%s\n' 'validate output'; printf '%s\n' 'validate diagnostic' >&2; exit "${FAKE_VALIDATE_EXIT:-0}" ;;
  start)
    printf '%s\n' 'start output'
    printf '%s\n' "${FAKE_DIAGNOSTIC:-start diagnostic}" >&2
    printf '%s\n' "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_CACHE_HOME" > "$FAKE_ENV"
    umask >> "$FAKE_ENV"
    exit "${FAKE_START_EXIT:-0}" ;;
  stop) printf '%s\n' 'stop output'; printf '%s\n' 'stop diagnostic' >&2; exit "${FAKE_STOP_EXIT:-0}" ;;
  *) exit 99 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "caddy"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_CALLS", calls)
	t.Setenv("FAKE_ENV", filepath.Join(bin, "environment"))
	t.Setenv("FAKE_VERSION", "v2.11.7 h1:test")
	for _, key := range []string{"FAKE_VERSION_EXIT", "FAKE_VALIDATE_EXIT", "FAKE_START_EXIT", "FAKE_STOP_EXIT", "FAKE_DIAGNOSTIC"} {
		t.Setenv(key, "")
	}
	return calls
}

func readCalls(t *testing.T, path string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	for _, block := range strings.Split(strings.TrimSuffix(string(data), "--\n"), "--\n") {
		if block != "" {
			calls = append(calls, strings.Split(strings.TrimSuffix(block, "\n"), "\n"))
		}
	}
	return calls
}

func TestCaddyGolden(t *testing.T) {
	for _, name := range []string{"default-ipv4", "default-ipv6", "override-ipv4", "override-ipv6"} {
		t.Run(name, func(t *testing.T) {
			c := validConfig()
			if strings.HasPrefix(name, "override") {
				c.HTTPPort = 8080
				c.HTTPSPort = 8443
			}
			got, err := renderCaddyfile(c, paths{state: "/tmp/sandbar proof/state"}, strings.HasSuffix(name, "ipv6"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join("testdata", name+".caddyfile"))
			if err != nil {
				t.Fatal(err)
			}
			if got != strings.ReplaceAll(string(want), "@STATE@", "/tmp/sandbar proof/state") {
				t.Fatalf("golden mismatch:\n%s", got)
			}
		})
	}
}

func TestIPv6Probe(t *testing.T) {
	for _, test := range []struct {
		err                error
		available, warning bool
	}{
		{nil, true, false}, {syscall.EAFNOSUPPORT, false, true}, {syscall.EPROTONOSUPPORT, false, true},
		{&net.OpError{Err: syscall.EADDRNOTAVAIL}, false, true}, {syscall.EACCES, false, false}, {syscall.EADDRINUSE, false, false},
	} {
		var diagnostics bytes.Buffer
		got, err := ipv6Available(func() error { return test.err }, &diagnostics)
		if got != test.available || (diagnostics.Len() > 0) != test.warning {
			t.Fatalf("%v: %v %s", test.err, got, &diagnostics)
		}
		if test.err != nil && !test.warning && !errors.Is(err, test.err) {
			t.Fatal("lost unexpected probe error", err)
		}
		if (test.err == nil || test.warning) && err != nil {
			t.Fatal(err)
		}
	}
}

func TestCaddyVersions(t *testing.T) {
	p := initialized(t)
	fakeCaddy(t)
	for _, version := range []string{"v2.11.7 h1:test", "v2.11.8", "v2.12.0", "v2.11.7+custom"} {
		t.Setenv("FAKE_VERSION", version)
		if err := checkCaddy(p, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []string{"", "dev", "v2.11.6", "v2.10.99", "v1.99.99", "v3.0.0", "v2.11.7-rc.1", "v2.11.7junk"} {
		t.Setenv("FAKE_VERSION", version)
		if err := checkCaddy(p, io.Discard); err == nil || !strings.Contains(err.Error(), "v2.11.7 or later v2") {
			t.Fatalf("%q: %v", version, err)
		}
	}
}

func TestStartDelegate(t *testing.T) {
	p := initialized(t)
	callsPath := fakeCaddy(t)
	code, out, errOut := cli(t, "--home", filepath.Dir(p.config), "start")
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	calls := readCalls(t, callsPath)
	if len(calls) != 3 || !reflect.DeepEqual(calls[0], []string{"version"}) {
		t.Fatal(calls)
	}
	if len(calls[1]) != 5 {
		t.Fatalf("invalid validate arguments: %v", calls[1])
	}
	candidate := calls[1][2]
	if filepath.Dir(candidate) != p.state || !strings.HasPrefix(filepath.Base(candidate), ".Caddyfile-") {
		t.Fatal(candidate)
	}
	if !reflect.DeepEqual(calls[1], []string{"validate", "--config", candidate, "--adapter", "caddyfile"}) {
		t.Fatal(calls[1])
	}
	if !reflect.DeepEqual(calls[2], []string{"start", "--config", p.file("Caddyfile"), "--adapter", "caddyfile", "--pidfile", p.file("caddy.pid")}) {
		t.Fatal(calls[2])
	}
	if _, err := os.Stat(candidate); !os.IsNotExist(err) {
		t.Fatal("candidate retained")
	}
	for _, expected := range []string{"https://netbox.sandbar.localhost:8443", p.file("caddy/pki/authorities/local/root.crt"), p.file("caddy.log")} {
		if !strings.Contains(out, expected) {
			t.Fatal(out)
		}
	}
	log := readTestFile(t, p.file("caddy.log"))
	if !strings.Contains(string(log), "start diagnostic") || !strings.Contains(string(log), "start output") {
		t.Fatal(string(log))
	}
	env := readTestFile(t, os.Getenv("FAKE_ENV"))
	for _, name := range []string{"home", "config", "data", "state", "cache"} {
		if !strings.Contains(string(env), p.file(name)+"\n") {
			t.Fatal(string(env))
		}
	}
	if !strings.Contains(string(env), "0077") {
		t.Fatal("child umask", string(env))
	}
}

func TestFailedValidationPreservesGeneratedFile(t *testing.T) {
	p := initialized(t)
	callsPath := fakeCaddy(t)
	if err := os.WriteFile(p.file("Caddyfile"), []byte("previous valid file"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_VALIDATE_EXIT", "23")
	code, _, errOut := cli(t, "--home", filepath.Dir(p.config), "start")
	if code != 23 || !strings.Contains(errOut, "validate diagnostic") {
		t.Fatalf("%d %s", code, errOut)
	}
	data := readTestFile(t, p.file("Caddyfile"))
	if string(data) != "previous valid file" {
		t.Fatal(string(data))
	}
	if len(readCalls(t, callsPath)) != 2 {
		t.Fatal("unexpected lifecycle command")
	}
	candidates, err := filepath.Glob(p.file(".Caddyfile-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatal(candidates)
	}
	if err := os.WriteFile(p.config, []byte("bad JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := cli(t, "--home", filepath.Dir(p.config), "start"); code == 0 {
		t.Fatal("accepted bad source")
	}
	if len(readCalls(t, callsPath)) != 2 {
		t.Fatal("invoked Caddy for invalid source")
	}
	data = readTestFile(t, p.file("Caddyfile"))
	if string(data) != "previous valid file" {
		t.Fatal("invalid source replaced generated file")
	}
}

func TestDelegateFailures(t *testing.T) {
	for _, diagnostic := range []string{"bind: address already in use (HTTP)", "bind: address already in use (HTTPS)", "bind: permission denied"} {
		t.Run(diagnostic, func(t *testing.T) {
			p := initialized(t)
			callsPath := fakeCaddy(t)
			t.Setenv("FAKE_START_EXIT", "37")
			t.Setenv("FAKE_DIAGNOSTIC", diagnostic)
			for range 2 {
				code, out, errOut := cli(t, "--home", filepath.Dir(p.config), "start")
				if code != 37 || strings.Contains(out, "HTTPS:") || !strings.Contains(errOut, diagnostic) || !strings.Contains(errOut, p.file("caddy.log")) {
					t.Fatalf("%d %s %s", code, out, errOut)
				}
			}
			calls := readCalls(t, callsPath)
			if len(calls) != 6 {
				t.Fatal(calls)
			}
			for i, call := range calls {
				if call[0] != []string{"version", "validate", "start"}[i%3] {
					t.Fatal(calls)
				}
			}
		})
	}
}

func TestStopDelegate(t *testing.T) {
	p := initialized(t)
	callsPath := fakeCaddy(t)
	// Stop must ignore edited source, generated content, and a stale pidfile.
	for name, content := range map[string]string{p.config: "bad JSON", p.file("Caddyfile"): "bad Caddyfile", p.file("caddy.pid"): fmt.Sprint(os.Getpid())} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, status := range []string{"0", "19"} {
		t.Setenv("FAKE_STOP_EXIT", status)
		code, out, errOut := cli(t, "--home", filepath.Dir(p.config), "stop")
		if fmt.Sprint(code) != status || !strings.Contains(out, "stop output") || !strings.Contains(errOut, "stop diagnostic") {
			t.Fatalf("%d %s %s", code, out, errOut)
		}
	}
	calls := readCalls(t, callsPath)
	address, err := p.adminAddress()
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatal(calls)
	}
	for _, call := range calls {
		if !reflect.DeepEqual(call, []string{"stop", "--address", address}) {
			t.Fatal(call)
		}
	}
}

func TestMissingAndUnlaunchableCaddy(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprint(broken), func(t *testing.T) {
			p := initialized(t)
			bin := t.TempDir()
			t.Setenv("PATH", bin)
			if broken {
				if err := os.WriteFile(filepath.Join(bin, "caddy"), []byte("#!/missing/interpreter\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, command := range []string{"start", "stop"} {
				code, _, errOut := cli(t, "--home", filepath.Dir(p.config), command)
				if code == 0 || !strings.Contains(errOut, "install Caddy") {
					t.Fatalf("%d %s", code, errOut)
				}
			}
			if _, err := os.Stat(p.file("Caddyfile")); !os.IsNotExist(err) {
				t.Fatal("generated file despite missing Caddy")
			}
		})
	}
}

func TestLockSerializesCommands(t *testing.T) {
	p := initialized(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 2)
	go func() { done <- withLock(p, func() error { close(entered); <-release; return nil }) }()
	<-entered
	second := make(chan struct{})
	go func() { done <- withLock(p, func() error { close(second); return nil }) }()
	select {
	case <-second:
		t.Error("second command entered before first released lock")
	case <-time.After(40 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	<-second
}

func TestStartupSocketGuard(t *testing.T) {
	for _, state := range []string{"active", "missing", "stale", "inaccessible"} {
		t.Run(state, func(t *testing.T) {
			p := initialized(t)
			calls := fakeCaddy(t)
			if state != "missing" {
				listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p.file("admin.sock"), Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				if state == "stale" {
					listener.SetUnlinkOnClose(false)
					listener.Close()
				}
				if state == "inaccessible" {
					listener.Close()
					// A symlink loop gives a deterministic unexpected connection error,
					// including when the test is run by root.
					if err := os.Symlink("admin.sock", p.file("admin.sock")); err != nil {
						t.Fatal(err)
					}
				}
			}
			code, _, errOut := cli(t, "--home", filepath.Dir(p.config), "start")
			if state == "active" || state == "inaccessible" {
				if code == 0 {
					t.Fatal("guard allowed startup")
				}
				if state == "active" && !strings.Contains(errOut, "already running") {
					t.Fatal(errOut)
				}
				if state == "inaccessible" && !strings.Contains(errOut, "check private admin socket") {
					t.Fatal(errOut)
				}
				if _, err := os.Stat(calls); !os.IsNotExist(err) {
					t.Fatal("guard invoked Caddy")
				}
			} else if code != 0 {
				t.Fatal(errOut)
			}
		})
	}
}

func testPaths(t *testing.T, home string) paths {
	t.Helper()
	p, err := resolvePaths(home)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

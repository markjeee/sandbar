package main

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func observeFixture(t *testing.T) (paths, teleportDestination, string) {
	t.Helper()
	p := testPaths(t, shortHome(t))
	d := teleportDestination{Machine: "remote", Host: "localhost", User: "developer", Port: 22}
	socket, _, err := teleportRuntime(p, d)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareTeleportSSH(p, []teleportDestination{d}); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	calls := filepath.Join(bin, "calls")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$OBSERVE_CALLS\"\nprintf '%s' \"$OBSERVE_ERROR\" >&2\nexit \"${OBSERVE_EXIT:-0}\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("OBSERVE_CALLS", calls)
	t.Setenv("OBSERVE_ERROR", "")
	t.Setenv("OBSERVE_EXIT", "0")
	return p, d, calls
}

func TestTeleportControlPathsArePure(t *testing.T) {
	for _, installed := range []bool{false, true} {
		for _, long := range []bool{false, true} {
			p := paths{config: filepath.Join(t.TempDir(), "absent/config.json"), state: filepath.Join(t.TempDir(), "absent/state")}
			if long {
				p.state += strings.Repeat("long", 30)
			}
			if installed {
				p.installed = &installation{ID: "apt-systemd-v1"}
			}
			d := teleportDestination{Machine: "pure"}
			socket, log, err := teleportControlPaths(p, d)
			if err != nil || !strings.HasSuffix(log, "/teleport/"+teleportID(d.Machine)+"/ssh.log") || len(socket)+sshControlSocketSuffixLength > socketPathLimit {
				t.Fatalf("paths: %s %s %v", socket, log, err)
			}
			if installed && !strings.HasPrefix(log, p.workDir()+"/") {
				t.Fatal("Linux log escaped work directory")
			}
			if _, err := os.Stat(p.state); !os.IsNotExist(err) {
				t.Fatalf("path derivation created state: %v", err)
			}
		}
	}
}

func TestObserveTeleportMissingStateDoesNotPrepare(t *testing.T) {
	p := testPaths(t, shortHome(t))
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("PATH", t.TempDir())
	state, err := observeTeleport(p, teleportDestination{Machine: "missing"})
	if state != "disconnected" || err != nil {
		t.Fatalf("%s %v", state, err)
	}
	entries, err := os.ReadDir(filepath.Dir(p.config))
	if err != nil || len(entries) != 0 {
		t.Fatalf("observation wrote state: %v %v", entries, err)
	}
}

func TestObserveTeleportUsesOnlyControlCheck(t *testing.T) {
	p, d, calls := observeFixture(t)
	configPath := filepath.Join(filepath.Dir(p.config), "ssh/config")
	before := readTestFile(t, configPath)
	state, err := observeTeleport(p, d)
	if state != "connected" || err != nil {
		t.Fatalf("%s %v", state, err)
	}
	socket, _, err := teleportControlPaths(p, d)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(readTestFile(t, calls))), "\n")
	want := []string{"-F", configPath, "-S", socket, "-O", "check", teleportAlias(d)}
	if !reflect.DeepEqual(got, want) || string(readTestFile(t, configPath)) != string(before) {
		t.Fatalf("control check or source changed: %q", got)
	}
	for _, test := range []struct{ diagnostic, want string }{
		{"Control socket connect(test): Connection refused", "disconnected"},
		{"Control socket connect(test): No such file or directory", "disconnected"},
		{"Control socket connect(test): Permission denied", "unknown"},
		{"unclassified error", "unknown"},
	} {
		t.Setenv("OBSERVE_EXIT", "255")
		t.Setenv("OBSERVE_ERROR", test.diagnostic)
		state, err := observeTeleport(p, d)
		if state != test.want || (err != nil) != (test.want == "unknown") {
			t.Fatalf("%q: %s %v", test.diagnostic, state, err)
		}
	}
	t.Setenv("PATH", t.TempDir())
	if state, err := observeTeleport(p, d); state != "unknown" || err == nil {
		t.Fatalf("missing SSH: %s %v", state, err)
	}
}

func TestObserveTeleportRejectsPrivatePathChanges(t *testing.T) {
	for _, target := range []string{"socket", "socket directory", "config", "config directory"} {
		t.Run(target, func(t *testing.T) {
			p, d, calls := observeFixture(t)
			socket, _, err := teleportControlPaths(p, d)
			if err != nil {
				t.Fatal(err)
			}
			path := map[string]string{"socket": socket, "socket directory": filepath.Dir(socket), "config": filepath.Join(filepath.Dir(p.config), "ssh/config"), "config directory": filepath.Join(filepath.Dir(p.config), "ssh")}[target]
			mode := os.FileMode(0644)
			if strings.Contains(target, "directory") {
				mode = 0755
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			state, err := observeTeleport(p, d)
			if state != "unknown" || err == nil {
				t.Fatalf("%s %v", state, err)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("observer changed permissions: %v %v", info, err)
			}
			if _, err := os.Stat(calls); !os.IsNotExist(err) {
				t.Fatalf("observer invoked SSH with unsafe state: %v", err)
			}
		})
	}
}

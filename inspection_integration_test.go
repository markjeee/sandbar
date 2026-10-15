package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type inspectionFile struct {
	Mode   fs.FileMode
	Digest [sha256.Size]byte
}

// Normal Caddy requests can append logs. Preserve their entries and modes,
// while comparing bytes for the remaining files after certificate warmup.
func inspectionTree(t *testing.T, root string, logs ...string) map[string]inspectionFile {
	t.Helper()
	entries := make(map[string]inspectionFile)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := inspectionFile{Mode: info.Mode()}
		isLog := false
		for _, log := range logs {
			if path == log {
				isLog = true
			}
		}
		if info.Mode().IsRegular() && !isLog {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.Digest = sha256.Sum256(data)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func assertInspectionTree(t *testing.T, root string, before map[string]inspectionFile, logs ...string) {
	t.Helper()
	after := inspectionTree(t, root, logs...)
	if !reflect.DeepEqual(before, after) {
		for name, entry := range before {
			if value, exists := after[name]; !exists || value != entry {
				t.Errorf("inspection changed %s: before %+v, after %+v, exists %t", filepath.Join(root, name), entry, value, exists)
			}
		}
		for name := range after {
			if _, exists := before[name]; !exists {
				t.Errorf("inspection created %s", filepath.Join(root, name))
			}
		}
	}
}

// Real forwarding and destination TLS are independent of SSH authentication.
// This stub accepts only an exact control check for the test-owned socket.
func inspectionControlFixture(t *testing.T, p paths, d teleportDestination) string {
	t.Helper()
	socket, _, err := teleportControlPaths(p, d)
	if err != nil {
		t.Fatal(err)
	}
	controlDir := filepath.Dir(socket)
	if _, err := os.Lstat(controlDir); !os.IsNotExist(err) {
		t.Fatalf("control fixture directory already exists: %s: %v", controlDir, err)
	}
	if err := os.MkdirAll(controlDir, 0700); err != nil {
		t.Fatal(err)
	}
	// Long-path fallback can place this fresh home's socket outside its home.
	if relative, err := filepath.Rel(filepath.Dir(p.config), controlDir); err != nil || strings.HasPrefix(relative, "..") {
		t.Cleanup(func() {
			if err := os.RemoveAll(controlDir); err != nil {
				t.Error(err)
			}
		})
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	sshConfig, err := prepareTeleportSSH(p, []teleportDestination{d})
	if err != nil {
		t.Fatal(err)
	}
	binDir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
[ "$#" -eq 7 ] && [ "$1" = -F ] && [ "$2" = %s ] &&
[ "$3" = -S ] && [ "$4" = %s ] && [ "$5" = -O ] &&
[ "$6" = check ] && [ "$7" = %s ] && [ -S "$4" ] || exit 99
printf 'Master running (pid=%%s)\n' %d >&2
`, quoteRemoteArg(sshConfig), quoteRemoteArg(socket), quoteRemoteArg(teleportAlias(d)), os.Getpid())
	if err := os.WriteFile(filepath.Join(binDir, "ssh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_AUTH_SOCK", "")
	return socket
}

func TestIntegrationInspectionReadOnly(t *testing.T) {
	requireIntegration(t)
	bin := buildCLI(t)
	isolated := shortHome(t)
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(key, isolated)
	}
	t.Run("incomplete-home", func(t *testing.T) {
		parent := shortHome(t)
		home := filepath.Join(parent, "not-created")
		before := inspectionTree(t, parent)
		code, output := runBinary(t, bin, home, "config", "--path")
		if code != 0 || output != filepath.Join(home, "config.json")+"\n" {
			t.Fatalf("config --path: %d %q", code, output)
		}
		for _, args := range [][]string{{"config", "--print"}, {"status"}, {"doctor"}} {
			if code, output := runBinary(t, bin, home, args...); code == 0 {
				t.Fatalf("incomplete-home %v unexpectedly passed: %s", args, output)
			}
		}
		assertInspectionTree(t, parent, before)
	})

	t.Run("running-home", func(t *testing.T) {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("inspection backend\n"))
		}))
		defer backend.Close()
		remote, remoteConfig := teleportTestRouter(t, bin, "remote", nil)
		forwardPort, _ := teleportTestForward(t, remoteConfig.HTTPSPort)
		local, localConfig := teleportTestRouter(t, bin, "local", []route{{Hostname: "inspect.sandbar.localhost", Upstream: backend.URL}})
		connected := teleportDestination{
			Machine: "remote", Host: "127.0.0.1", User: "developer", Port: 22,
			HTTPSPort: remoteConfig.HTTPSPort, LocalPort: forwardPort,
			RootPEM: string(readTestFile(t, remote.rootCertificate())),
		}
		disconnected := connected
		disconnected.Machine = "disconnected"
		disconnected.LocalPort, _ = freePorts(t)
		localConfig.Teleports = []teleportDestination{connected, disconnected}
		if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
			t.Fatal(err)
		}
		socket := inspectionControlFixture(t, local, connected)
		socketBefore, err := os.Lstat(socket)
		if err != nil {
			t.Fatal(err)
		}
		client := routerClient(t, local, "127.0.0.1")
		for _, site := range localConfig.localSites(false) {
			waitForTLS(t, client, localConfig.routeURL(site.Hostname))
		}
		if err := probeTeleportWelcome(connected); err != nil {
			t.Fatal(err)
		}
		// Preserve valid source whitespace exactly, without changing its meaning.
		source := append([]byte("\n "), readTestFile(t, local.config)...)
		source = append(source, '\n')
		if err := os.WriteFile(local.config, source, 0600); err != nil {
			t.Fatal(err)
		}
		localHome, remoteHome := filepath.Dir(local.config), filepath.Dir(remote.config)
		localBefore := inspectionTree(t, localHome, local.file("caddy.log"))
		remoteBefore := inspectionTree(t, remoteHome, remote.file("caddy.log"))
		controlBefore := inspectionTree(t, filepath.Dir(socket))
		isolatedBefore := inspectionTree(t, isolated)
		localPID := strings.TrimSpace(string(readTestFile(t, local.file("caddy.pid"))))
		remotePID := strings.TrimSpace(string(readTestFile(t, remote.file("caddy.pid"))))
		checkProcessEvidence(t, localPID)
		checkProcessEvidence(t, remotePID)

		code, output := runBinary(t, bin, localHome, "config", "--path")
		if code != 0 || output != local.config+"\n" {
			t.Fatalf("config --path: %d %q", code, output)
		}
		code, output = runBinary(t, bin, localHome, "config", "--print")
		if code != 0 || !bytes.Equal([]byte(output), source) {
			t.Fatalf("config --print changed source bytes: %d %q", code, output)
		}
		code, output = runBinary(t, bin, localHome, "status")
		if code != 0 {
			t.Fatalf("status: %d %s", code, output)
		}
		for _, want := range []string{
			"Router: running",
			"Teleport: remote " + localConfig.routeURL(machineHostname("remote")) + " connected",
			"Teleport: disconnected " + localConfig.routeURL(machineHostname("disconnected")) + " disconnected",
			selectedCommand(local, "teleport", "connect", "disconnected"),
		} {
			if !strings.Contains(output, want) {
				t.Fatalf("status missing %q: %s", want, output)
			}
		}
		code, output = runBinary(t, bin, localHome, "doctor")
		if code == 0 {
			t.Fatalf("doctor accepted private root in system trust: %s", output)
		}
		// Doctor assertions below distinguish direct TLS, system trust, and
		// Teleport transport. They do not depend on native localhost resolution.
		assertInspectionDoctor(t, output, local)

		assertInspectionTree(t, localHome, localBefore, local.file("caddy.log"))
		assertInspectionTree(t, remoteHome, remoteBefore, remote.file("caddy.log"))
		assertInspectionTree(t, filepath.Dir(socket), controlBefore)
		assertInspectionTree(t, isolated, isolatedBefore)
		socketAfter, err := os.Lstat(socket)
		if err != nil || !os.SameFile(socketBefore, socketAfter) {
			t.Fatalf("inspection replaced or removed control socket: %v", err)
		}
		checkProcessEvidence(t, localPID)
		checkProcessEvidence(t, remotePID)
		checkListenerEvidence(t, localConfig, localPID)
		checkListenerEvidence(t, remoteConfig, remotePID)
		if err := probeTeleportWelcome(connected); err != nil {
			t.Fatalf("inspection changed forwarding: %v", err)
		}
		t.Log("real Caddy processes, files, modes, listeners, and TCP forwarding unchanged; SSH control observation uses a strict stub")
	})
}

func assertInspectionDoctor(t *testing.T, output string, p paths) {
	t.Helper()
	for _, want := range []string{
		"pass: source: valid",
		"pass: private admin: active configuration is readable",
		"pass: source comparison: source matches generated configuration",
		"pass: active comparison: generated configuration matches active configuration",
		"pass: selected CA: " + p.rootCertificate() + "; SHA-256 ",
		"pass: inspect.sandbar.localhost IPv4 selected CA: HTTP 200; reachable",
		"failure: inspect.sandbar.localhost system verifier:",
		"pass: Teleport remote SSH control: connected for the current user",
		"pass: Teleport remote forwarded HTTPS: machine welcome verified with saved destination CA",
		"warning: Teleport disconnected: disconnected; run " + selectedCommand(p, "teleport", "connect", "disconnected"),
		"not applicable: Teleport disconnected forwarded HTTPS: destination is disconnected",
		"unknown: browser:",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("doctor missing %q: %s", want, output)
		}
	}
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "failure:") && !strings.Contains(line, " system verifier:") && !strings.Contains(line, " system resolution:") {
			t.Fatalf("unexpected doctor failure: %s\n%s", line, output)
		}
	}
}

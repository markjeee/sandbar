package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type uninstallDarwinService struct {
	fakeService
	installation *installation
}

func (s *uninstallDarwinService) Control(action string, out, errOut io.Writer) error {
	s.Actions = append(s.Actions, action)
	if s.ControlErr != nil {
		return s.ControlErr
	}
	if action != "stop" {
		return fmt.Errorf("unexpected control: %s", action)
	}
	s.State = serviceState{State: "inactive", Boot: "disabled", Sockets: "released"}
	return os.Remove(s.installation.Fragment)
}
func uninstallDarwinFixture(t *testing.T) (paths, *uninstallDarwinService, string) {
	t.Helper()
	p, _ := testInstalledPaths(t)
	calls := fakeCaddy(t)
	i := p.installed
	i.State = filepath.Join(filepath.Dir(i.Source), "state")
	i.Globals = filepath.Join(i.State, "global.Caddyfile")
	p = installedPaths(i)
	i.ID = sandbarLaunchdID
	i.Unit = sandbarLaunchdLabel
	i.Binary = filepath.Join(filepath.Dir(calls), "caddy")
	i.CLI = filepath.Join(shortHome(t), "custom/sandbar")
	i.Fragment = filepath.Join(shortHome(t), "local.sandbar.caddy.plist")
	i.Log = filepath.Join(shortHome(t), "shared-caddy.log")
	writeUninstallFixture(t, i.CLI, []byte("retained CLI fixture"), 0755)
	writeUninstallFixture(t, i.Log, []byte("shared log fixture"), 0600)
	cfg := config{Version: 3, Machine: "fixture", HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}}
	source, err := configBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, p.config, source, 0600)
	address, err := p.adminAddress()
	if err != nil {
		t.Fatal(err)
	}
	globals := []byte(renderInstalledGlobals(cfg, address, "", ""))
	routes, err := renderInstalledRoutes(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, i.Config, []byte("# shared configuration retained\n{}\n# tail retained\n"), 0600)
	composition, err := composeInstalledConfig(i.Config, readTestFile(t, i.Config), i.Globals, p.generatedPath(), globals, []byte(routes), false)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, i.Config, composition.Top, 0600)
	writeUninstallFixture(t, i.Globals, globals, 0600)
	writeUninstallFixture(t, p.generatedPath(), []byte(routes), 0600)
	_, manifest, err := stageInstalledCandidate(i.Config, i.Globals, p.generatedPath(), []byte(routes))
	if err != nil {
		t.Fatal(err)
	}
	socketPlan := &socketPlan{HTTPPort: cfg.HTTPPort, HTTPSPort: cfg.HTTPSPort}
	record, err := json.Marshal(setupRecord{Identity: i.identity(), Manifest: manifest, SocketPlan: socketPlan})
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, p.file("setup.json"), record, 0600)
	template, err := renderLaunchdJob(i, *socketPlan)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, launchdTemplate(i), template, 0600)
	writeUninstallFixture(t, i.Fragment, template, 0600)
	writeUninstallFixture(t, p.file("router.lock"), nil, 0600)
	privateRoot := storedRoot(t, paths{state: shortHome(t)})
	writeUninstallFixture(t, p.rootCertificate(), readTestFile(t, privateRoot), 0600)
	writeUninstallFixture(t, filepath.Join(filepath.Dir(p.rootCertificate()), "root.key"), []byte("test private key placeholder"), 0600)
	writeUninstallFixture(t, filepath.Join(i.Storage, "pki/authorities/other/root.crt"), []byte("unrelated authority fixture"), 0600)
	for _, ext := range []string{"crt", "key", "json"} {
		writeUninstallFixture(t, filepath.Join(i.Storage, "certificates/sandbar/obsolete.localhost/obsolete.localhost."+ext), []byte("obsolete selected leaf fixture"), 0600)
	}
	writeUninstallFixture(t, filepath.Join(i.Storage, "certificates/other/keep/keep.crt"), []byte("unrelated leaf fixture"), 0600)
	backup, err := json.Marshal(setupUndo{Dir: p.file("backups/setup-fixture"), Files: []setupBackup{{Path: p.rootCertificate(), Data: []byte("test backup private key placeholder")}}})
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, p.file("backups/setup-fixture/backup.json"), backup, 0600)
	service := &uninstallDarwinService{installation: i, fakeService: fakeService{State: serviceState{State: "active", Boot: "enabled", Sockets: "owned by launchd"}}}
	i.Service = service
	oldSocket := uninstallSocketOutput
	uninstallSocketOutput = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() { uninstallSocketOutput = oldSocket })
	return p, service, calls
}
func writeUninstallFixture(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}
func uninstallEvidence(t *testing.T, p paths) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	for _, path := range []string{p.config, p.file("setup.json"), p.generatedPath(), p.installed.Config, p.installed.Globals, p.installed.Fragment, p.rootCertificate(), filepath.Join(filepath.Dir(p.rootCertificate()), "root.key"), p.file("backups/setup-fixture/backup.json"), p.installed.CLI, p.installed.Log} {
		result[path] = readTestFile(t, path)
	}
	return result
}
func assertUninstallEvidence(t *testing.T, evidence map[string][]byte) {
	t.Helper()
	for path, before := range evidence {
		if !bytes.Equal(before, readTestFile(t, path)) {
			t.Fatalf("changed retained evidence: %s", path)
		}
	}
}
func TestDarwinUninstallPreviewAndSuccessfulCleanup(t *testing.T) {
	p, service, calls := uninstallDarwinFixture(t)
	evidence := uninstallEvidence(t, p)
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var preview bytes.Buffer
	printUninstallPlan(plan, &preview)
	if !strings.Contains(preview.String(), "Keep executable:") || !strings.Contains(preview.String(), plan.Fingerprint) {
		t.Fatal(preview.String())
	}
	assertUninstallEvidence(t, evidence)
	if len(service.Actions) != 0 {
		t.Fatal(service.Actions)
	}
	if err := runUninstallUser(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(service.Actions) != "[stop]" {
		t.Fatal(service.Actions)
	}
	for _, path := range []string{p.config, p.state, p.installed.Globals, p.installed.Fragment, filepath.Join(p.installed.Storage, "pki/authorities/sandbar"), filepath.Join(p.installed.Storage, "certificates/sandbar")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retained owned target %s: %v", path, err)
		}
	}
	for _, path := range []string{p.installed.CLI, p.installed.Log} {
		if !bytes.Equal(evidence[path], readTestFile(t, path)) {
			t.Fatalf("changed %s", path)
		}
	}
	if got := string(readTestFile(t, p.installed.Config)); got != string(plan.Stripped) {
		t.Fatal(got)
	}
	if got := string(readTestFile(t, filepath.Join(p.installed.Storage, "pki/authorities/other/root.crt"))); got != "unrelated authority fixture" {
		t.Fatal(got)
	}
	if got := string(readTestFile(t, filepath.Join(p.installed.Storage, "certificates/other/keep/keep.crt"))); got != "unrelated leaf fixture" {
		t.Fatal(got)
	}
	seenUntrust := false
	for _, call := range readCalls(t, calls) {
		if call[0] == "untrust" {
			seenUntrust = true
			if len(call) != 3 || call[1] != "--cert" || call[2] != p.rootCertificate() {
				t.Fatal(call)
			}
		} else if call[0] != "version" && call[0] != "adapt" {
			t.Fatal(call)
		}
	}
	if !seenUntrust {
		t.Fatal("missing exact-root untrust")
	}
}
func TestDarwinUninstallPreservesOnFailures(t *testing.T) {
	for _, failure := range []string{"untrust", "shutdown", "backup edit", "root copy mismatch", "missing root", "unreadable root", "unknown file", "changed marker", "generated edit", "source edit"} {
		t.Run(failure, func(t *testing.T) {
			p, service, _ := uninstallDarwinFixture(t)
			plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "untrust":
				t.Setenv("FAKE_TRUST_EXIT", "29")
			case "shutdown":
				service.ControlErr = errors.New("fixture shutdown failure")
			case "backup edit":
				writeUninstallFixture(t, p.file("backups/setup-fixture/backup.json"), []byte("external backup edit"), 0600)
			case "source edit":
				writeUninstallFixture(t, p.config, append(readTestFile(t, p.config), '\n'), 0600)
			case "root copy mismatch":
				root := storedRoot(t, paths{state: shortHome(t)})
				writeUninstallFixture(t, p.file("root.crt"), readTestFile(t, root), 0600)
			case "unreadable root":
				rootBefore := readTestFile(t, p.rootCertificate())
				keyPath := filepath.Join(filepath.Dir(p.rootCertificate()), "root.key")
				keyBefore := readTestFile(t, keyPath)
				backupBefore := readTestFile(t, p.file("backups/setup-fixture/backup.json"))
				if err := os.Chmod(p.rootCertificate(), 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p.rootCertificate(), 0600) })
				if _, err := buildUninstallPlan(p, os.Getuid(), io.Discard); err == nil {
					t.Fatal("accepted unreadable root")
				}
				if len(service.Actions) != 0 {
					t.Fatal(service.Actions)
				}
				if err := os.Chmod(p.rootCertificate(), 0600); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(rootBefore, readTestFile(t, p.rootCertificate())) || !bytes.Equal(keyBefore, readTestFile(t, keyPath)) || !bytes.Equal(backupBefore, readTestFile(t, p.file("backups/setup-fixture/backup.json"))) {
					t.Fatal("changed unreadable certificate evidence")
				}
				return
			case "missing root":
				if err := os.Remove(p.rootCertificate()); err != nil {
					t.Fatal(err)
				}
			case "unknown file":
				writeUninstallFixture(t, p.file("keep-user-data"), []byte("keep"), 0600)
			case "changed marker":
				writeUninstallFixture(t, p.installed.Config, bytes.Replace(plan.Top, []byte("# END SANDBAR ROUTES"), []byte("# CHANGED SANDBAR ROUTES"), 1), 0600)
			case "generated edit":
				writeUninstallFixture(t, p.generatedPath(), append(readTestFile(t, p.generatedPath()), []byte("# external edit\n")...), 0600)
			}
			if failure == "root copy mismatch" || failure == "missing root" || failure == "unknown file" || failure == "changed marker" || failure == "generated edit" {
				if _, err := buildUninstallPlan(p, os.Getuid(), io.Discard); err == nil {
					t.Fatal("accepted conflict")
				}
				if len(service.Actions) != 0 {
					t.Fatal(service.Actions)
				}
				return
			}
			evidence := uninstallEvidence(t, p)
			if failure == "untrust" {
				if err := runUninstallUser(plan, io.Discard, io.Discard); err == nil {
					t.Fatal("accepted failed untrust")
				}
			} else {
				if err := finishUninstall(plan, io.Discard, io.Discard); err == nil {
					t.Fatal("accepted cleanup failure")
				}
			}
			assertUninstallEvidence(t, evidence)
			if failure != "shutdown" && len(service.Actions) != 0 {
				t.Fatal(service.Actions)
			}
		})
	}
}
func TestDarwinUninstallRepeatAndPartialRemnants(t *testing.T) {
	p, _, _ := uninstallDarwinFixture(t)
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	old := launchdOutput
	launchdOutput = func(binary string, args ...string) ([]byte, error) {
		err := exec.Command("/bin/sh", "-c", "exit 113").Run()
		return nil, fmt.Errorf("Could not find service \"%s\" in domain for user gui: %w", sandbarLaunchdLabel, err)
	}
	t.Cleanup(func() { launchdOutput = old })
	repeated, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil || !repeated.AlreadyRemoved {
		t.Fatal(repeated, err)
	}
	if _, err := os.Stat(p.file("router.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repeat created lock", err)
	}
	writeUninstallFixture(t, p.installed.Config, []byte(routesMarkerStart+"import \"/missing\"\n"+routesMarkerEnd), 0600)
	if _, err := buildUninstallPlan(p, os.Getuid(), io.Discard); err == nil {
		t.Fatal("accepted orphan markers")
	}
	writeUninstallFixture(t, p.installed.Config, []byte("{}\n"), 0600)
	writeUninstallFixture(t, p.installed.Fragment, []byte("orphan job"), 0600)
	if _, err := buildUninstallPlan(p, os.Getuid(), io.Discard); err == nil {
		t.Fatal("accepted orphan login job")
	}
}
func TestDarwinUninstallObservesStandardPortsWithoutBinding(t *testing.T) {
	old := uninstallSocketOutput
	var calls [][]string
	uninstallSocketOutput = func(binary string, args ...string) ([]byte, error) { calls = append(calls, args); return nil, nil }
	t.Cleanup(func() { uninstallSocketOutput = old })
	if err := checkUninstallSocketsReleased(socketPlan{HTTPPort: 80, HTTPSPort: 443}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.Contains(strings.Join(calls[0], " "), "TCP:80") || !strings.Contains(strings.Join(calls[1], " "), "UDP:443") {
		t.Fatal(calls)
	}
	uninstallSocketOutput = func(string, ...string) ([]byte, error) { return []byte("p123\nccaddy\nn127.0.0.1:443\n"), nil }
	if err := checkUninstallSocketsReleased(socketPlan{HTTPPort: 80, HTTPSPort: 443}); err == nil {
		t.Fatal("accepted listener after stop")
	}
}

func TestDarwinUninstallDisconnectAndStaleSocketPreservation(t *testing.T) {
	p, service, _ := uninstallDarwinFixture(t)
	cfg, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	d := teleportDestination{Machine: "peer", Host: "localhost", User: "developer", Port: 22, HTTPSPort: 443, LocalPort: 19000, RootPEM: string(readTestFile(t, p.rootCertificate()))}
	cfg.Teleports = []teleportDestination{d}
	source, err := configBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, p.config, source, 0600)
	routes, err := renderInstalledRoutes(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, p.generatedPath(), []byte(routes), 0600)
	record, err := readSetupRecord(p)
	if err != nil {
		t.Fatal(err)
	}
	_, record.Manifest, err = stageInstalledCandidate(p.installed.Config, p.installed.Globals, p.generatedPath(), []byte(routes))
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	writeUninstallFixture(t, p.file("setup.json"), recordBytes, 0600)
	if _, err := prepareTeleportSSH(p, cfg.Teleports); err != nil {
		t.Fatal(err)
	}
	socket, _, err := teleportRuntime(p, d)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if err := os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	fixture := shortHome(t)
	master := filepath.Join(fixture, "master")
	writeUninstallFixture(t, master, []byte("active"), 0600)
	script := `#!/bin/sh
operation=
while [ "$#" -gt 0 ]; do
 case "$1" in -O) operation=$2; shift ;; esac
 shift
done
case "$operation" in
 check) if [ -f "$UNINSTALL_MASTER" ]; then exit 0; fi
        printf '%s\n' 'Control socket connect(fixture): Connection refused' >&2
        exit 255 ;;
 exit) /bin/rm "$UNINSTALL_MASTER"; exit 0 ;;
 *) exit 99 ;;
esac
`
	writeUninstallFixture(t, filepath.Join(fixture, "ssh"), []byte(script), 0700)
	t.Setenv("UNINSTALL_MASTER", master)
	t.Setenv("PATH", fixture+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", "/caller-trust-home")
	t.Setenv("XDG_CONFIG_HOME", "/caller-trust-config")
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	evidence := uninstallEvidence(t, p)
	t.Setenv("FAKE_TRUST_EXIT", "29")
	var result bytes.Buffer
	if err := runUninstallUser(plan, &result, io.Discard); err == nil {
		t.Fatal("accepted untrust failure")
	}
	if !strings.Contains(result.String(), "Disconnected Teleport: peer") {
		t.Fatal(result.String())
	}
	assertUninstallEvidence(t, evidence)
	if _, err := os.Lstat(socket); err != nil {
		t.Fatal("removed socket before untrust success", err)
	}
	if _, err := os.Stat(master); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("connected master remained", err)
	}
	if len(service.Actions) != 0 {
		t.Fatal(service.Actions)
	}
	t.Setenv("FAKE_TRUST_EXIT", "")
	if err := runUninstallUser(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned stale socket remained", err)
	}
	if !strings.HasPrefix(string(readTestFile(t, os.Getenv("FAKE_ENV"))), "/caller-trust-home\n/caller-trust-config\n") {
		t.Fatal("untrust lost caller environment")
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinUninstallPreservesSafeCaddyfileEdits(t *testing.T) {
	p, _, _ := uninstallDarwinFixture(t)
	later := append([]byte("# added after setup\n"), readTestFile(t, p.installed.Config)...)
	writeUninstallFixture(t, p.installed.Config, later, 0600)
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := runUninstallUser(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(readTestFile(t, p.installed.Config), []byte("# added after setup\n")) {
		t.Fatal("lost external edit")
	}
}

func TestDarwinUninstallSocketInspectionDistinguishesNoMatch(t *testing.T) {
	if _, err := uninstallSocketCommand("/bin/sh", "-c", "exit 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := uninstallSocketCommand("/bin/sh", "-c", "printf 'inspection denied' >&2; exit 1"); err == nil {
		t.Fatal("accepted failed inspection as no listeners")
	}
}

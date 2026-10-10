package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeService struct {
	State                               serviceState
	InspectErr, ControlErr, ValidateErr error
	Actions                             []string
}

func (f *fakeService) Inspect() (serviceState, error) { return f.State, f.InspectErr }
func (f *fakeService) Control(action string, _, _ io.Writer) error {
	f.Actions = append(f.Actions, action)
	return f.ControlErr
}
func (f *fakeService) Validate(_, _ io.Writer) error { return f.ValidateErr }

func testInstalledPaths(t *testing.T) (paths, *fakeService) {
	t.Helper()
	root := shortHome(t)
	service := &fakeService{State: serviceState{State: "inactive", Boot: "enabled"}}
	i := &installation{ID: "fixture-v1", Binary: "/usr/bin/caddy", Unit: "fixture.service", Config: filepath.Join(root, "service/Caddyfile"), Globals: filepath.Join(root, "service/global.Caddyfile"), Source: filepath.Join(root, "source/config.json"), State: filepath.Join(root, "state"), Storage: filepath.Join(root, "storage"), Account: "fixture", UID: os.Getuid(), GID: os.Getgid(), GroupID: os.Getgid(), Service: service}
	p := installedPaths(i)
	for _, path := range []string{filepath.Dir(p.config), filepath.Dir(i.Config), p.state, p.workDir(), p.file("routes"), p.file("admin"), p.file("validation")} {
		if err := os.MkdirAll(path, 0770); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config{Version: 2, HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}}
	source, err := configBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.writeFile(p.config, source); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(setupRecord{Identity: i.identity(), Manifest: inputManifest{}})
	if err := os.WriteFile(p.file("setup.json"), data, 0640); err != nil {
		t.Fatal(err)
	}
	return p, service
}

func TestServiceCommandIdentity(t *testing.T) {
	wrap := func(args string) string {
		return "{ path=/usr/bin/caddy ; argv[]=" + args + " ; ignore_errors=no ; pid=0 ; }"
	}
	start := "/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile"
	reload := "/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force"
	for _, suffix := range []string{"", " --address unix//var/lib/sandbar/admin/admin.sock"} {
		if err := checkServiceCommands(map[string]string{"ExecStart": wrap(start), "ExecReload": wrap(reload + suffix)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, fields := range []map[string]string{
		{"ExecStart": wrap(start + " --resume"), "ExecReload": wrap(reload)},
		{"ExecStart": wrap(start), "ExecReload": wrap(reload + " --address localhost:2019")},
		{"ExecStart": wrap(start) + wrap(start), "ExecReload": wrap(reload)},
		{"ExecStart": strings.Replace(wrap(start), "path=/usr/bin/caddy", "path=/tmp/caddy", 1), "ExecReload": wrap(reload)},
	} {
		if err := checkServiceCommands(fields); err == nil {
			t.Fatal("accepted incompatible service", fields)
		}
	}
	for _, bad := range []string{"ActiveState", "=active", "ActiveState=active\nActiveState=inactive"} {
		if _, err := parseProperties([]byte(bad)); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

func TestInstalledStopIgnoresInvalidSourceAndRecovery(t *testing.T) {
	p, service := testInstalledPaths(t)
	if err := os.WriteFile(p.config, []byte("bad"), 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.file("transaction"), 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("transaction/journal.json"), []byte("bad"), 0660); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := withLock(p, func() error { return stop(p, &out, io.Discard) }); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(service.Actions) != "[stop]" || !strings.Contains(out.String(), "all routes") {
		t.Fatal(service.Actions, out.String())
	}
}

func TestInstalledRecoveryStateAndMetadata(t *testing.T) {
	for _, state := range []string{"inactive", "active", "failed", "inaccessible", "identity", "metadata", "manual edit"} {
		t.Run(state, func(t *testing.T) {
			p, service := testInstalledPaths(t)
			previous := readTestFile(t, p.config)
			tx := transaction{Version: 1, Phase: "prepared", Reload: true, PreviousSource: previous, CandidateSource: append(append([]byte{}, previous...), '\n'), PreviousGenerated: []byte("old"), CandidateGenerated: []byte("new"), PreviousActive: []byte(`{"old":true}`), CandidateActive: []byte(`{"new":true}`)}
			if err := p.writeFile(p.generatedPath(), tx.PreviousGenerated); err != nil {
				t.Fatal(err)
			}
			if err := prepareTransaction(p, &tx); err != nil {
				t.Fatal(err)
			}
			if err := saveTransaction(p, tx); err != nil {
				t.Fatal(err)
			}
			tx.Phase = "loading"
			if err := saveTransaction(p, tx); err != nil {
				t.Fatal(err)
			}
			if err := publishGenerated(p, tx.CandidateGenerated); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "active":
				service.State.State = "active"
				transactionAdmin(t, p, string(tx.CandidateActive))
			case "failed":
				service.State.State = "failed"
			case "inaccessible":
				service.InspectErr = errors.New("denied")
			case "identity":
				p.installed.ID = "changed"
			case "metadata":
				if err := os.Chmod(p.generatedPath(), 0600); err != nil {
					t.Fatal(err)
				}
			case "manual edit":
				if err := os.WriteFile(p.generatedPath(), []byte("manual"), 0660); err != nil {
					t.Fatal(err)
				}
			}
			err := recoverTransaction(p, io.Discard)
			if state != "inactive" && state != "active" {
				if err == nil {
					t.Fatal("discarded uncertain recovery")
				}
				if _, err := os.Stat(p.file("transaction/journal.json")); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := tx.PreviousGenerated
			if state == "active" {
				want = tx.CandidateGenerated
			}
			if !bytes.Equal(want, readTestFile(t, p.generatedPath())) {
				t.Fatal("wrong recovery choice")
			}
			meta, err := readFileMetadata(p.generatedPath())
			if err != nil {
				t.Fatal(err)
			}
			if meta.Mode != 0660 || meta.GID != os.Getgid() || meta.UID != os.Getuid() {
				t.Fatal(meta)
			}
		})
	}
}

func TestInstalledFailedServiceWithActiveAdmin(t *testing.T) {
	p, service := testInstalledPaths(t)
	service.State.State = "failed"
	transactionAdmin(t, p, `{"still":"active"}`)
	data, err := selectedActiveConfig(p)
	if err != nil || !bytes.Equal(data, []byte(`{"still":"active"}`)) {
		t.Fatal(string(data), err)
	}
}

func TestSetupBackupConflictingEdit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte("old"), 0640); err != nil {
		t.Fatal(err)
	}
	undo := setupUndo{Dir: dir}
	if err := undo.write(path, []byte("new"), 0640, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("manual"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := undo.restore(); err == nil || !strings.Contains(err.Error(), "external edit preserved") {
		t.Fatal(err)
	}
	if string(readTestFile(t, path)) != "manual" {
		t.Fatal("overwrote edit")
	}
}

func TestSetgidSharedDirectories(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := setupDirectory(dir, 0770|os.ModeSetgid, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Fatal("shared directory lacks setgid")
	}
	path := filepath.Join(dir, "file")
	if err := atomicWriteMode(path, []byte("data"), 0660, -1, -1); err != nil {
		t.Fatal(err)
	}
	meta, err := readFileMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Mode != 0660 || meta.GID != os.Getgid() {
		t.Fatal(meta)
	}
}

func TestInstalledStatusReportsServiceBeforeInvalidSource(t *testing.T) {
	p, service := testInstalledPaths(t)
	service.State = serviceState{State: "active", Boot: "disabled"}
	if err := os.WriteFile(p.config, []byte("invalid"), 0660); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := status(p, &out, io.Discard); err == nil {
		t.Fatal("invalid source reported success")
	}
	for _, text := range []string{"Service: active", "Boot startup: disabled", "Router: inaccessible", "Recovery: none", "Configuration: invalid"} {
		if !strings.Contains(out.String(), text) {
			t.Fatal(out.String())
		}
	}
	if len(service.Actions) != 0 {
		t.Fatal("status changed service", service.Actions)
	}
}

func TestInstalledTrustSelectsCAAndCallerEnvironment(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		t.Run(command, func(t *testing.T) {
			p, _ := testInstalledPaths(t)
			callsPath := fakeCaddy(t)
			p.installed.Binary = filepath.Join(filepath.Dir(callsPath), "caddy")
			for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
				t.Setenv(key, "/caller/"+key)
			}
			if err := os.WriteFile(p.rootCertificate(), []byte("stored public root"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.config, []byte("invalid"), 0660); err != nil {
				t.Fatal(err)
			}
			if err := changeTrust(p, command, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			calls := readCalls(t, callsPath)
			want := []string{"untrust", "--cert", p.rootCertificate()}
			if command == "trust" {
				address, _ := p.adminAddress()
				want = []string{"trust", "--ca", "sandbar", "--address", address}
			}
			if fmt.Sprint(calls) != fmt.Sprint([][]string{{"version"}, want}) {
				t.Fatal(calls)
			}
			env := string(readTestFile(t, os.Getenv("FAKE_ENV")))
			if !strings.Contains(env, "/caller/HOME\n") || strings.Contains(env, p.state) {
				t.Fatal(env)
			}
		})
	}
}

func TestSetupArgumentsFailBeforeSystemInspection(t *testing.T) {
	for _, args := range [][]string{{"setup"}, {"setup", "--user", "root"}, {"setup", "--user", "this-account-does-not-exist-sandbar"}, {"--home", "/tmp/must-not-create-sandbar", "setup", "--user", "root"}} {
		code, _, errOut := cli(t, args...)
		if code == 0 || strings.Contains(errOut, "Caddy package") {
			t.Fatal(args, code, errOut)
		}
	}
}

func TestSetupCertificateReadiness(t *testing.T) {
	internal := &routeTLSError{&net.OpError{Op: "remote error", Err: errors.New("tls: internal error")}}
	attempts := 0
	code, err := waitForSetupCertificate(func() (int, error) {
		attempts++
		if attempts == 1 {
			return 0, internal
		}
		return 200, nil
	}, time.Second)
	if err != nil || code != 200 || attempts != 2 {
		t.Fatal(code, err, attempts)
	}
	attempts = 0
	_, err = waitForSetupCertificate(func() (int, error) { attempts++; return 0, internal }, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "not ready") || attempts != 1 {
		t.Fatal(err, attempts)
	}
	for _, permanent := range []error{errors.New("connection refused"), &routeTLSError{errors.New("unknown authority")}, &routeTLSError{&net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}}} {
		attempts = 0
		_, err := waitForSetupCertificate(func() (int, error) { attempts++; return 0, permanent }, time.Second)
		if !errors.Is(err, permanent) || attempts != 1 {
			t.Fatal(err, attempts)
		}
	}
	attempts = 0
	code, err = waitForSetupCertificate(func() (int, error) { attempts++; return 503, nil }, time.Second)
	if code != 503 || err != nil || attempts != 1 {
		t.Fatal(code, err, attempts)
	}
}

func TestSetupInputSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	snapshots := []setupSnapshot{{Path: path}}
	if err := checkSetupSnapshots(snapshots); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("manual"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkSetupSnapshots(snapshots); err == nil {
		t.Fatal("accepted source created during setup")
	}
	snapshots[0].Data = []byte("manual")
	if err := checkSetupSnapshots(snapshots); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "other"), path); err != nil {
		t.Fatal(err)
	}
	if err := checkSetupSnapshots(snapshots); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestSetupDirectoryRollbackPreservesModes(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "owned")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	undo := setupUndo{Dir: root}
	if err := undo.directory(dir, 0770|os.ModeSetgid, os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	if err := undo.restore(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fileAccessMode(info.Mode()) != 0700 {
		t.Fatal(info.Mode())
	}
}

func TestInstalledInitCreatesSharedSource(t *testing.T) {
	p, _ := testInstalledPaths(t)
	if err := os.Remove(p.config); err != nil {
		t.Fatal(err)
	}
	if err := initialize(p, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	meta, err := readFileMetadata(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Mode != 0660 || meta.GID != p.installed.GroupID {
		t.Fatal(meta)
	}
	if err := initialize(p, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(p.config)
	if err != nil || len(cfg.Routes) != 0 || cfg.HTTPPort != 80 || cfg.HTTPSPort != 443 {
		t.Fatal(cfg, err)
	}
	before := readTestFile(t, p.config)
	if err := createSelectedConfig(p, cfg); err == nil {
		t.Fatal("replaced an existing source")
	}
	if !bytes.Equal(before, readTestFile(t, p.config)) {
		t.Fatal("changed source")
	}
}

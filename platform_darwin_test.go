package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func homebrewMetadata(prefix string) []byte {
	metadata := map[string]any{"formulae": []any{map[string]any{"name": "caddy", "installed": []any{map[string]any{"version": "2.11.7"}}, "service": map[string]any{"run": []string{prefix + "/opt/caddy/bin/caddy", "run", "--config", prefix + "/etc/Caddyfile"}, "environment_variables": map[string]string{"HOME": prefix + "/var/lib", "XDG_DATA_HOME": prefix + "/var/lib"}, "log_path": prefix + "/var/log/caddy.log", "error_log_path": prefix + "/var/log/caddy.log"}}}}
	data, _ := json.Marshal(metadata)
	return data
}
func TestHomebrewInstallationMetadata(t *testing.T) {
	account := &user.User{Uid: "501", Gid: "20", Username: "developer", HomeDir: "/Users/developer"}
	data := homebrewMetadata("/custom brew")
	i, err := homebrewInstallation("/custom brew", data, account)
	if err != nil {
		t.Fatal(err)
	}
	if i.Binary != "/custom brew/opt/caddy/bin/caddy" || i.Config != "/custom brew/etc/Caddyfile" || i.Storage != "/custom brew/var/lib/caddy" || i.Source != "/Users/developer/Library/Application Support/sandbar/config.json" || i.Unit != "sh.brew.caddy" {
		t.Fatal(i)
	}
	for _, change := range []func(string) string{
		func(s string) string { return strings.Replace(s, `"run","--config"`, `"run","--resume","--config"`, 1) },
		func(s string) string {
			return strings.Replace(s, `"HOME":"/custom brew/var/lib"`, `"HOME":"/other"`, 1)
		},
		func(s string) string {
			return strings.Replace(s, `"installed":[{"version":"2.11.7"}]`, `"installed":[]`, 1)
		},
		func(s string) string { return strings.Replace(s, `"name":"caddy"`, `"name":"other"`, 1) },
	} {
		if _, err := homebrewInstallation("/custom brew", []byte(change(string(data))), account); err == nil {
			t.Fatal("accepted incompatible formula")
		}
	}
}

func TestDarwinSocketPathBoundary(t *testing.T) {
	for _, length := range []int{socketPathLimit, socketPathLimit + 1} {
		p := paths{state: "/" + strings.Repeat("a", length-len("/admin.sock")-1)}
		address, err := p.adminAddress()
		if length == socketPathLimit && (err != nil || len(strings.TrimPrefix(address, "unix/")) != length) {
			t.Fatal(address, err)
		}
		if length > socketPathLimit && err == nil {
			t.Fatal("accepted overlong socket")
		}
	}
}

func loadedHomebrewJob(i *installation) string {
	return fmt.Sprintf("program = %s\narguments = {\n%s\nrun\n--config\n%s\n}\nenvironment = {\nHOME => %s\nXDG_DATA_HOME => %s\nXPC_SERVICE_NAME => %s\n}\nstate = running\n", i.Binary, i.Binary, i.Config, filepath.Dir(i.Storage), filepath.Dir(i.Storage), i.Unit)
}
func TestLoadedHomebrewJob(t *testing.T) {
	i, err := homebrewInstallation("/custom brew", homebrewMetadata("/custom brew"), &user.User{Uid: "501", Gid: "20", HomeDir: "/Users/developer"})
	if err != nil {
		t.Fatal(err)
	}
	valid := loadedHomebrewJob(i)
	if err := checkLoadedHomebrewJob(i, []byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(valid, "\nrun\n", "\nrun\n--resume\n", 1),
		strings.Replace(valid, "HOME => /custom brew/var/lib", "HOME => /other", 1),
		strings.Replace(valid, "XPC_SERVICE_NAME =>", "XDG_CONFIG_HOME => /other\nXPC_SERVICE_NAME =>", 1),
		strings.Replace(valid, "program = "+i.Binary, "program = /other/caddy", 1),
	} {
		if err := checkLoadedHomebrewJob(i, []byte(bad)); err == nil {
			t.Fatal("accepted incompatible loaded job", bad)
		}
	}
}

func TestHomebrewCommandsAndStorageEnvironment(t *testing.T) {
	p, _ := testInstalledPaths(t)
	callsPath := fakeCaddy(t)
	p.installed.Binary = filepath.Join(filepath.Dir(callsPath), "caddy")
	p.installed.Storage = filepath.Join(p.state, "service-storage/caddy")
	s := &homebrewService{brew: p.installed.Binary, installation: p.installed}
	t.Setenv("HOME", "/caller-home")
	t.Setenv("XDG_CONFIG_HOME", "/caller-config")
	t.Setenv("CADDY_ADMIN", "localhost:9999")
	// Fake Caddy records the exact argv without running Homebrew or changing a service.
	for _, action := range []string{"reload"} {
		if err := s.Control(action, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Validate(io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	address, _ := p.adminAddress()
	want := [][]string{{"reload", "--config", p.installed.Config, "--force", "--address", address}, {"validate", "--config", p.file("validation/Caddyfile"), "--adapter", "caddyfile"}}
	if !reflect.DeepEqual(readCalls(t, callsPath), want) {
		t.Fatal(readCalls(t, callsPath))
	}
	env := strings.Join(installedCaddyEnv(p.installed), "\n")
	if !strings.Contains(env, "HOME="+filepath.Dir(p.installed.Storage)) || !strings.Contains(env, "XDG_DATA_HOME="+filepath.Dir(p.installed.Storage)) || strings.Contains(env, "/caller-config") || strings.Contains(env, "CADDY_ADMIN=") {
		t.Fatal("wrong service environment")
	}
	if err := s.Control("restart", io.Discard, io.Discard); err == nil {
		t.Fatal("accepted unsupported action")
	}
	// A command wrapper records start/stop and forwards their output and errors.
	wrapper := filepath.Join(shortHome(t), "brew")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$FAKE_CALLS\"\nprintf '%s\\n' -- >> \"$FAKE_CALLS\"\nprintf 'service output\\n'\nprintf 'service diagnostic\\n' >&2\nexit \"${SERVICE_EXIT:-0}\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	s.brew = wrapper
	var out, errOut bytes.Buffer
	for _, action := range []string{"start", "stop", "run", "kill"} {
		if err := s.Control(action, &out, &errOut); err != nil {
			t.Fatal(err)
		}
	}
	calls := readCalls(t, callsPath)
	for n, action := range []string{"start", "stop", "run", "kill"} {
		if !reflect.DeepEqual(calls[n+2], []string{"services", action, "caddy"}) {
			t.Fatal(calls)
		}
	}
	if !strings.Contains(out.String(), "service output") || !strings.Contains(errOut.String(), "service diagnostic") {
		t.Fatal(out.String(), errOut.String())
	}
	t.Setenv("SERVICE_EXIT", "17")
	if err := s.Control("start", io.Discard, io.Discard); err == nil {
		t.Fatal("discarded failed service command")
	}
}

func TestDarwinSetupRejectsLinuxOptions(t *testing.T) {
	for _, args := range [][]string{{"--user", "developer"}, {"--migrate-config", "old.json"}, {"--migrate-state", "old-state"}, {"unexpected"}} {
		var diagnostic bytes.Buffer
		if err := setup(args, io.Discard, &diagnostic); err == nil {
			t.Fatal(args)
		}
	}
}

type darwinSetupService struct {
	fakeService
	installation *installation
	validations  int
	failAction   string
	activeFile   string
}

func (s *darwinSetupService) Validate(out, errOut io.Writer) error {
	s.validations++
	if s.ValidateErr != nil {
		return s.ValidateErr
	}
	return (&homebrewService{installation: s.installation}).Validate(out, errOut)
}
func (s *darwinSetupService) Control(action string, out, errOut io.Writer) error {
	s.Actions = append(s.Actions, action)
	if action == s.failAction {
		s.failAction = ""
		return errors.New("simulated activation failure")
	}
	switch action {
	case "start":
		s.State = serviceState{State: "active", Boot: "enabled"}
	case "stop":
		s.State = serviceState{State: "inactive", Boot: "disabled"}
	case "run":
		s.State = serviceState{State: "active", Boot: "disabled"}
	case "kill":
		s.State = serviceState{State: "inactive", Boot: "enabled"}
	case "reload":
		if s.activeFile != "" {
			data, err := adaptCaddyfile(installedPaths(s.installation), s.installation.Config, errOut)
			if err != nil {
				return err
			}
			return atomicWriteMode(s.activeFile, data, 0600, -1, -1)
		}
	}
	return nil
}
func darwinSetupFixture(t *testing.T) (paths, *darwinSetupService) {
	t.Helper()
	requireIntegration(t)
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal(err)
	}
	root := shortHome(t)
	i := &installation{ID: "homebrew-fixture-v1", Binary: binary, Unit: "fixture.caddy", Config: filepath.Join(root, "brew/Caddyfile"), Globals: filepath.Join(root, "app/state/global.Caddyfile"), Source: filepath.Join(root, "app/config.json"), State: filepath.Join(root, "app/state"), Storage: filepath.Join(root, "service-storage/caddy"), UID: os.Getuid(), GID: os.Getgid(), GroupID: os.Getgid(), Account: "fixture"}
	if err := os.MkdirAll(filepath.Dir(i.Config), 0700); err != nil {
		t.Fatal(err)
	}
	service := &darwinSetupService{installation: i, fakeService: fakeService{State: serviceState{State: "inactive", Boot: "disabled"}}}
	i.Service = service
	return installedPaths(i), service
}
func setupFixtureVerified(p paths, c config) error {
	if c.HTTPPort != 80 || c.HTTPSPort != 443 {
		return errors.New("setup changed installed ports")
	}
	_, err := selectedStatusRoots(p.rootCertificate())
	return err
}
func TestDarwinSetupPreviewFreshRepeatAndRollback(t *testing.T) {
	p, service := darwinSetupFixture(t)
	var out, diagnostic bytes.Buffer
	if err := setupDarwin(p, setupOptions{Machine: "fixture", Check: true}, &out, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if !strings.Contains(out.String(), "Create missing Caddyfile:") || !strings.Contains(out.String(), "Login startup:") {
		t.Fatal(out.String())
	}
	for _, path := range []string{p.installed.Config, filepath.Dir(p.config)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("preview mutated %s: %v", path, err)
		}
	}
	if len(service.Actions) > 0 || service.validations > 0 {
		t.Fatal("preview mutated service")
	}
	apply := func() error { return setupDarwin(p, setupOptions{}, &out, &diagnostic, setupFixtureVerified) }
	if err := setupDarwin(p, setupOptions{Machine: "fixture"}, &out, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if fmt.Sprint(service.Actions) != "[start]" || service.validations != 1 {
		t.Fatal(service.Actions, service.validations)
	}
	root := readTestFile(t, p.rootCertificate())
	keyPath := filepath.Join(filepath.Dir(p.rootCertificate()), "root.key")
	key := readTestFile(t, keyPath)
	caPaths := []string{p.installed.Storage, filepath.Dir(p.rootCertificate()), p.rootCertificate(), keyPath}
	caModes := make([]os.FileMode, len(caPaths))
	for n, path := range caPaths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		caModes[n] = info.Mode()
	}
	if _, err := os.Lstat(p.file("root.crt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fresh setup exported a root", err)
	}
	top := readTestFile(t, p.installed.Config)
	cfg, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routes = append(cfg.Routes, route{Hostname: "kept.sandbar.localhost", Upstream: "8000"})
	source, err := configBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.writeFile(p.config, source); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if !bytes.Equal(root, readTestFile(t, p.rootCertificate())) || !bytes.Equal(top, readTestFile(t, p.installed.Config)) || !bytes.Equal(source, readTestFile(t, p.config)) {
		t.Fatal("repeat changed CA, top file, or routes")
	}
	if _, err := os.Lstat(p.file("root.crt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repeated setup exported a root", err)
	}
	if !bytes.Equal(key, readTestFile(t, keyPath)) {
		t.Fatal("repeat changed the CA private key")
	}
	for n, path := range caPaths {
		info, err := os.Stat(path)
		if err != nil || info.Mode() != caModes[n] {
			t.Fatal("repeat changed CA storage permissions", path, err)
		}
	}
	if bytes.Count(readTestFile(t, p.installed.Config), []byte(globalMarkerStart)) != 1 {
		t.Fatal("duplicated integration")
	}
	if err := filepath.WalkDir(filepath.Dir(p.config), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if entry.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			return fmt.Errorf("%s mode %o, want %o", path, info.Mode().Perm(), want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := readTestFile(t, p.generatedPath())
	service.failAction = "start"
	if err := apply(); err == nil || !strings.Contains(err.Error(), "backup.json") || strings.Contains(err.Error(), "external directory edit preserved") {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readTestFile(t, p.generatedPath())) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) || service.State.State != "active" || service.State.Boot != "enabled" {
		t.Fatal("rollback lost files or prior service state")
	}
	backups, err := filepath.Glob(p.file("backups/setup-*/backup.json"))
	if err != nil || len(backups) != 3 {
		t.Fatal(backups, err)
	}
}
func TestDarwinSetupExistingConfigAndRejectedCandidates(t *testing.T) {
	for _, test := range []struct {
		name, top string
		wantError bool
	}{
		{"unrelated", "http://other.localhost:19090 {\nbind 127.0.0.1\nrespond unrelated\n}\n", false},
		{"admin conflict", "{\nadmin localhost:2019\n}\n", true},
		{"syntax", "http://other.localhost:19090 {\ninvalid_directive\n}\n", true},
		{"hostname conflict", "https://sandbar.localhost {\nrespond conflict\n}\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, service := darwinSetupFixture(t)
			original := []byte(test.top)
			if err := os.WriteFile(p.installed.Config, original, 0600); err != nil {
				t.Fatal(err)
			}
			var out, diagnostic bytes.Buffer
			err := setupDarwin(p, setupOptions{Machine: "fixture"}, &out, &diagnostic, setupFixtureVerified)
			if test.wantError {
				if err == nil {
					t.Fatal("accepted conflict")
				}
				if len(service.Actions) > 0 {
					t.Fatal("activated rejected configuration", service.Actions)
				}
				if !bytes.Equal(original, readTestFile(t, p.installed.Config)) {
					t.Fatal("changed rejected config")
				}
				return
			}
			if err != nil {
				t.Fatal(err, diagnostic.String())
			}
			if !bytes.Contains(readTestFile(t, p.installed.Config), original) {
				t.Fatal("lost unrelated site")
			}
			if err := setupDarwin(p, setupOptions{}, &out, &diagnostic, setupFixtureVerified); err != nil {
				t.Fatal(err, diagnostic.String())
			}
		})
	}
}
func TestDarwinServiceRollbackRegistration(t *testing.T) {
	for _, test := range []struct {
		prior serviceState
		want  []string
	}{
		{serviceState{State: "active", Boot: "enabled"}, []string{"start", "reload"}},
		{serviceState{State: "active", Boot: "disabled"}, []string{"stop", "run"}},
		{serviceState{State: "failed", Boot: "enabled"}, []string{"start", "kill"}},
		{serviceState{State: "inactive", Boot: "disabled"}, []string{"stop"}},
	} {
		service := &fakeService{}
		if err := restoreDarwinService(service, test.prior, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(service.Actions, test.want) {
			t.Fatal(test.prior, service.Actions)
		}
	}
}
func TestDarwinInstalledTrustFailureForwarding(t *testing.T) {
	p, service := testInstalledPaths(t)
	calls := fakeCaddy(t)
	p.installed.Binary = filepath.Join(filepath.Dir(calls), "caddy")
	t.Setenv("FAKE_TRUST_EXIT", strconv.Itoa(19))
	t.Setenv("FAKE_DIAGNOSTIC", "partial trust failure")
	for _, command := range []string{"trust", "untrust"} {
		if err := p.writeFile(p.rootCertificate(), []byte("public root")); err != nil {
			t.Fatal(err)
		}
		var out, diagnostic bytes.Buffer
		err := changeTrust(p, command, &out, &diagnostic)
		var result *caddyError
		if !errors.As(err, &result) || result.code != 19 {
			t.Fatal("discarded trust exit status", err)
		}
		if !strings.Contains(diagnostic.String(), "partial trust failure") {
			t.Fatal(diagnostic.String())
		}
	}
	if len(service.Actions) > 0 {
		t.Fatal("trust changed service")
	}
}

func TestHomebrewServiceStates(t *testing.T) {
	i, err := homebrewInstallation("/brew", homebrewMetadata("/brew"), &user.User{Uid: "501", Gid: "20", HomeDir: "/Users/developer"})
	if err != nil {
		t.Fatal(err)
	}
	code := 1
	for _, test := range []struct {
		name        string
		entry       homebrewServiceInfo
		job         []byte
		state, boot string
		wantError   bool
	}{
		{name: "unregistered", state: "inactive", boot: "disabled"},
		{name: "registered stopped", entry: homebrewServiceInfo{Registered: true}, state: "failed", boot: "enabled"},
		{name: "failed", entry: homebrewServiceInfo{ExitCode: &code}, state: "failed", boot: "disabled"},
		{name: "active", entry: homebrewServiceInfo{Registered: true, Running: true, Loaded: true}, job: []byte(loadedHomebrewJob(i)), state: "active", boot: "enabled"},
		{name: "active unregistered", entry: homebrewServiceInfo{Running: true, Loaded: true}, job: []byte(loadedHomebrewJob(i)), state: "active", boot: "disabled"},
		{name: "inconsistent", entry: homebrewServiceInfo{Running: true}, wantError: true},
		{name: "incompatible", entry: homebrewServiceInfo{Running: true}, job: []byte("program = /other/caddy"), wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			state, err := homebrewServiceState(i, test.entry, test.job)
			if (err != nil) != test.wantError {
				t.Fatal(state, err)
			}
			if !test.wantError && (state.State != test.state || state.Boot != test.boot) {
				t.Fatal(state)
			}
		})
	}
}
func TestHomebrewServiceInspectionFailure(t *testing.T) {
	p, _ := testInstalledPaths(t)
	dir := shortHome(t)
	wrapper := filepath.Join(dir, "brew")
	// Inspection fails before any launchd command or mutation is attempted.
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nprintf 'inspection denied\\n' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	service := &homebrewService{brew: wrapper, installation: p.installed}
	state, err := service.Inspect()
	if err == nil || state.State != "inaccessible" || state.Boot != "unknown" || !strings.Contains(state.Diagnostic, "inspection denied") {
		t.Fatal(state, err)
	}
	if launchdJobMissing(errors.New("permission denied"), p.installed.Unit) {
		t.Fatal("treated inspection failure as missing")
	}
}
func TestHomebrewExistingJobCompatibility(t *testing.T) {
	p, _ := testInstalledPaths(t)
	i := p.installed
	i.Fragment = filepath.Join(shortHome(t), "caddy.plist")
	i.Log = "/fixture/caddy.log"
	job := map[string]any{"Label": i.Unit, "ProgramArguments": []string{i.Binary, "run", "--config", i.Config}, "EnvironmentVariables": map[string]string{"HOME": filepath.Dir(i.Storage), "XDG_DATA_HOME": filepath.Dir(i.Storage)}, "StandardOutPath": i.Log, "StandardErrorPath": i.Log}
	data, _ := json.Marshal(job)
	if err := os.WriteFile(i.Fragment, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkHomebrewJob(i); err != nil {
		t.Fatal(err)
	}
	job["ProgramArguments"] = []string{i.Binary, "run", "--resume", "--config", i.Config}
	data, _ = json.Marshal(job)
	if err := os.WriteFile(i.Fragment, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkHomebrewJob(i); err == nil {
		t.Fatal("accepted customized job")
	}
}
func TestDarwinStartRegistersActiveUnregisteredService(t *testing.T) {
	p, service := darwinSetupFixture(t)
	var diagnostic bytes.Buffer
	if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	adapted, err := adaptCaddyfile(p, p.installed.Config, &diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	transactionAdmin(t, p, string(adapted))
	service.Actions = nil
	service.State = serviceState{State: "active", Boot: "disabled"}
	before := service.validations
	if err := startInstalled(p, io.Discard, &diagnostic); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if fmt.Sprint(service.Actions) != "[start]" || service.State.Boot != "enabled" || service.validations != before+1 {
		t.Fatal(service.Actions, service.State, service.validations)
	}
}

func TestDarwinInstalledRouteChanges(t *testing.T) {
	p, service := darwinSetupFixture(t)
	unrelated := []byte("http://other.localhost:19090 {\nbind 127.0.0.1\nrespond unrelated\n}\n")
	if err := os.WriteFile(p.installed.Config, unrelated, 0600); err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	service.State = serviceState{State: "inactive", Boot: "disabled"}
	service.Actions = nil
	change := func(args ...string) error {
		return withLock(p, func() error { return changeRoutes(p, "add", args, io.Discard, &diagnostic) })
	}
	if err := change("first.sandbar.localhost", "8000"); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if len(service.Actions) > 0 {
		t.Fatal("stopped edit activated service", service.Actions)
	}
	adapted, err := adaptCaddyfile(p, p.installed.Config, &diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	service.activeFile = transactionAdmin(t, p, string(adapted))
	service.State = serviceState{State: "active", Boot: "enabled"}
	root := readTestFile(t, p.rootCertificate())
	if err := change("second.sandbar.localhost", "8001"); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if fmt.Sprint(service.Actions) != "[reload]" {
		t.Fatal("live route change restarted service", service.Actions)
	}
	source, generated := readTestFile(t, p.config), readTestFile(t, p.generatedPath())
	service.ValidateErr = errors.New("simulated validation failure")
	if err := change("rejected.sandbar.localhost", "8002"); err == nil {
		t.Fatal("accepted rejected candidate")
	}
	service.ValidateErr = nil
	service.failAction = "reload"
	if err := change("failed.sandbar.localhost", "8003"); err == nil {
		t.Fatal("discarded reload failure")
	}
	if !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(generated, readTestFile(t, p.generatedPath())) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) || !bytes.Contains(readTestFile(t, p.installed.Config), unrelated) {
		t.Fatal("failed change lost committed state")
	}
	if _, err := os.Stat(p.file("transaction")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed reload did not recover", err)
	}
}

func TestHomebrewEnvironmentOverrides(t *testing.T) {
	for _, test := range []struct{ name, xdg, brewXDG, root string }{
		{name: "home", root: ".homebrew"},
		{name: "XDG", xdg: "xdg", root: "xdg/homebrew"},
		{name: "Homebrew XDG", brewXDG: "brew-xdg", root: "brew-xdg/homebrew"},
		{name: "XDG precedence", xdg: "xdg", brewXDG: "brew-xdg", root: "xdg/homebrew"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := shortHome(t)
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", "")
			t.Setenv("HOMEBREW_XDG_CONFIG_HOME", "")
			if test.xdg != "" {
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, test.xdg))
			}
			if test.brewXDG != "" {
				t.Setenv("HOMEBREW_XDG_CONFIG_HOME", filepath.Join(home, test.brewXDG))
			}
			if err := checkHomebrewEnvironmentOverride(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(home, test.root, "services/caddy.env")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte("HOME=/unsupported/storage\n")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkHomebrewEnvironmentOverride(); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatal(err)
			}
			if !bytes.Equal(data, readTestFile(t, path)) {
				t.Fatal("inspection changed override")
			}
		})
	}
}

func TestDarwinStartupWait(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	initialTLS := &routeTLSError{&net.OpError{Op: "remote error", Err: errors.New("tls: internal error")}}
	attempts := 0
	if err := waitForDarwinStartup(func() error {
		attempts++
		switch attempts {
		case 1:
			return refused
		case 2:
			return initialTLS
		}
		return nil
	}, time.Second); err != nil || attempts != 3 {
		t.Fatal(err, attempts)
	}
	attempts = 0
	err := waitForDarwinStartup(func() error { attempts++; return refused }, 10*time.Millisecond)
	if !errors.Is(err, syscall.ECONNREFUSED) || !strings.Contains(err.Error(), "did not become ready") || attempts != 1 {
		t.Fatal(err, attempts)
	}
	for _, permanent := range []error{syscall.EACCES, &routeTLSError{errors.New("unknown authority")}, errors.New("welcome returned HTTP 503")} {
		attempts = 0
		err := waitForDarwinStartup(func() error { attempts++; return permanent }, time.Second)
		if !errors.Is(err, permanent) || attempts != 1 {
			t.Fatal(err, attempts)
		}
	}
}

func TestDarwinStartupDelayedTLSListener(t *testing.T) {
	p, _ := testInstalledPaths(t)
	certificate, root := statusCertificate(t, "sandbar.localhost")
	if err := p.writeFile(p.rootCertificate(), root); err != nil {
		t.Fatal(err)
	}
	roots, err := selectedStatusRoots(p.rootCertificate())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	address := server.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(address)
	httpsPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	t.Cleanup(server.Close)
	c := config{Version: 2, HTTPPort: 18080, HTTPSPort: httpsPort}
	attempts := 0
	err = waitForDarwinStartup(func() error {
		attempts++
		code, checkErr := checkHTTPSRoute(c, route{Hostname: "sandbar.localhost"}, roots)
		if attempts == 1 {
			if !errors.Is(checkErr, syscall.ECONNREFUSED) {
				return fmt.Errorf("expected delayed listener refusal: %w", checkErr)
			}
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return err
			}
			server.Listener = listener
			server.StartTLS()
		}
		if checkErr != nil {
			return checkErr
		}
		if code != 200 {
			return fmt.Errorf("unexpected HTTP %d", code)
		}
		return nil
	}, time.Second)
	if err != nil || attempts != 2 {
		t.Fatal(err, attempts)
	}
}

func TestDarwinInstalledStartupChecksWelcomeOnly(t *testing.T) {
	p, _ := testInstalledPaths(t)
	c, _, root := statusHTTPS(t, "sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "sandbar.localhost:") {
			w.WriteHeader(200)
		} else {
			t.Error("startup checked an app backend", r.Host)
			w.WriteHeader(502)
		}
	}))
	c.Routes = []route{{Hostname: "offline.sandbar.localhost", Upstream: "http://127.0.0.1:1"}}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", c.routeURL("sandbar.localhost")+"/")
		w.WriteHeader(308)
	}))
	defer redirect.Close()
	c.HTTPPort = redirect.Listener.Addr().(*net.TCPAddr).Port
	if err := p.writeFile(p.rootCertificate(), root); err != nil {
		t.Fatal(err)
	}
	if err := waitForInstalledStartup(p, c); err != nil {
		t.Fatal(err)
	}
}

func TestDarwinInstalledStartupRejectsRealTLSAndHTTPFailures(t *testing.T) {
	for _, test := range []struct {
		name      string
		code      int
		wrongRoot bool
	}{{name: "HTTP failure", code: 503}, {name: "wrong root", code: 200, wrongRoot: true}} {
		t.Run(test.name, func(t *testing.T) {
			p, _ := testInstalledPaths(t)
			var requests atomic.Int32
			c, _, root := statusHTTPS(t, "sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(test.code) }))
			if test.wrongRoot {
				_, root = statusCertificate(t, "other.localhost")
			}
			if err := p.writeFile(p.rootCertificate(), root); err != nil {
				t.Fatal(err)
			}
			err := waitForInstalledStartup(p, c)
			if err == nil {
				t.Fatal("accepted a startup failure")
			}
			if test.wrongRoot {
				var tlsErr *routeTLSError
				if !errors.As(err, &tlsErr) {
					t.Fatal(err)
				}
			} else if requests.Load() != 1 || !strings.Contains(err.Error(), "HTTP 503") {
				t.Fatal(err, requests.Load())
			}
		})
	}
}

func TestDarwinSetupVerificationFailureRollsBack(t *testing.T) {
	p, service := darwinSetupFixture(t)
	failed := errors.New("simulated startup verification failure")
	err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, io.Discard, func(paths, config) error { return failed })
	if !errors.Is(err, failed) || !strings.Contains(err.Error(), "backup.json") {
		t.Fatal(err)
	}
	if fmt.Sprint(service.Actions) != "[start stop]" || service.State.State != "inactive" || service.State.Boot != "disabled" {
		t.Fatal(service.Actions, service.State)
	}
	for _, path := range []string{p.installed.Config, p.config, p.generatedPath(), p.installed.Globals, p.file("setup.json")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("rollback left %s: %v", path, err)
		}
	}
}

func TestDarwinSetupCustomPorts(t *testing.T) {
	p, service := darwinSetupFixture(t)
	httpPort, httpsPort := 8080, 8443
	options := setupOptions{Machine: "fixture", HTTPPort: &httpPort, HTTPSPort: &httpsPort, Check: true}
	var out, diagnostic bytes.Buffer
	verify := func(p paths, c config) error {
		if c.HTTPPort != httpPort || c.HTTPSPort != httpsPort {
			return fmt.Errorf("wrong setup ports: %d/%d", c.HTTPPort, c.HTTPSPort)
		}
		_, err := selectedStatusRoots(p.rootCertificate())
		return err
	}
	if err := setupDarwin(p, options, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if !strings.Contains(out.String(), "Ports: HTTP 8080 HTTPS 8443") || !strings.Contains(out.String(), "https://sandbar.localhost:8443") {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(p.config); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("preview created config", err)
	}
	options.Check = false
	if err := setupDarwin(p, options, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if err := initialize(p, nil, io.Discard, &diagnostic); err != nil {
		t.Fatal("init did not retain selected ports", err)
	}
	if err := initialize(p, []string{"--http-port", "9080"}, io.Discard, &diagnostic); err == nil || !strings.Contains(err.Error(), "setup") {
		t.Fatal("init changed installed ports", err)
	}
	root := readTestFile(t, p.rootCertificate())
	service.State = serviceState{State: "inactive", Boot: "disabled"}
	if err := changeRoutes(p, "add", []string{"kept.sandbar.localhost", "8000"}, io.Discard, &diagnostic); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if err := setupDarwin(p, setupOptions{}, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	cfg, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTPPort != 8080 || cfg.HTTPSPort != 8443 || len(cfg.Routes) != 1 || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("repeat lost selected ports, route, or CA", cfg)
	}
	globals := string(readTestFile(t, p.installed.Globals))
	routes := string(readTestFile(t, p.generatedPath()))
	if !strings.Contains(globals, "http_port 8080\nhttps_port 8443\n") || !strings.Contains(routes, "http://:8080 {") || strings.Contains(routes, "http://:80 {") {
		t.Fatal(globals, routes)
	}
	httpsPort = 9443
	if err := setupDarwin(p, setupOptions{HTTPSPort: &httpsPort}, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	cfg, err = readConfig(p.config)
	if err != nil || cfg.HTTPPort != 8080 || cfg.HTTPSPort != 9443 || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal(cfg, err)
	}
}

func TestDarwinSetupInvalidPortsPreserveFiles(t *testing.T) {
	for _, test := range []struct {
		name        string
		http, https int
	}{
		{"zero", 0, 8443}, {"negative", -1, 8443}, {"range", 8080, 65536}, {"same", 8080, 8080}, {"backend", 8000, 8443},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, service := darwinSetupFixture(t)
			cfg := config{Version: 2, HTTPPort: 80, HTTPSPort: 443, Routes: []route{{Hostname: "kept.sandbar.localhost", Upstream: "8000"}}}
			source, err := configBytes(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(p.config), 0700); err != nil {
				t.Fatal(err)
			}
			if err := p.writeFile(p.config, source); err != nil {
				t.Fatal(err)
			}
			top := []byte("# preserve existing configuration\n")
			if err := os.WriteFile(p.installed.Config, top, 0600); err != nil {
				t.Fatal(err)
			}
			options := setupOptions{Machine: "fixture", HTTPPort: &test.http, HTTPSPort: &test.https}
			err = setupDarwin(p, options, io.Discard, io.Discard, setupFixtureVerified)
			if err == nil {
				t.Fatal("accepted invalid ports")
			}
			if len(service.Actions) != 0 || service.validations != 0 || !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(top, readTestFile(t, p.installed.Config)) {
				t.Fatal("invalid ports changed files or service")
			}
			if _, err := os.Stat(p.state); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid ports created state", err)
			}
		})
	}
}

func TestDarwinSetupExistingGlobalPorts(t *testing.T) {
	for _, test := range []struct {
		name, settings string
		wantError      bool
	}{
		{"matching", "http_port 8080\nhttps_port 8443\n", false},
		{"conflicting HTTP", "http_port 80\n", true},
		{"conflicting HTTPS", "https_port 443\n", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, service := darwinSetupFixture(t)
			fragment := filepath.Join(filepath.Dir(p.installed.Config), "ports.Caddyfile")
			if err := os.WriteFile(fragment, []byte(test.settings), 0600); err != nil {
				t.Fatal(err)
			}
			top := []byte("{\nimport " + strconv.Quote(fragment) + "\n}\nhttp://other.localhost:19090 {\nbind 127.0.0.1\nrespond kept\n}\n")
			if err := os.WriteFile(p.installed.Config, top, 0600); err != nil {
				t.Fatal(err)
			}
			httpPort, httpsPort := 8080, 8443
			options := setupOptions{Machine: "fixture", HTTPPort: &httpPort, HTTPSPort: &httpsPort, Check: true}
			var diagnostic bytes.Buffer
			verify := func(p paths, c config) error { _, err := selectedStatusRoots(p.rootCertificate()); return err }
			err := setupDarwin(p, options, io.Discard, &diagnostic, verify)
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), "conflicts") {
					t.Fatal(err)
				}
				if len(service.Actions) != 0 || !bytes.Equal(top, readTestFile(t, p.installed.Config)) {
					t.Fatal("conflict changed state")
				}
				return
			}
			if err != nil {
				t.Fatal(err, diagnostic.String())
			}
			options.Check = false
			if err := setupDarwin(p, options, io.Discard, &diagnostic, verify); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			if bytes.Contains(readTestFile(t, p.installed.Globals), []byte("http_port")) || bytes.Contains(readTestFile(t, p.installed.Globals), []byte("https_port")) {
				t.Fatal("duplicated existing global settings")
			}
			if string(readTestFile(t, fragment)) != test.settings || !bytes.Contains(readTestFile(t, p.installed.Config), []byte("respond kept")) {
				t.Fatal("rewrote unrelated configuration")
			}
		})
	}
}

func TestDarwinCustomPortListeners(t *testing.T) {
	p, _ := darwinSetupFixture(t)
	httpPort, httpsPort := freePorts(t)
	var diagnostic bytes.Buffer
	verify := func(p paths, c config) error { _, err := selectedStatusRoots(p.rootCertificate()); return err }
	if err := setupDarwin(p, setupOptions{Machine: "fixture", HTTPPort: &httpPort, HTTPSPort: &httpsPort}, io.Discard, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	adapted, err := adaptCaddyfile(p, p.installed.Config, &diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Listen []string `json:"listen"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(adapted, &document); err != nil {
		t.Fatal(err)
	}
	for _, server := range document.Apps.HTTP.Servers {
		for _, address := range server.Listen {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			if port == "80" || port == "443" {
				t.Fatal("adapted privileged listener", address)
			}
		}
	}
	var logs bytes.Buffer
	command := exec.Command(p.installed.Binary, "run", "--config", p.installed.Config, "--adapter", "caddyfile")
	command.Env = installedCaddyEnv(p.installed)
	command.Stdout = &logs
	command.Stderr = &logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
		if err := command.Wait(); err != nil {
			t.Errorf("test Caddy: %v\n%s", err, logs.String())
		}
	})
	if err := waitForInstalledStartup(p, c); err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(command.Process.Pid)
	for _, protocol := range []string{"TCP", "UDP"} {
		args := []string{"-nP", "-a", "-p", pid, "-i" + protocol, "-Fn"}
		if protocol == "TCP" {
			args = append(args, "-sTCP:LISTEN")
		}
		output, err := exec.Command("/usr/sbin/lsof", args...).Output()
		if err != nil {
			if status, ok := err.(*exec.ExitError); protocol != "UDP" || !ok || status.ExitCode() != 1 {
				t.Fatal(err)
			}
		}
		seen := map[string]bool{}
		for _, line := range strings.Split(string(output), "\n") {
			if !strings.HasPrefix(line, "n") {
				continue
			}
			host, port, err := net.SplitHostPort(strings.TrimPrefix(line, "n"))
			if err != nil {
				t.Fatal(err)
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() || (port != strconv.Itoa(httpPort) && port != strconv.Itoa(httpsPort)) {
				t.Fatal("implicit or non-loopback Caddy listener", line)
			}
			seen[port] = true
			t.Log(protocol, line)
		}
		if protocol == "TCP" && (!seen[strconv.Itoa(httpPort)] || !seen[strconv.Itoa(httpsPort)]) {
			t.Fatal("missing selected listeners", seen)
		}
	}

	// The unknown-host fallback uses the selected HTTP port.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://unknown.localhost/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 || response.Header.Get("Location") != "" {
		t.Fatal("unexpected fallback", response.StatusCode, response.Header)
	}
}

func TestDarwinSetupRestartsFailedRegisteredJob(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(strconv.FormatBool(failStart), func(t *testing.T) {
			p, service := darwinSetupFixture(t)
			service.State = serviceState{State: "failed", Boot: "enabled"}
			var out bytes.Buffer
			if err := setupDarwin(p, setupOptions{Machine: "fixture", Check: true}, &out, io.Discard, setupFixtureVerified); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Service action: one setup stop/start") || len(service.Actions) != 0 {
				t.Fatal(out.String(), service.Actions)
			}
			if failStart {
				service.failAction = "start"
			}
			err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, io.Discard, setupFixtureVerified)
			if !failStart {
				if err != nil || fmt.Sprint(service.Actions) != "[stop start]" || service.State.State != "active" || service.State.Boot != "enabled" {
					t.Fatal(err, service.Actions, service.State)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "backup.json") || fmt.Sprint(service.Actions) != "[stop start start kill]" {
				t.Fatal(err, service.Actions)
			}
			if service.State.State != "inactive" || service.State.Boot != "enabled" {
				t.Fatal("rollback lost registered non-running state", service.State)
			}
			for _, path := range []string{p.installed.Config, p.config, p.generatedPath(), p.installed.Globals, p.file("setup.json")} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rollback left %s: %v", path, err)
				}
			}
		})
	}
}

func TestDarwinSetupIgnoresStateRoot(t *testing.T) {
	p, _ := darwinSetupFixture(t)
	if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, io.Discard, setupFixtureVerified); err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
	original := readTestFile(t, rootPath)
	_, stale := statusCertificate(t, "old.localhost")
	if bytes.Equal(original, stale) {
		t.Fatal("fixture roots must differ")
	}
	if err := p.writeFile(p.file("root.crt"), stale); err != nil {
		t.Fatal(err)
	}
	verify := func(p paths, c config) error {
		if p.rootCertificate() != rootPath || !bytes.Equal(readTestFile(t, p.rootCertificate()), original) {
			return errors.New("setup selected the old state copy")
		}
		return setupFixtureVerified(p, c)
	}
	if err := setupDarwin(p, setupOptions{}, io.Discard, io.Discard, verify); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stale, readTestFile(t, p.file("root.crt"))) || !bytes.Equal(original, readTestFile(t, rootPath)) {
		t.Fatal("setup changed either certificate")
	}
	backups, err := filepath.Glob(p.file("backups/setup-*/backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range backups {
		var backup setupUndo
		if err := json.Unmarshal(readTestFile(t, path), &backup); err != nil {
			t.Fatal(err)
		}
		for _, file := range backup.Files {
			if file.Path == p.file("root.crt") || file.Path == rootPath {
				t.Fatal("setup backed up a certificate", file.Path)
			}
		}
	}
}

func TestDarwinInstalledOriginalRootConsumers(t *testing.T) {
	p, service := testInstalledPaths(t)
	rootPath := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
	if p.rootCertificate() != rootPath {
		t.Fatal("root did not use verified storage", p.rootCertificate())
	}
	c, _, root := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	_, stale := statusCertificate(t, "old.localhost")
	for path, data := range map[string][]byte{rootPath: root, p.file("root.crt"): stale} {
		if err := p.writeFile(path, data); err != nil {
			t.Fatal(err)
		}
	}
	source, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.writeFile(p.config, source); err != nil {
		t.Fatal(err)
	}
	statusGenerated(t, p, c)
	service.State = serviceState{State: "active", Boot: "enabled"}
	var out bytes.Buffer
	// An unavailable admin socket is reported separately from the route's TLS probe.
	if err := status(p, &out, io.Discard); err == nil || !strings.Contains(out.String(), "HTTP 200 (reachable)") {
		t.Fatal("status did not verify with the original root", err, out.String())
	}
	if !bytes.Equal(root, readTestFile(t, rootPath)) || !bytes.Equal(stale, readTestFile(t, p.file("root.crt"))) || len(service.Actions) != 0 {
		t.Fatal("status changed certificates or service")
	}
}

func TestDarwinInstalledUntrustOriginalRoot(t *testing.T) {
	p, service := testInstalledPaths(t)
	rootPath := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
	keyPath := filepath.Join(filepath.Dir(rootPath), "root.key")
	_, root := statusCertificate(t, "sandbar.localhost")
	_, stale := statusCertificate(t, "old.localhost")
	key := []byte("retained private key fixture")
	for path, data := range map[string][]byte{rootPath: root, p.file("root.crt"): stale, keyPath: key, p.config: []byte("invalid routes")} {
		if err := p.writeFile(path, data); err != nil {
			t.Fatal(err)
		}
	}
	calls := fakeCaddy(t)
	p.installed.Binary = filepath.Join(filepath.Dir(calls), "caddy")
	var out, diagnostic bytes.Buffer
	if err := changeTrust(p, "untrust", &out, &diagnostic); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(readCalls(t, calls), [][]string{{"version"}, {"untrust", "--cert", rootPath}}) {
		t.Fatal(readCalls(t, calls))
	}
	if !strings.Contains(out.String(), rootPath) || !strings.Contains(diagnostic.String(), rootPath) || strings.Contains(out.String(), p.file("root.crt")) {
		t.Fatal("untrust reported the wrong certificate", out.String(), diagnostic.String())
	}
	for path, data := range map[string][]byte{rootPath: root, p.file("root.crt"): stale, keyPath: key, p.config: []byte("invalid routes")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 || !bytes.Equal(data, readTestFile(t, path)) {
			t.Fatal("untrust changed retained data or permissions", path, err)
		}
	}
	if len(service.Actions) != 0 || service.State.State != "inactive" {
		t.Fatal("untrust changed the stopped service")
	}
}

func TestDarwinOriginalRootUnavailable(t *testing.T) {
	for _, kind := range []string{"missing", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			p, service := testInstalledPaths(t)
			root := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
			_, stale := statusCertificate(t, "old.localhost")
			if err := p.writeFile(p.file("root.crt"), stale); err != nil {
				t.Fatal(err)
			}
			want := os.ErrNotExist
			if kind == "unreadable" {
				if os.Geteuid() == 0 {
					t.Skip("root can read mode-0000 fixture files")
				}
				if err := os.WriteFile(root, stale, 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(root, 0600) })
				want = os.ErrPermission
			}
			calls := fakeCaddy(t)
			p.installed.Binary = filepath.Join(filepath.Dir(calls), "caddy")
			for _, check := range []func() error{
				func() error { return changeTrust(p, "untrust", io.Discard, io.Discard) },
				func() error { _, err := selectedStatusRoots(p.rootCertificate()); return err },
				func() error { return waitForInstalledStartup(p, config{}) },
			} {
				err := check()
				if !errors.Is(err, want) || !strings.Contains(err.Error(), "read selected root certificate "+root) {
					t.Fatal("original-root access error was lost", err)
				}
			}
			start := time.Now()
			if _, err := readServiceRoot(p); !errors.Is(err, want) {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			if elapsed > 6*time.Second || (kind == "missing" && elapsed < 3*time.Second) {
				t.Fatal("setup root readiness changed its bound", elapsed)
			}
			if _, err := os.Stat(calls); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invoked certificate removal for an unavailable original", err)
			}
			if !bytes.Equal(stale, readTestFile(t, p.file("root.crt"))) || len(service.Actions) != 0 {
				t.Fatal("access failure changed the old copy or service")
			}
			info, err := os.Stat(root)
			if kind == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("regenerated a missing original", err)
			}
			if kind == "unreadable" && (err != nil || info.Mode().Perm() != 0000) {
				t.Fatal("changed original permissions", err)
			}
		})
	}
}

func TestDarwinSetupWaitsForOriginalRoot(t *testing.T) {
	p, _ := testInstalledPaths(t)
	rootPath := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
	_, root := statusCertificate(t, "sandbar.localhost")
	written := make(chan error, 1)
	go func() {
		time.Sleep(150 * time.Millisecond)
		written <- atomicWriteMode(rootPath, root, 0600, -1, -1)
	}()
	got, err := readServiceRoot(p)
	if writeErr := <-written; writeErr != nil {
		t.Fatal(writeErr)
	}
	if err != nil || !bytes.Equal(got, root) {
		t.Fatal("setup did not wait for Caddy's original root", err)
	}
	if _, err := os.Lstat(p.file("root.crt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("root readiness created a state copy", err)
	}
}

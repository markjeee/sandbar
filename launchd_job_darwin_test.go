package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func missingLaunchdFixture(t *testing.T, unit string) error {
	t.Helper()
	err := exec.Command("/bin/sh", "-c", "exit 113").Run()
	return fmt.Errorf("%w: Could not find service %q in domain for user gui:", err, unit)
}
func launchdFixtureOutput(i *installation, plan socketPlan) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "program = %s\narguments = {\n", i.CLI)
	for _, arg := range bridgeArguments(i) {
		fmt.Fprintln(&b, arg)
	}
	fmt.Fprintf(&b, "}\nenvironment = {\nHOME => %s\nXDG_DATA_HOME => %s\n}\nstate = running\n", filepath.Dir(i.Storage), filepath.Dir(i.Storage))
	// Observed from gui/501/local.sandbar.caddy after installed migration.
	// launchctl repeats each group name for its IPv6 and IPv4 socket entries.
	b.WriteString("\tsockets = {\n")
	descriptor := 42
	for _, g := range []struct {
		name, kind string
		port       int
	}{{"HTTPS", "stream", plan.HTTPSPort}, {"HTTP", "stream", plan.HTTPPort}, {"QUIC", "datagram", plan.HTTPSPort}} {
		families := []string{"ipv4"}
		if plan.IPv6 {
			families = []string{"ipv6", "ipv4"}
		}
		for _, family := range families {
			node := "127.0.0.1"
			if family == "ipv6" {
				node = "::1"
			}
			fmt.Fprintf(&b, "\t\t%q = {\n\t\t\ttype = %s\n\t\t\tnode name = %s\n\t\t\tservice name = %d\n\t\t\tfamily = %s\n\n\t\t\tsockets = {\n\t\t\t\t%d (no bytes to read)\n\t\t\t}\n\n\t\t\tactive = 1\n\t\t\tpassive = 1\n\t\t\tbonjour = 0\n\t\t\tipv4v6 = 0\n\t\t\treceive_packet_info = 0\n\t\t}\n", g.name, g.kind, node, g.port, family, descriptor)
			descriptor++
		}
	}
	b.WriteString("\t}\n")
	return []byte(b.String())
}
func launchdOwnedFixture(t *testing.T) (*launchdService, socketPlan) {
	t.Helper()
	p, _ := testInstalledPaths(t)
	old := p.installed
	old.Fragment = filepath.Join(filepath.Dir(old.Source), "LaunchAgents/sh.brew.caddy.plist")
	old.Log = filepath.Join(filepath.Dir(old.Source), "caddy.log")
	i := newLaunchdInstallation(old, "/custom/bin/sandbar")
	s := &launchdService{installation: i}
	i.Service = s
	plan := socketPlan{18080, 18443, false}
	job, err := renderLaunchdJob(i, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{launchdTemplate(i), i.Fragment} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, job, 0600); err != nil {
			t.Fatal(err)
		}
	}
	record, _ := json.Marshal(setupRecord{Identity: i.identity(), SocketPlan: &plan})
	if err := os.WriteFile(filepath.Join(i.State, "setup.json"), record, 0600); err != nil {
		t.Fatal(err)
	}
	return s, plan
}
func TestLaunchdJobDefinitionAndLoadedIdentity(t *testing.T) {
	s, plan := launchdOwnedFixture(t)
	i := s.installation
	for _, ipv6 := range []bool{false, true} {
		plan.IPv6 = ipv6
		data, err := renderLaunchdJob(i, plan)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("/usr/bin/plutil", "-lint", "-")
		cmd.Stdin = bytes.NewReader(data)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("plist: %v %s", err, output)
		}
		output := launchdFixtureOutput(i, plan)
		if err := checkLoadedLaunchdJob(i, output); err != nil {
			t.Fatal(err)
		}
		if err := checkLoadedSocketPlan(output, plan); err != nil {
			t.Fatal(err)
		}
		for _, change := range []struct{ old, new string }{{"type = datagram", "type = stream"}, {"service name = 18443", "service name = 443"}, {"\"HTTP\" = {", "\"FOREIGN\" = {"}} {
			if err := checkLoadedSocketPlan(bytes.Replace(output, []byte(change.old), []byte(change.new), 1), plan); err == nil {
				t.Fatalf("accepted %s", change.old)
			}
		}
	}
}
func TestLaunchdLifecycleStopStartAndChangedDefinition(t *testing.T) {
	s, plan := launchdOwnedFixture(t)
	i := s.installation
	oldOutput, oldControl := launchdOutput, launchdControl
	t.Cleanup(func() { launchdOutput = oldOutput; launchdControl = oldControl })
	loaded := true
	var actions []string
	missing := missingLaunchdFixture(t, i.Unit)
	launchdOutput = func(binary string, args ...string) ([]byte, error) {
		if args[len(args)-1] == launchdDomain(i) {
			return []byte("domain"), nil
		}
		if !loaded {
			return nil, missing
		}
		return launchdFixtureOutput(i, plan), nil
	}
	launchdControl = func(args ...string) error {
		actions = append(actions, args[0])
		loaded = args[0] == "bootstrap"
		return nil
	}
	if err := os.WriteFile(i.Source, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(i.State, "transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Control("stop", io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(i.Fragment); !os.IsNotExist(err) {
		t.Fatal("login copy retained", err)
	}
	if _, err := os.Stat(launchdTemplate(i)); err != nil {
		t.Fatal(err)
	}
	if err := s.Control("stop", io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	state, err := s.Inspect()
	if err != nil || state.State != "inactive" || state.Sockets != "released" || state.Boot != "disabled" {
		t.Fatal(state, err)
	}
	if err := s.Control("start", io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(actions) != "[bootout bootstrap]" {
		t.Fatal(actions)
	}
	state, err = s.Inspect()
	if err != nil || state.State != "active" || state.Boot != "enabled" {
		t.Fatal(state, err)
	}
	if err := os.WriteFile(i.Fragment, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Control("stop", io.Discard, io.Discard); err == nil {
		t.Fatal("accepted changed job")
	}
}
func TestLaunchdRemovalWaitObservesProcessAndTimeout(t *testing.T) {
	s, _ := launchdOwnedFixture(t)
	i := s.installation
	old := launchdOutput
	t.Cleanup(func() { launchdOutput = old })
	missing := missingLaunchdFixture(t, i.Unit)
	checks := 0
	launchdOutput = func(binary string, args ...string) ([]byte, error) {
		if binary == "/bin/ps" {
			checks++
			if checks < 2 {
				return []byte("999"), nil
			}
			return nil, fmt.Errorf("process absent")
		}
		return nil, missing
	}
	if err := waitLaunchdRemoval(i, time.Second, "999"); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatal(checks)
	}
	launchdOutput = func(string, ...string) ([]byte, error) { return []byte("still loaded"), nil }
	if err := waitLaunchdRemoval(i, time.Millisecond); err == nil {
		t.Fatal("shutdown timeout ignored")
	}
}
func TestLaunchdOwnershipConflicts(t *testing.T) {
	s, _ := launchdOwnedFixture(t)
	i := s.installation
	if err := checkNewLaunchdTarget(i); err == nil {
		t.Fatal("existing target overwritten")
	}
	old := *i
	old.Unit = "sh.brew.caddy"
	old.Fragment = filepath.Join(filepath.Dir(i.Fragment), "sh.brew.caddy.plist")
	if err := os.WriteFile(old.Fragment, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkCompetingHomebrewJob(&old); err == nil {
		t.Fatal("competing owner ignored")
	}
}

type launchdSetupFixtureService struct {
	*darwinSetupService
	beforeControl func(string) error
}

func (s *launchdSetupFixtureService) Control(action string, out, errOut io.Writer) error {
	if s.beforeControl != nil {
		if err := s.beforeControl(action); err != nil {
			return err
		}
	}
	return s.darwinSetupService.Control(action, out, errOut)
}
func launchdSetupFixture(t *testing.T) (paths, *launchdSetupFixtureService) {
	t.Helper()
	p, base := darwinSetupFixture(t)
	i := p.installed
	i.ID = sandbarLaunchdID
	i.Unit = sandbarLaunchdLabel
	i.CLI = "/custom/bin/sandbar"
	i.Fragment = filepath.Join(filepath.Dir(i.Source), "LaunchAgents/local.sandbar.caddy.plist")
	i.Log = filepath.Join(filepath.Dir(i.Source), "caddy.log")
	service := &launchdSetupFixtureService{darwinSetupService: base}
	i.Service = service
	return p, service
}
func TestLaunchdSetupPublicationRepeatAndRollback(t *testing.T) {
	p, service := launchdSetupFixture(t)
	i := p.installed
	oldOutput, oldControl := launchdOutput, launchdControl
	t.Cleanup(func() { launchdOutput = oldOutput; launchdControl = oldControl })
	loaded := false
	var actions []string
	missing := missingLaunchdFixture(t, i.Unit)
	launchdOutput = func(string, ...string) ([]byte, error) {
		if !loaded {
			return nil, missing
		}
		return []byte("state = running"), nil
	}
	launchdControl = func(args ...string) error { actions = append(actions, args[0]); loaded = false; return nil }
	service.beforeControl = func(action string) error {
		actions = append(actions, action)
		if action == "start" {
			record, err := readSetupRecord(p)
			if err != nil {
				return fmt.Errorf("record missing before bootstrap: %w", err)
			}
			if record.SocketPlan == nil {
				return fmt.Errorf("plan missing before bootstrap")
			}
			if _, err := os.Stat(launchdTemplate(i)); err != nil {
				return err
			}
			loaded = true
		}
		if action == "stop" {
			loaded = false
		}
		return nil
	}
	http, https := 8080, 8443
	options := setupOptions{Machine: "fixture", HTTPPort: &http, HTTPSPort: &https}
	var out, diagnostic bytes.Buffer
	verify := func(p paths, c config) error {
		if c.HTTPPort != http || c.HTTPSPort != https {
			return fmt.Errorf("ports changed")
		}
		_, err := selectedStatusRoots(p.rootCertificate())
		return err
	}
	if err := setupDarwin(p, setupOptions{Machine: "fixture", Check: true, HTTPPort: &http, HTTPSPort: &https}, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if _, err := os.Stat(p.state); !os.IsNotExist(err) {
		t.Fatal("preview created state", err)
	}
	if err := setupDarwin(p, options, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	root := readTestFile(t, p.rootCertificate())
	cfg := readTestFile(t, p.config)
	top := readTestFile(t, i.Config)
	if err := setupDarwin(p, setupOptions{}, &out, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if !bytes.Equal(root, readTestFile(t, p.rootCertificate())) || !bytes.Equal(cfg, readTestFile(t, p.config)) || !bytes.Equal(top, readTestFile(t, i.Config)) {
		t.Fatal("repeated setup changed committed state")
	}
	recordBefore := readTestFile(t, p.file("setup.json"))
	jobBefore := readTestFile(t, i.Fragment)
	actions = nil
	failed := fmt.Errorf("simulated route verification failure")
	err := setupDarwin(p, setupOptions{}, io.Discard, &diagnostic, func(paths, config) error { return failed })
	if err == nil || !strings.Contains(err.Error(), failed.Error()) {
		t.Fatal(err)
	}
	if !bytes.Equal(recordBefore, readTestFile(t, p.file("setup.json"))) || !bytes.Equal(jobBefore, readTestFile(t, i.Fragment)) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("rollback lost record, job or CA")
	}
	if fmt.Sprint(actions) != "[stop start bootout start reload]" {
		t.Fatal("wrong rollback service order", actions)
	}
	if err := os.WriteFile(p.config, []byte("invalid pending source"), 0600); err != nil {
		t.Fatal(err)
	}
	record, err := readSetupRecord(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadLaunchdRuntime(i, record, &diagnostic); err != nil {
		t.Fatal("login used pending source", err, diagnostic.String())
	}
}

func TestLaunchdActiveHomebrewMigration(t *testing.T) {
	p, _ := launchdSetupFixture(t)
	i := p.installed
	old := *i
	old.ID = "homebrew-launchd-v1"
	old.Unit = "sh.brew.caddy"
	old.CLI = ""
	old.Fragment = filepath.Join(filepath.Dir(i.Fragment), "sh.brew.caddy.plist")
	if err := os.MkdirAll(filepath.Dir(old.Fragment), 0700); err != nil {
		t.Fatal(err)
	}
	oldJob := []byte("verified prior Homebrew fixture job")
	if err := os.WriteFile(old.Fragment, oldJob, 0600); err != nil {
		t.Fatal(err)
	}
	brewLog := filepath.Join(filepath.Dir(i.Source), "brew-actions")
	brew := filepath.Join(filepath.Dir(i.Source), "brew")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$FIXTURE_BREW_LOG\"\nif [ \"$2\" = stop ]; then rm -f \"$FIXTURE_OLD_JOB\"; fi\n"
	if err := os.WriteFile(brew, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIXTURE_BREW_LOG", brewLog)
	t.Setenv("FIXTURE_OLD_JOB", old.Fragment)
	priorService := &homebrewService{brew: brew, installation: &old}
	i.Service = &launchdService{installation: i, old: priorService}
	plan := socketPlan{HTTPPort: 8080, HTTPSPort: 8443, IPv6: false}
	cfg := config{Version: 2, HTTPPort: plan.HTTPPort, HTTPSPort: plan.HTTPSPort}
	source, err := configBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := renderInstalledRoutes(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	address, err := p.adminAddress()
	if err != nil {
		t.Fatal(err)
	}
	globals := []byte(renderInstalledGlobals(cfg, address, "", ""))
	composition, err := composeInstalledConfig(i.Config, nil, i.Globals, p.generatedPath(), globals, []byte(routes), false)
	if err != nil {
		t.Fatal(err)
	}
	oldOutput, oldControl := launchdOutput, launchdControl
	t.Cleanup(func() { launchdOutput = oldOutput; launchdControl = oldControl })
	missingOld, missingNew := missingLaunchdFixture(t, old.Unit), missingLaunchdFixture(t, i.Unit)
	loaded := false
	bootstrap := 0
	launchdOutput = func(binary string, args ...string) ([]byte, error) {
		target := args[len(args)-1]
		if target == launchdTarget(&old) {
			return nil, missingOld
		}
		if target == launchdDomain(i) {
			return []byte("domain"), nil
		}
		if !loaded {
			return nil, missingNew
		}
		return launchdFixtureOutput(i, plan), nil
	}
	launchdControl = func(args ...string) error {
		if args[0] != "bootstrap" {
			return fmt.Errorf("unexpected action %v", args)
		}
		bootstrap++
		record, err := readSetupRecord(p)
		if err != nil {
			return err
		}
		if record.Identity != i.identity() || record.SocketPlan == nil {
			return fmt.Errorf("record not published before bootstrap")
		}
		loaded = true
		return nil
	}
	verify := func(p paths, c config) error { _, err := selectedStatusRoots(p.rootCertificate()); return err }
	var diagnostic bytes.Buffer
	err = applyDarwinSetup(p, cfg, source, []byte(routes), globals, composition, nil, serviceState{State: "active", Boot: "enabled"}, priorService, plan, io.Discard, &diagnostic, verify)
	if err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if bootstrap != 1 {
		t.Fatal(bootstrap)
	}
	if got := string(readTestFile(t, brewLog)); got != "services stop caddy\n" {
		t.Fatal(got)
	}
	backups, err := filepath.Glob(p.file("backups/setup-*/backup.json"))
	if err != nil || len(backups) != 1 {
		t.Fatal(backups, err)
	}
	var undo setupUndo
	if err := json.Unmarshal(readTestFile(t, backups[0]), &undo); err != nil {
		t.Fatal(err)
	}
	if undo.PriorInstallation != old.identity() || undo.PriorJob == nil || !bytes.Equal(undo.PriorJob.Data, oldJob) {
		t.Fatal("prior job backup missing")
	}
	state, err := i.Service.Inspect()
	if err != nil || state.State != "active" || state.Boot != "enabled" {
		t.Fatal(state, err)
	}
	// A failed Caddy process can leave launchd holding every listening socket.
	failedOutput := bytes.Replace(launchdFixtureOutput(i, plan), []byte("state = running"), []byte("state = not running"), 1)
	launchdOutput = func(binary string, args ...string) ([]byte, error) {
		if args[len(args)-1] == launchdTarget(&old) {
			return nil, missingOld
		}
		return failedOutput, nil
	}
	state, err = i.Service.Inspect()
	if err != nil || state.State != "failed" || state.Sockets != "owned by launchd" || state.Boot != "enabled" {
		t.Fatal(state, err)
	}
}

func TestLaunchdRollbackRestoresRegistrationSeparately(t *testing.T) {
	for _, prior := range []serviceState{{State: "active", Boot: "enabled"}, {State: "active", Boot: "disabled"}, {State: "failed", Boot: "enabled"}, {State: "inactive", Boot: "enabled"}, {State: "inactive", Boot: "disabled"}} {
		t.Run(prior.State+"/"+prior.Boot, func(t *testing.T) {
			s, _ := launchdOwnedFixture(t)
			i := s.installation
			if prior.Boot == "disabled" {
				if err := os.Remove(i.Fragment); err != nil {
					t.Fatal(err)
				}
			}
			oldOutput, oldControl := launchdOutput, launchdControl
			t.Cleanup(func() { launchdOutput = oldOutput; launchdControl = oldControl })
			missing := missingLaunchdFixture(t, i.Unit)
			launchdOutput = func(binary string, args ...string) ([]byte, error) {
				if args[len(args)-1] == launchdDomain(i) {
					return []byte("domain"), nil
				}
				return nil, missing
			}
			var actions []string
			launchdControl = func(args ...string) error {
				actions = append(actions, args[0])
				if len(args) != 3 || args[2] != launchdTemplate(i) {
					return fmt.Errorf("rollback did not bootstrap the retained template: %v", args)
				}
				return nil
			}
			if err := restoreDarwinService(s, prior, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			if (len(actions) == 1) != (prior.State == "active" || prior.State == "failed") {
				t.Fatal(prior, actions)
			}
			_, err := os.Stat(i.Fragment)
			if (err == nil) != (prior.Boot == "enabled") {
				t.Fatal("rollback changed login registration", prior, err)
			}
		})
	}
}

func TestLaunchdRuntimeTransactionRecovery(t *testing.T) {
	for _, candidateActive := range []bool{false, true} {
		t.Run(fmt.Sprintf("candidate-active=%t", candidateActive), func(t *testing.T) {
			p, service := launchdSetupFixture(t)
			var diagnostic bytes.Buffer
			verify := func(p paths, c config) error { _, err := selectedStatusRoots(p.rootCertificate()); return err }
			if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, &diagnostic, verify); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			previousSource := readTestFile(t, p.config)
			previousGenerated := readTestFile(t, p.generatedPath())
			previousActive, err := committedAdaptedConfig(p, &diagnostic)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := readConfig(p.config)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Routes = append(cfg.Routes, route{Hostname: "recovered.sandbar.localhost", Upstream: "http://127.0.0.1:18000"})
			candidateSource, err := configBytes(cfg)
			if err != nil {
				t.Fatal(err)
			}
			record, err := readSetupRecord(p)
			if err != nil {
				t.Fatal(err)
			}
			generated, err := renderInstalledRoutes(cfg, record.SocketPlan.IPv6)
			if err != nil {
				t.Fatal(err)
			}
			candidateGenerated := []byte(generated)
			candidateJSON, err := installedCandidate(p, candidateGenerated, cfg, io.Discard, &diagnostic)
			if err != nil {
				t.Fatal(err, diagnostic.String())
			}
			for _, active := range [][]byte{previousActive, candidateJSON} {
				if !bytes.Contains(active, []byte("fd/100")) || !bytes.Contains(active, []byte("fdgram/104")) {
					t.Fatalf("active configuration lacks inherited listeners: %s", active)
				}
			}
			tx := transaction{Version: 1, Phase: "prepared", Reload: true, PreviousSource: previousSource, CandidateSource: candidateSource, PreviousGenerated: previousGenerated, CandidateGenerated: candidateGenerated, PreviousActive: previousActive, CandidateActive: candidateJSON}
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
			// A load can stop after publishing generated routes and before source publication.
			if err := p.writeFile(p.generatedPath(), candidateGenerated); err != nil {
				t.Fatal(err)
			}
			active := previousActive
			wantSource, wantGenerated := previousSource, previousGenerated
			if candidateActive {
				active = candidateJSON
				wantSource, wantGenerated = candidateSource, candidateGenerated
			}
			transactionAdmin(t, p, string(active))
			service.State = serviceState{State: "active", Boot: "enabled"}
			if err := withLock(p, func() error { return recoverTransaction(p, &diagnostic) }); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			if !bytes.Equal(wantSource, readTestFile(t, p.config)) || !bytes.Equal(wantGenerated, readTestFile(t, p.generatedPath())) {
				t.Fatal("recovery selected wrong committed files")
			}
			if _, err := os.Stat(p.file("transaction")); !os.IsNotExist(err) {
				t.Fatal("recovery retained journal", err)
			}
			recovered, err := committedAdaptedConfig(p, &diagnostic)
			if err != nil {
				t.Fatal(err)
			}
			if !jsonEqual(active, recovered) {
				t.Fatal("numeric versus descriptor configuration drift after recovery")
			}
			committed, err := readConfig(p.config)
			if err != nil {
				t.Fatal(err)
			}
			var status bytes.Buffer
			if err := configurationStatus(committed, p, active, nil, &status, &diagnostic); err != nil {
				t.Fatal(err, status.String(), diagnostic.String())
			}
			if !strings.Contains(status.String(), "Configuration: current") {
				t.Fatal(status.String())
			}
		})
	}
}

func TestRecordedDarwinInstallationSelection(t *testing.T) {
	for _, scenario := range []string{"missing", "old", "new", "identity mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			selected, _ := launchdOwnedFixture(t)
			i := selected.installation
			old := *i
			old.ID = "homebrew-launchd-v1"
			old.Unit = "sh.brew.caddy"
			old.CLI = ""
			old.Fragment = filepath.Join(filepath.Dir(i.Fragment), "sh.brew.caddy.plist")
			record, err := readSetupRecord(installedPaths(i))
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing":
				if err := os.Remove(filepath.Join(i.State, "setup.json")); err != nil {
					t.Fatal(err)
				}
			case "old":
				record.Identity = old.identity()
				record.SocketPlan = nil
			case "identity mismatch":
				changed := *i
				changed.Binary = "/changed/caddy"
				record.Identity = changed.identity()
			}
			if scenario != "missing" {
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(i.State, "setup.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			actual, err := recordedDarwinInstallation(&old, "/fixture/brew")
			if scenario == "identity mismatch" {
				if err == nil || !strings.Contains(err.Error(), "differs from setup") {
					t.Fatal(actual, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario != "new" {
				if actual != &old || actual.ID != "homebrew-launchd-v1" {
					t.Fatal("old setup silently migrated", actual)
				}
				return
			}
			if actual.identity() != i.identity() || actual.CLI != "/custom/bin/sandbar" {
				t.Fatal("saved selection changed", actual)
			}
			service, ok := actual.Service.(*launchdService)
			if !ok || service.old.installation != &old || service.old.brew != "/fixture/brew" {
				t.Fatal("wrong selected service", actual.Service)
			}
		})
	}
}

func TestLaunchdServiceValidatesConvertedCandidate(t *testing.T) {
	p, _ := launchdSetupFixture(t)
	var out, diagnostic bytes.Buffer
	verify := func(p paths, c config) error { _, err := selectedStatusRoots(p.rootCertificate()); return err }
	if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, &diagnostic, verify); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	service := &launchdService{installation: p.installed}
	p.installed.Service = service
	// No job or descriptors exist. Real Caddy validates the exact FD JSON anyway.
	if err := service.Validate(&out, &diagnostic); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	if !strings.Contains(out.String(), "Valid configuration") {
		t.Fatal(out.String(), diagnostic.String())
	}
	candidate := p.file("validation/Caddyfile")
	data := readTestFile(t, candidate)
	data = append(data, []byte("\nhttp://extra.localhost:19090 {\nbind fd/999\nrespond extra\n}\n")...)
	if err := os.WriteFile(candidate, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.Validate(io.Discard, &diagnostic); err == nil || !strings.Contains(err.Error(), "unowned Caddy descriptor") {
		t.Fatal("accepted unknown descriptor", err, diagnostic.String())
	}
}

func TestLaunchdSocketPlanRejectsChangedEntries(t *testing.T) {
	s, plan := launchdOwnedFixture(t)
	plan.IPv6 = true
	original := launchdFixtureOutput(s.installation, plan)
	firstHTTP := bytes.Index(original, []byte("\t\t\"HTTP\" = {"))
	endHTTP := firstHTTP + bytes.Index(original[firstHTTP:], []byte("\n\t\t}\n")) + len("\n\t\t}\n")
	missingHTTPv6 := append(append([]byte{}, original[:firstHTTP]...), original[endHTTP:]...)
	duplicateHTTPSv4 := bytes.Replace(original, []byte("node name = ::1"), []byte("node name = 127.0.0.1"), 1)
	duplicateHTTPSv4 = bytes.Replace(duplicateHTTPSv4, []byte("family = ipv6"), []byte("family = ipv4"), 1)
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"missing IPv6 entry", missingHTTPv6},
		{"duplicate IPv4 entry", duplicateHTTPSv4},
		{"wildcard IPv4", bytes.Replace(original, []byte("node name = 127.0.0.1"), []byte("node name = 0.0.0.0"), 1)},
		{"wildcard IPv6", bytes.Replace(original, []byte("node name = ::1"), []byte("node name = ::"), 1)},
		{"wrong family", bytes.Replace(original, []byte("family = ipv6"), []byte("family = ipv4"), 1)},
		{"old UDP spelling", bytes.Replace(original, []byte("type = datagram"), []byte("type = dgram"), 1)},
		{"extra descriptor", bytes.Replace(original, []byte("42 (no bytes to read)"), []byte("42 (no bytes to read)\n\t\t\t\t99 (no bytes to read)"), 1)},
		{"missing descriptor", bytes.Replace(original, []byte("42 (no bytes to read)"), nil, 1)},
		{"invalid descriptor", bytes.Replace(original, []byte("42 (no bytes to read)"), []byte("invalid descriptor"), 1)},
		{"incomplete definitions", original[:len(original)-len("\t}\n")]},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := checkLoadedSocketPlan(test.data, plan); err == nil {
				t.Fatal("accepted changed launchd socket definition")
			}
		})
	}
	plan.IPv6 = false
	if err := checkLoadedSocketPlan(original, plan); err == nil {
		t.Fatal("IPv4-only plan accepted IPv6 entries")
	}
}

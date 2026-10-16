package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestDarwinFailedRestartRestoresSocketJob(t *testing.T) {
	for _, admin := range []string{"absent", "refusing"} {
		t.Run(admin, func(t *testing.T) {
			p, fixture := launchdSetupFixture(t)
			httpPort, httpsPort := freePorts(t)
			var diagnostic bytes.Buffer
			verify := func(p paths, c config) error {
				_, err := selectedStatusRoots(p.rootCertificate())
				return err
			}
			if err := setupDarwin(p, setupOptions{Machine: "fixture", HTTPPort: &httpPort, HTTPSPort: &httpsPort}, io.Discard, &diagnostic, verify); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			fixture.State = serviceState{State: "inactive", Boot: "disabled"}
			if err := withLock(p, func() error {
				return changeRoutes(p, "add", []string{"saved.sandbar.localhost", "8000"}, io.Discard, &diagnostic)
			}); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			i := p.installed
			i.Service = &launchdService{installation: i}
			record, err := readSetupRecord(p)
			if err != nil || record.SocketPlan == nil {
				t.Fatal(record, err)
			}
			oldOutput, oldControl := launchdOutput, launchdControl
			t.Cleanup(func() { launchdOutput = oldOutput; launchdControl = oldControl })
			loaded, running := true, false
			missing := missingLaunchdFixture(t, i.Unit)
			launchdOutput = func(binary string, args ...string) ([]byte, error) {
				if args[len(args)-1] == launchdDomain(i) {
					return []byte("domain"), nil
				}
				if !loaded {
					return nil, missing
				}
				data := launchdFixtureOutput(i, *record.SocketPlan)
				if !running {
					data = bytes.Replace(data, []byte("state = running"), []byte("state = waiting"), 1)
				}
				return data, nil
			}
			var actions []string
			var command *exec.Cmd
			var logs bytes.Buffer
			t.Cleanup(func() {
				if command != nil && command.Process != nil {
					if err := command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
						t.Error(err)
					}
					if err := command.Wait(); err != nil {
						t.Errorf("test Caddy: %v\n%s", err, logs.String())
					}
				}
			})
			launchdControl = func(args ...string) error {
				actions = append(actions, args[0])
				switch args[0] {
				case "bootout":
					loaded = false
				case "bootstrap":
					if loaded {
						return errors.New("duplicate launchd job")
					}
					if !bytes.Equal(readTestFile(t, i.Fragment), readTestFile(t, launchdTemplate(i))) {
						return errors.New("login registration was not restored")
					}
					// Simulate launchd control. Caddy uses isolated high ports and storage.
					command = exec.Command(i.Binary, "run", "--config", i.Config, "--adapter", "caddyfile")
					command.Env = installedCaddyEnv(i)
					command.Stdout, command.Stderr = &logs, &logs
					if err := command.Start(); err != nil {
						return err
					}
					loaded, running = true, true
				default:
					return fmt.Errorf("unexpected launchd action %v", args)
				}
				return nil
			}
			state, err := i.Service.Inspect()
			if err != nil || state.State != "failed" || state.Sockets != "owned by launchd" {
				t.Fatal("fixture did not retain failed socket job", state, err)
			}
			if admin == "refusing" {
				refusingRestartAdmin(t, p)
			}
			before := map[string][]byte{}
			for _, path := range []string{p.config, p.generatedPath(), p.rootCertificate(), i.Config, i.Globals, launchdTemplate(i)} {
				before[path] = readTestFile(t, path)
			}
			var out bytes.Buffer
			if err := withLock(p, func() error { return startInstalled(p, &out, &diagnostic) }); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			if fmt.Sprint(actions) != "[bootout bootstrap]" || !strings.Contains(out.String(), "saved.sandbar.localhost") {
				t.Fatal(actions, out.String())
			}
			state, err = i.Service.Inspect()
			if err != nil || state.State != "active" || state.Boot != "enabled" || state.Sockets != "owned by launchd" {
				t.Fatal("restart did not restore socket registration", state, err)
			}
			for path, data := range before {
				if !bytes.Equal(data, readTestFile(t, path)) {
					t.Fatal("restart changed saved state", path)
				}
			}
		})
	}
}

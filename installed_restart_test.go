package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

type restartFixtureService struct {
	fakeService
	afterStop func()
}

func (s *restartFixtureService) Control(action string, out, errOut io.Writer) error {
	if err := s.fakeService.Control(action, out, errOut); err != nil {
		return err
	}
	if action == "stop" && s.afterStop != nil {
		s.afterStop()
	}
	return nil
}

func refusingRestartAdmin(t *testing.T, p paths) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: p.file("admin.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readActiveConfig(p); !isRouterStopped(err) {
		t.Fatal("fixture endpoint did not refuse connections", err)
	}
}

func TestInstalledFailedRestartRefusesUncertainState(t *testing.T) {
	for _, test := range []struct {
		name, want string
		actions    string
	}{
		{"responding admin", "admin endpoint responds", "[]"},
		{"invalid admin", "invalid configuration JSON", "[]"},
		{"denied service", "inspection denied", "[]"},
		{"stop failure", "stop failed Caddy", "[stop]"},
		{"still failed", "after shutdown with service state failed", "[stop]"},
		{"inspection after stop", "inspection denied", "[stop]"},
		{"admin after stop", "admin endpoint still responds", "[stop]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, base := testInstalledPaths(t)
			service := &restartFixtureService{fakeService: *base}
			service.State.State = "failed"
			p.installed.Service = service
			switch test.name {
			case "responding admin":
				transactionAdmin(t, p, `{"still":"active"}`)
			case "invalid admin":
				transactionAdmin(t, p, `invalid`)
			case "denied service":
				service.InspectErr = errors.New("inspection denied")
			case "stop failure":
				service.ControlErr = errors.New("shutdown denied")
			case "inspection after stop":
				service.afterStop = func() { service.InspectErr = errors.New("inspection denied") }
			case "admin after stop":
				service.afterStop = func() {
					service.State.State = "inactive"
					transactionAdmin(t, p, `{"still":"active"}`)
				}
			}
			if err := p.writeFile(p.generatedPath(), []byte("saved routes")); err != nil {
				t.Fatal(err)
			}
			if err := p.writeFile(p.rootCertificate(), []byte("saved root")); err != nil {
				t.Fatal(err)
			}
			before := map[string][]byte{}
			for _, path := range []string{p.config, p.generatedPath(), p.rootCertificate()} {
				before[path] = readTestFile(t, path)
			}
			err := withLock(p, func() error { return startInstalled(p, io.Discard, io.Discard) })
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("restart error = %v, want %q", err, test.want)
			}
			if fmt.Sprint(service.Actions) != test.actions {
				t.Fatal("unexpected service actions", service.Actions)
			}
			for path, data := range before {
				if !bytes.Equal(data, readTestFile(t, path)) {
					t.Fatal("restart changed saved file", path)
				}
			}
			if _, err := os.Stat(p.file("transaction")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("restart published recovery state", err)
			}
		})
	}
}

func TestInstalledFailedRestartPreservesUnresolvedRecovery(t *testing.T) {
	p, service := testInstalledPaths(t)
	service.State.State = "failed"
	previous := readTestFile(t, p.config)
	tx := transaction{Version: 1, Phase: "prepared", Reload: true,
		PreviousSource: previous, CandidateSource: append(append([]byte{}, previous...), '\n'),
		PreviousGenerated: []byte("old"), CandidateGenerated: []byte("new"),
		PreviousActive: []byte(`{"old":true}`), CandidateActive: []byte(`{"new":true}`)}
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
	journal := readTestFile(t, p.file("transaction/journal.json"))
	err := withLock(p, func() error { return startInstalled(p, io.Discard, io.Discard) })
	if err == nil || !strings.Contains(err.Error(), "cannot establish active router configuration") {
		t.Fatal(err)
	}
	if len(service.Actions) != 0 || !bytes.Equal(journal, readTestFile(t, p.file("transaction/journal.json"))) || !bytes.Equal(previous, readTestFile(t, p.config)) || !bytes.Equal(tx.PreviousGenerated, readTestFile(t, p.generatedPath())) {
		t.Fatal("restart bypassed unresolved recovery", service.Actions)
	}
}

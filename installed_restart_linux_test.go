package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type linuxRestartFixtureService struct{ fakeService }

func (s *linuxRestartFixtureService) Control(action string, out, errOut io.Writer) error {
	if err := s.fakeService.Control(action, out, errOut); err != nil {
		return err
	}
	switch action {
	case "stop":
		s.State.State = "inactive"
	case "start":
		s.State.State = "active"
	}
	return nil
}

func TestLinuxFailedRestartPreservesRoutesAndCA(t *testing.T) {
	requireIntegration(t)
	for _, admin := range []string{"absent", "refusing"} {
		t.Run(admin, func(t *testing.T) {
			p, _ := testInstalledPaths(t)
			binary, err := exec.LookPath("caddy")
			if err != nil {
				t.Fatal(err)
			}
			i := p.installed
			i.Binary = binary
			service := &linuxRestartFixtureService{fakeService{State: serviceState{State: "failed", Boot: "enabled"}}}
			i.Service = service
			c := config{Version: 3, Machine: "fixture", HTTPPort: 80, HTTPSPort: 443, Routes: []route{{Hostname: "saved.sandbar.localhost", Upstream: "http://127.0.0.1:8000"}}}
			source, err := configBytes(c)
			if err != nil {
				t.Fatal(err)
			}
			address, err := p.adminAddress()
			if err != nil {
				t.Fatal(err)
			}
			globals := []byte(renderInstalledGlobals(c, address, "", ""))
			routes, err := renderInstalledRoutes(c, false)
			if err != nil {
				t.Fatal(err)
			}
			composition, err := composeInstalledConfig(i.Config, nil, i.Globals, p.generatedPath(), globals, []byte(routes), false)
			if err != nil {
				t.Fatal(err)
			}
			for path, data := range map[string][]byte{p.config: source, i.Config: composition.Top, i.Globals: globals, p.generatedPath(): []byte(routes)} {
				if err := p.writeFile(path, data); err != nil {
					t.Fatal(err)
				}
			}
			_, manifest, err := stageInstalledCandidate(i.Config, i.Globals, p.generatedPath(), []byte(routes))
			if err != nil {
				t.Fatal(err)
			}
			record, err := json.Marshal(setupRecord{Identity: i.identity(), Manifest: manifest})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.writeFile(p.file("setup.json"), record); err != nil {
				t.Fatal(err)
			}
			root := readTestFile(t, storedRoot(t, p))
			if err := p.writeFile(p.rootCertificate(), root); err != nil {
				t.Fatal(err)
			}
			if admin == "refusing" {
				refusingRestartAdmin(t, p)
			}
			var out, diagnostic bytes.Buffer
			if err := withLock(p, func() error { return startInstalled(p, &out, &diagnostic) }); err != nil {
				t.Fatal(err, diagnostic.String())
			}
			if fmt.Sprint(service.Actions) != "[stop start]" || service.State.State != "active" || service.State.Boot != "enabled" || !strings.Contains(out.String(), "saved.sandbar.localhost") {
				t.Fatal(service.Actions, service.State, out.String())
			}
			if !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) || !bytes.Equal(composition.Top, readTestFile(t, i.Config)) || !bytes.Equal(globals, readTestFile(t, i.Globals)) {
				t.Fatal("restart changed saved configuration or CA")
			}
			generated := readTestFile(t, p.generatedPath())
			if !bytes.Contains(generated, []byte("saved.sandbar.localhost")) || !bytes.Contains(generated, []byte("127.0.0.1:8000")) {
				t.Fatal("restart lost saved route")
			}
			if _, err := os.Stat(p.file("transaction")); !os.IsNotExist(err) {
				t.Fatal("restart retained transaction", err)
			}
		})
	}
}

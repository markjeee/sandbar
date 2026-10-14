//go:build darwin

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func TestDarwinTeleportPublication(t *testing.T) {
	p, service := darwinSetupFixture(t)
	unrelated := []byte("http://unrelated.localhost:19090 {\n bind 127.0.0.1\n respond unrelated\n}\n")
	if err := os.WriteFile(p.installed.Config, unrelated, 0600); err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	if err := setupDarwin(p, setupOptions{Machine: "local"}, io.Discard, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	service.State = serviceState{State: "inactive", Boot: "disabled"}
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	c.Teleports = []teleportDestination{routingDestination(t, "remote", 19999)}
	if err := publishTeleportTestConfig(t, p, c); err != nil {
		t.Fatal(err)
	}
	adapted, err := adaptCaddyfile(p, p.installed.Config, &diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	service.activeFile = transactionAdmin(t, p, string(adapted))
	service.State = serviceState{State: "active", Boot: "enabled"}
	source, generated := readTestFile(t, p.config), readTestFile(t, p.generatedPath())
	global, top, root := readTestFile(t, p.installed.Globals), readTestFile(t, p.installed.Config), readTestFile(t, p.rootCertificate())
	service.ValidateErr = errors.New("rejected destination removal")
	c.Teleports = nil
	if err := publishTeleportTestConfig(t, p, c); err == nil {
		t.Fatal("accepted rejected validation")
	}
	service.ValidateErr = nil
	service.failAction = "reload"
	if err := publishTeleportTestConfig(t, p, c); err == nil {
		t.Fatal("accepted rejected reload")
	}
	if !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(generated, readTestFile(t, p.generatedPath())) || !bytes.Equal(global, readTestFile(t, p.installed.Globals)) || !bytes.Equal(top, readTestFile(t, p.installed.Config)) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("failed destination removal changed accepted state")
	}
	if _, err := os.Stat(p.file("transaction")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("ordinary failed reload retained unresolved journal", err)
	}
	service.failAction = ""
	if err := publishTeleportTestConfig(t, p, c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readTestFile(t, p.installed.Config), unrelated) || !bytes.Equal(global, readTestFile(t, p.installed.Globals)) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("destination removal changed unrelated configuration or CA")
	}
}

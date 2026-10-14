package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func routingDestination(t *testing.T, machine string, localPort int) teleportDestination {
	t.Helper()
	_, root := statusCertificate(t, machineHostname(machine))
	return teleportDestination{Machine: machine, Host: "127.0.0.1", User: "developer", Port: 22, HTTPSPort: 18443, LocalPort: localPort, RootPEM: string(root)}
}

func TestTeleportNamespace(t *testing.T) {
	pattern := regexp.MustCompile(teleportNamespacePattern("remote"))
	for _, name := range []string{"sandbar-remote.localhost", "app.sandbar-remote.localhost", "api.app.sandbar-remote.localhost", "APP.sandbar-remote.localhost"} {
		if !pattern.MatchString(name) {
			t.Errorf("denied %s", name)
		}
	}
	for _, name := range []string{"sandbar-other.localhost", "app.sandbar-remote.localhost.evil", "-app.sandbar-remote.localhost", "app-.sandbar-remote.localhost", "a..sandbar-remote.localhost", "*.sandbar-remote.localhost", strings.Repeat("a", 64) + ".sandbar-remote.localhost"} {
		if pattern.MatchString(name) {
			t.Errorf("permitted %s", name)
		}
	}
}

func TestTeleportInstalledCompositionAndRuntime(t *testing.T) {
	requireIntegration(t)
	c := config{Version: 3, Machine: "local", HTTPPort: 80, HTTPSPort: 443, Teleports: []teleportDestination{routingDestination(t, "remote", 19999)}}
	dir := shortHome(t)
	top, global, routes := filepath.Join(dir, "top"), filepath.Join(dir, "global"), filepath.Join(dir, "routes")
	source := []byte("{\n email developer@example.test\n auto_https disable_redirects\n}\nhttps://unrelated.localhost:443 {\n bind 127.0.0.1\n tls internal\n respond unrelated\n}\n")
	if err := os.WriteFile(top, source, 0600); err != nil {
		t.Fatal(err)
	}
	rendered, err := renderInstalledRoutes(c, true)
	if err != nil {
		t.Fatal(err)
	}
	admin := "unix/" + filepath.Join(dir, "admin.sock")
	composed, err := composeInstalledConfig(top, source, global, routes, []byte(renderInstalledGlobals(c, admin, "", "")), []byte(rendered), false)
	if err != nil {
		t.Fatal(err)
	}
	p := testPaths(t, dir)
	if err := withLock(p, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, "candidate")
	if err := os.WriteFile(candidate, composed.Candidate, 0600); err != nil {
		t.Fatal(err)
	}
	adapted, err := adaptCaddyfile(p, candidate, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkInstalledAdapted(adapted, c, admin); err != nil {
		t.Fatalf("%v\n%s", err, adapted)
	}
	runtime, err := convertSocketRuntime(adapted, socketPlan{80, 443, true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(runtime, []byte("fd/100")) || !bytes.Contains(runtime, []byte("fdgram/104")) || !bytes.Contains(runtime, []byte(teleportCertificatePath)) {
		t.Fatalf("missing inherited listener/permission route: %s", runtime)
	}
	runtimePath := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(runtimePath, runtime, 0600); err != nil {
		t.Fatal(err)
	}
	if err := invokeCaddy(caddyEnv(p), nil, io.Discard, os.Stderr, "validate", "--config", runtimePath); err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	if err := json.Unmarshal(adapted, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(runtime, &after); err != nil {
		t.Fatal(err)
	}
	beforeTLS, _ := json.Marshal(before["apps"].(map[string]any)["tls"])
	afterTLS, _ := json.Marshal(after["apps"].(map[string]any)["tls"])
	if !jsonEqual(beforeTLS, afterTLS) {
		t.Fatal("socket conversion changed TLS policies")
	}
	for _, altered := range [][]byte{
		bytes.Replace(adapted, []byte(teleportPermissionEndpoint(c)), []byte("http://127.0.0.1:19990/foreign"), 1),
		bytes.Replace(adapted, []byte(`"on_demand":true`), []byte(`"on_demand":false`), 1),
	} {
		if checkInstalledAdapted(altered, c, admin) == nil {
			t.Fatal("accepted conflicting TLS policy")
		}
	}
	// An empty registration list retains the fixed global endpoint, but no
	// fallback certificate policy or destination transport remains.
	c.Teleports = nil
	rendered, err = renderInstalledRoutes(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "on_demand") || strings.Contains(rendered, "trust_der") {
		t.Fatal("removed destination retained policy or trust")
	}
	if err := os.WriteFile(candidate, []byte("{\n"+renderInstalledGlobals(c, admin, "", "")+"}\n"+rendered), 0600); err != nil {
		t.Fatal(err)
	}
	adapted, err = adaptCaddyfile(p, candidate, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkInstalledAdapted(adapted, c, admin); err != nil {
		t.Fatal(err)
	}
}

func TestTeleportAmbiguousPublicationRetainsRecovery(t *testing.T) {
	p := initialized(t)
	fakeCaddy(t)
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	c.Teleports = []teleportDestination{routingDestination(t, "remote", 19999)}
	if err := publishTeleportTestConfig(t, p, c); err != nil {
		t.Fatal(err)
	}
	source, generated := readTestFile(t, p.config), readTestFile(t, p.generatedPath())
	transactionAdmin(t, p, `{"test":"previous"}`)
	t.Setenv("FAKE_RELOAD_EXIT", "24")
	t.Setenv("FAKE_ACTIVE_AFTER_RELOAD", `{"unknown":true}`)
	c.Teleports = nil
	if err := publishTeleportTestConfig(t, p, c); err == nil {
		t.Fatal("accepted ambiguous destination removal")
	}
	if !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(generated, readTestFile(t, p.generatedPath())) {
		t.Fatal("ambiguous publication changed accepted files")
	}
	if _, err := os.Stat(p.file("transaction")); err != nil {
		t.Fatal("lost unresolved recovery evidence", err)
	}
	if !bytes.Equal(source, readTestFile(t, p.file("transaction/previous.config.json"))) {
		t.Fatal("recovery lost previous destination and trust")
	}
}

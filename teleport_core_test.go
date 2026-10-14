package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func coreConfig(t *testing.T) config {
	t.Helper()
	p := testPaths(t, shortHome(t))
	root := string(readTestFile(t, storedRoot(t, p)))
	return config{Version: 3, Machine: "local", HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}, Teleports: []teleportDestination{{Machine: "remote", Host: "127.0.0.1", User: "developer", Port: 22, HTTPSPort: 18443, LocalPort: 19000, RemoteBin: "/tmp/peer/sandbar", RemoteHome: "/tmp/peer/home", RootPEM: root}}}
}

func TestTeleportVersion3Config(t *testing.T) {
	c := coreConfig(t)
	c.Routes = []route{{"API.App.sandbar.localhost", "8000"}}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	data, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeConfig(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("%+v %v", got, err)
	}
	if !strings.Contains(string(data), `"teleports": [`) {
		t.Fatal(string(data))
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.Machine = "bad.name" }, func(c *config) { c.Machine = strings.Repeat("a", 56) },
		func(c *config) { c.Teleports[0].Machine = "local" }, func(c *config) { c.Teleports = append(c.Teleports, c.Teleports[0]) },
		func(c *config) {
			c.Teleports[0].RootPEM += "\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
		},
		func(c *config) { c.Teleports[0].Host = "host\nProxyCommand evil" }, func(c *config) { c.Teleports[0].LocalPort = c.HTTPSPort },
		func(c *config) { c.Teleports[0].RemoteHome = "relative/home" }, func(c *config) { c.Teleports[0].Port = 65536 },
	} {
		bad := coreConfig(t)
		mutate(&bad)
		if err := bad.validate(); err == nil {
			t.Fatalf("accepted invalid config %+v", bad)
		}
	}
	for _, input := range []string{
		`{"version":3,"machine":"local","http_port":80,"https_port":443,"routes":[]}`,
		`{"version":3,"machine":"local","http_port":80,"https_port":443,"routes":[],"teleports":null}`,
		`{"version":3,"machine":"local","http_port":80,"https_port":443,"routes":null,"teleports":[]}`,
		`{"version":2,"machine":"local","http_port":80,"https_port":443,"routes":[]}`,
	} {
		if _, err := decodeConfig(strings.NewReader(input)); err == nil {
			t.Fatal("accepted", input)
		}
	}
	empty := config{Version: 3, Machine: "local", HTTPPort: 80, HTTPSPort: 443}
	encoded, _ := configBytes(empty)
	if !strings.Contains(string(encoded), `"routes": []`) || !strings.Contains(string(encoded), `"teleports": []`) {
		t.Fatal(string(encoded))
	}
}

func TestTeleportMachineSelection(t *testing.T) {
	for _, test := range []struct{ saved, requested, hostname, want string }{
		{"", "", "MARK-PRO4.example", "mark-pro4"}, {"", "Demo", "invalid hostname", "demo"},
		{"saved", "", "renamed.example", "saved"}, {"saved", "SAVED", "renamed.example", "saved"},
	} {
		got, err := selectMachine(test.saved, test.requested, test.hostname)
		if err != nil || got != test.want {
			t.Fatalf("%+v: %q %v", test, got, err)
		}
	}
	for _, test := range []struct{ saved, requested, hostname string }{
		{"saved", "different", "os"}, {"", "", "invalid_hostname"}, {"", "", ".empty"}, {"", "-invalid", "os"}, {"", "é", "os"},
	} {
		if _, err := selectMachine(test.saved, test.requested, test.hostname); err == nil {
			t.Fatal("accepted", test)
		}
	}
	if got := ownMachineHostname("api.app.sandbar.localhost", "mark-pro4"); got != "api.app.sandbar-mark-pro4.localhost" {
		t.Fatal(got)
	}
}

func TestTeleportInitUpgrade(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			p := testPaths(t, shortHome(t))
			if err := withLock(p, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			c := validConfig()
			c.HTTPPort, c.HTTPSPort = 18080, 18443
			if version == 2 {
				c = config{Version: 2, HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{{"app.sandbar.localhost", "8000"}, {"api.app.sandbar.localhost", "8001"}}}
			}
			old, _ := configBytes(c)
			if err := os.WriteFile(p.config, old, 0600); err != nil {
				t.Fatal(err)
			}
			generated := []byte("accepted old generated file\n")
			if err := os.WriteFile(p.file("Caddyfile"), generated, 0600); err != nil {
				t.Fatal(err)
			}
			root := readTestFile(t, storedRoot(t, p))
			fakeCaddy(t)
			t.Setenv("FAKE_VALIDATE_EXIT", "42")
			if code, _, _ := routeCommand(t, p, "init", "--machine", "saved"); code != 42 {
				t.Fatalf("validation failure code %d", code)
			}
			if !bytes.Equal(old, readTestFile(t, p.config)) || !bytes.Equal(generated, readTestFile(t, p.file("Caddyfile"))) {
				t.Fatal("failed validation changed files")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(p.config), "config.v"+string(rune('0'+version))+".backup.json")); !os.IsNotExist(err) {
				t.Fatal("failed validation created backup", err)
			}
			t.Setenv("FAKE_VALIDATE_EXIT", "")
			if code, _, errOut := routeCommand(t, p, "init", "--machine", "saved"); code != 0 {
				t.Fatal(errOut)
			}
			got, err := readConfig(p.config)
			if err != nil || got.Version != 3 || got.Machine != "saved" || got.HTTPPort != 18080 || got.HTTPSPort != 18443 {
				t.Fatalf("%+v %v", got, err)
			}
			before, err := decodeConfig(bytes.NewReader(old))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Routes, before.Routes) || len(got.Teleports) != 0 {
				t.Fatal("upgrade lost routes", got)
			}
			prefix := filepath.Join(filepath.Dir(p.config), "config.v"+string(rune('0'+version))+".backup")
			if !bytes.Equal(old, readTestFile(t, prefix+".json")) || !bytes.Equal(generated, readTestFile(t, prefix+".Caddyfile")) {
				t.Fatal("unmatched backups")
			}
			for _, path := range []string{prefix + ".json", prefix + ".Caddyfile"} {
				info, _ := os.Stat(path)
				if info.Mode().Perm() != 0600 {
					t.Fatal(path, info.Mode())
				}
			}
			if !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
				t.Fatal("upgrade changed CA")
			}
			accepted := readTestFile(t, p.config)
			if code, _, errOut := routeCommand(t, p, "init"); code != 0 {
				t.Fatal(errOut)
			}
			if code, _, _ := routeCommand(t, p, "init", "--machine", "renamed"); code == 0 {
				t.Fatal("changed established identity")
			}
			if !bytes.Equal(accepted, readTestFile(t, p.config)) {
				t.Fatal("repeated init rewrote source")
			}
		})
	}
}

func TestTeleportPreservesDestinationOnAppMutation(t *testing.T) {
	p := testPaths(t, shortHome(t))
	c := coreConfig(t)
	if err := withLock(p, func() error { return writeConfig(p.config, c) }); err != nil {
		t.Fatal(err)
	}
	fakeCaddy(t)
	for _, args := range [][]string{{"add", "app.sandbar.localhost", "8000"}, {"add", "--replace", "app.sandbar.localhost", "8001"}, {"rm", "app.sandbar.localhost"}} {
		if code, _, errOut := routeCommand(t, p, args...); code != 0 {
			t.Fatal(errOut)
		}
		got, err := readConfig(p.config)
		if err != nil || got.Version != 3 || got.Machine != c.Machine || !reflect.DeepEqual(got.Teleports, c.Teleports) {
			t.Fatalf("destination lost: %+v %v", got, err)
		}
	}
}

func TestTeleportMetadataReadOnly(t *testing.T) {
	p := testPaths(t, shortHome(t))
	c := config{Version: 3, Machine: "saved", HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}, Teleports: []teleportDestination{}}
	if err := writeConfig(p.config, c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeTeleportInfo(p, &out); err == nil {
		t.Fatal("metadata created missing CA")
	}
	root := readTestFile(t, storedRoot(t, p))
	source := readTestFile(t, p.config)
	rootInfo, _ := os.Stat(p.rootCertificate())
	sourceInfo, _ := os.Stat(p.config)
	out.Reset()
	if err := writeTeleportInfo(p, &out); err != nil {
		t.Fatal(err)
	}
	var got teleportInfo
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Protocol != 1 || got.Machine != "saved" || got.HTTPSPort != 18443 || got.RootPEM != string(root) {
		t.Fatalf("%+v", got)
	}
	if strings.Contains(out.String(), "PRIVATE") || !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("metadata changed or exposed private state")
	}
	rootAfter, _ := os.Stat(p.rootCertificate())
	sourceAfter, _ := os.Stat(p.config)
	if rootInfo.ModTime() != rootAfter.ModTime() || sourceInfo.ModTime() != sourceAfter.ModTime() {
		t.Fatal("metadata wrote selected files")
	}
	if _, err := os.Stat(p.file("router.lock")); !os.IsNotExist(err) {
		t.Fatal("metadata created lock")
	}
	c.Version = 2
	c.Machine = ""
	if err := p.writeFile(p.config, mustConfigBytes(t, c)); err != nil {
		t.Fatal(err)
	}
	if err := writeTeleportInfo(p, io.Discard); err == nil {
		t.Fatal("metadata accepted missing identity")
	}
}

func mustConfigBytes(t *testing.T, c config) []byte {
	t.Helper()
	data, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTeleportUpgradeRetainsPriorLegacyBackup(t *testing.T) {
	p := testPaths(t, shortHome(t))
	old := mustConfigBytes(t, validConfig())
	if err := withLock(p, func() error { return os.WriteFile(p.config, old, 0600) }); err != nil {
		t.Fatal(err)
	}
	fakeCaddy(t)
	if code, _, errOut := routeCommand(t, p, "add", "extra.sandbar.localhost", "8001"); code != 0 {
		t.Fatal(errOut)
	}
	version2 := readTestFile(t, p.config)
	generated := readTestFile(t, p.generatedPath())
	if code, _, errOut := routeCommand(t, p, "init", "--machine", "stable"); code != 0 {
		t.Fatal(errOut)
	}
	dir := filepath.Dir(p.config)
	if !bytes.Equal(old, readTestFile(t, filepath.Join(dir, "config.v1.backup.json"))) || !bytes.Equal(version2, readTestFile(t, filepath.Join(dir, "config.v2.backup.json"))) || !bytes.Equal(generated, readTestFile(t, filepath.Join(dir, "config.v2.backup.Caddyfile"))) {
		t.Fatal("Teleport upgrade replaced an earlier conversion backup")
	}
}

func TestTeleportEmptyMachineOption(t *testing.T) {
	for _, args := range [][]string{{"--home", shortHome(t), "init", "--machine", ""}, {"setup", "--machine", "", "--check"}} {
		if code, _, errOut := cli(t, args...); code == 0 || !strings.Contains(errOut, "--machine requires") {
			t.Fatalf("%v: %d %s", args, code, errOut)
		}
	}
}

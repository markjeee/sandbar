package main

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	syscall.Umask(0077)
	os.Exit(m.Run())
}

func validConfig() config {
	return config{Version: 1, Hostname: "netbox.sandbar.localhost", UpstreamPort: 8000, HTTPPort: 80, HTTPSPort: 443}
}

func cli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestConfigValidation(t *testing.T) {
	for _, hostname := range []string{"netbox.sandbar.localhost", "A.B.sandbar.localhost", "a-b.sandbar.localhost"} {
		c := validConfig()
		c.Hostname = hostname
		if err := c.validate(); err != nil {
			t.Fatal(err)
		}
		if c.Hostname != strings.ToLower(hostname) {
			t.Fatal(c.Hostname)
		}
	}
	for _, hostname := range []string{"sandbar.localhost", "evilsandbar.localhost", "a.sandbar.localhost.evil", "*.sandbar.localhost", "a.sandbar.localhost.", "http://a.sandbar.localhost", "a.sandbar.localhost:443", "a.sandbar.localhost/path", ".sandbar.localhost", "a..sandbar.localhost", "-a.sandbar.localhost", "a-.sandbar.localhost", "é.sandbar.localhost", "K.sandbar.localhost", "a_b.sandbar.localhost", strings.Repeat("a", 64) + ".sandbar.localhost", strings.Repeat("a.", 130) + "sandbar.localhost"} {
		t.Run(hostname, func(t *testing.T) {
			c := validConfig()
			c.Hostname = hostname
			if c.validate() == nil {
				t.Fatal("accepted invalid hostname")
			}
		})
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.Version = 3 }, func(c *config) { c.HTTPPort = 0 },
		func(c *config) { c.HTTPSPort = 65536 }, func(c *config) { c.UpstreamPort = -1 },
		func(c *config) { c.UpstreamPort = c.HTTPPort }, func(c *config) { c.UpstreamPort = c.HTTPSPort },
		func(c *config) { c.HTTPPort = c.HTTPSPort },
	} {
		c := validConfig()
		mutate(&c)
		if c.validate() == nil {
			t.Fatal("accepted invalid config", c)
		}
	}
	c := validConfig()
	c.HTTPPort = 1
	c.HTTPSPort = 65535
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	if validConfig().httpsURL() != "https://netbox.sandbar.localhost" || c.httpsURL() != "https://netbox.sandbar.localhost:65535" {
		t.Fatal("URL formatting")
	}
}

func TestReadConfig(t *testing.T) {
	data, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]string{
		"malformed": "{", "unknown": strings.Replace(string(data), "{", `{"extra":1,`, 1),
		"version": strings.Replace(string(data), `"version":1`, `"version":2`, 1),
		"missing": `{"version":1}`, "null": "null", "trailing": string(data) + " {}",
		"wrong type": strings.Replace(string(data), `"http_port":80`, `"http_port":"80"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readConfig(path); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}

func TestInit(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	args := []string{"--home", home, "init", "NETBOX.sandbar.localhost", "8000"}
	if code, out, errOut := cli(t, args...); code != 0 || !strings.Contains(out, filepath.Join(home, "config.json")) {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	p := testPaths(t, home)
	c, err := readConfig(p.config)
	if err != nil || !reflect.DeepEqual(c.Routes, []route{{"netbox.sandbar.localhost", "http://127.0.0.1:8000"}}) || c.Version != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	before, err := os.Stat(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := cli(t, args...); code != 0 || !strings.Contains(out, "already exists") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	after, err := os.Stat(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if before.ModTime() != after.ModTime() {
		t.Fatal("repeated init wrote configuration")
	}
	args[len(args)-1] = "8001"
	if code, _, _ := cli(t, args...); code == 0 {
		t.Fatal("accepted different existing config")
	}
	got, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Fatal("changed existing config")
	}
	for path, mode := range map[string]os.FileMode{home: 0700, p.state: 0700, p.config: 0600, p.file("router.lock"): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s mode %o", path, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(p.file("Caddyfile")); !os.IsNotExist(err) {
		t.Fatal("init generated Caddyfile")
	}
	if err := os.WriteFile(p.config, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := cli(t, args...); code == 0 {
		t.Fatal("replaced malformed existing config")
	}
	data := readTestFile(t, p.config)
	if string(data) != "broken" {
		t.Fatal("overwrote source")
	}
}

func TestInitOverridesAndInvalidArguments(t *testing.T) {
	home := t.TempDir()
	if code, _, errOut := cli(t, "--home", home, "init", "--http-port", "8080", "--https-port", "8443", "netbox.sandbar.localhost", "8000"); code != 0 {
		t.Fatal(errOut)
	}
	p := testPaths(t, home)
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPPort != 8080 || c.HTTPSPort != 8443 {
		t.Fatal(c)
	}
	for _, args := range [][]string{
		{"init", "one"}, {"init", "netbox.sandbar.localhost", "abc"}, {"init", "bad", "8000"},
		{"init", "--http-port", "8000", "netbox.sandbar.localhost", "8000"},
		{"init", "netbox.sandbar.localhost", "8000", "--http-port", "8080"},
		{"start", "extra"}, {"stop", "extra"}, {"unknown"},
	} {
		home := filepath.Join(t.TempDir(), "absent")
		if code, _, _ := cli(t, append([]string{"--home", home}, args...)...); code == 0 {
			t.Fatal("accepted", args)
		}
		if _, err := os.Stat(filepath.Join(home, "config.json")); !os.IsNotExist(err) {
			t.Fatal("wrote invalid config")
		}
	}
}

func TestPaths(t *testing.T) {
	base := t.TempDir()
	t.Setenv("HOME", base)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("SANDBAR_HOME", "")
	var p paths
	envHome := filepath.Join(base, "env")
	flagHome := filepath.Join(base, "flag")
	t.Setenv("SANDBAR_HOME", envHome)
	for _, args := range [][]string{{"init", "netbox.sandbar.localhost", "8000"}, {"--home", flagHome, "init", "netbox.sandbar.localhost", "8000"}} {
		if code, _, errOut := cli(t, args...); code != 0 {
			t.Fatal(errOut)
		}
	}
	for _, home := range []string{envHome, flagHome} {
		if _, err := os.Stat(filepath.Join(home, "config.json")); err != nil {
			t.Fatal(err)
		}
	}
	p = testPaths(t, strings.Repeat("x", 120))
	if _, err := p.adminAddress(); err == nil || !strings.Contains(err.Error(), "shorter path") {
		t.Fatal(err)
	}
}

func TestHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"help"}, {"init", "--help"}, {"--version"}} {
		if code, out, errOut := cli(t, args...); code != 0 || out == "" {
			t.Fatalf("%d %s %s", code, out, errOut)
		}
	}
}

func TestSocketPathSyntax(t *testing.T) {
	for _, home := range []string{"/tmp/{$HOME}", "/tmp/{env.HOME}", "/tmp/name|0700", "/tmp/name\tpart", "/tmp/name\npart"} {
		p, err := resolvePaths(home)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.adminAddress(); err == nil {
			t.Fatalf("accepted Caddy syntax in path %q", home)
		}
	}
}

func TestReadConfigNormalizesHostname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c := validConfig()
	c.Hostname = "NETBOX.SANDBAR.LOCALHOST"
	if err := writeConfig(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := readConfig(path)
	if err != nil || got.Hostname != "netbox.sandbar.localhost" {
		t.Fatalf("%+v %v", got, err)
	}
}

// Successful decoding must produce a stable configuration and an unambiguous URL.
func FuzzConfig(f *testing.F) {
	for _, input := range []string{
		`{"version":1,"hostname":"NETBOX.sandbar.localhost","upstream_port":8000,"http_port":80,"https_port":443}`,
		`{"version":1,"hostname":"a.b.sandbar.localhost","upstream_port":8000,"http_port":8080,"https_port":8443}`,
		`null`, `{}`, `{`, `{"version":2}`, `{"extra":true}`, `[]`,
	} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		c, err := decodeConfig(bytes.NewReader(input))
		if err != nil {
			return
		}
		encoded, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip, err := decodeConfig(bytes.NewReader(encoded))
		if err != nil || !reflect.DeepEqual(roundTrip, c) {
			t.Fatalf("unstable config round trip: %+v, %v", roundTrip, err)
		}
		if len(c.Routes) == 0 {
			return
		}
		target, err := url.Parse(c.httpsURL())
		if err != nil {
			t.Fatal(err)
		}
		if target.Scheme != "https" || target.Hostname() != c.Routes[0].Hostname || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
			t.Fatalf("configuration changed URL authority: %q", c.httpsURL())
		}
	})
}

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestSetupArgumentsFailBeforeSystemInspection(t *testing.T) {
	for _, args := range [][]string{{"setup"}, {"setup", "--user", "root"}, {"setup", "--user", "this-account-does-not-exist-sandbar"}, {"--home", "/tmp/must-not-create-sandbar", "setup", "--user", "root"}} {
		code, _, errOut := cli(t, args...)
		if code == 0 || strings.Contains(errOut, "Caddy package") {
			t.Fatal(args, code, errOut)
		}
	}
}

func TestInstalledPortOverridesRejected(t *testing.T) {
	for _, c := range []config{{Version: 2, HTTPPort: 8080, HTTPSPort: 443}, {Version: 2, HTTPPort: 80, HTTPSPort: 8443}} {
		if _, err := renderInstalledRoutes(c, false); err == nil || !strings.Contains(err.Error(), "--home") {
			t.Fatalf("installed port override accepted: %v", err)
		}
	}
}

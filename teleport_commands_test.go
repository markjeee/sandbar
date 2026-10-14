package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTeleportRegisterRetainsFailedConnect(t *testing.T) {
	d, info := sshFixturePeer(t)
	p, _ := sshFixturePaths(t)
	fakeCaddy(t)
	calls := fakeTeleportSSH(t, info)
	t.Setenv("FAKE_SSH_START_FAIL", "yes")
	args := []string{"register", "--remote-bin", "/srv/a 'quoted' binary", "--remote-home", "/srv/a home", "work-alias"}
	err := executeTeleport(p, args, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "remains registered") {
		t.Fatalf("registration failure %v", err)
	}
	got, err := readConfig(p.config)
	if err != nil || len(got.Teleports) != 1 {
		t.Fatalf("saved %+v %v", got, err)
	}
	saved := got.Teleports[0]
	if saved.Machine != d.Machine || saved.RootPEM != d.RootPEM || saved.RemoteBin != args[2] || saved.RemoteHome != args[4] || saved.LocalPort == 0 {
		t.Fatalf("saved peer %+v", saved)
	}
	if count := countSSHArgument(t, calls, "-M"); count != 1 {
		t.Fatalf("connect called %d times", count)
	}
	// Registration gets metadata once, reusable connect gets it once again.
	metadataCalls := 0
	for _, args := range readSSHCalls(t, calls) {
		if strings.Contains(args[len(args)-1], "'teleport' 'info' '--json'") {
			metadataCalls++
		}
	}
	if metadataCalls != 2 {
		t.Fatalf("peer checks %d", metadataCalls)
	}
	// Retry through the same public connect entry point after a fixture correction.
	got.Teleports[0].LocalPort = d.LocalPort
	data, _ := configBytes(got)
	if err := os.WriteFile(p.config, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_SSH_START_FAIL", "")
	if err := executeTeleport(p, []string{"connect", "remote"}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := executeTeleport(p, args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if count := countSSHArgument(t, calls, "-M"); count != 2 {
		t.Fatalf("identical registration duplicated master: %d", count)
	}
}

func TestTeleportRegisterIdentityCollisions(t *testing.T) {
	for _, machine := range []string{"local", "remote"} {
		t.Run(machine, func(t *testing.T) {
			d, info := sshFixturePeer(t)
			info.Machine = machine
			p, _ := sshFixturePaths(t, d)
			fakeCaddy(t)
			fakeTeleportSSH(t, info)
			before := readTestFile(t, p.config)
			if err := executeTeleport(p, []string{"register", "--host", "different.example", "work"}, io.Discard, io.Discard); err == nil {
				t.Fatal("accepted identity collision")
			}
			if !bytes.Equal(before, readTestFile(t, p.config)) {
				t.Fatal("collision rewrote source")
			}
		})
	}
}

func TestTeleportRegisterPublicationFailureRestoresSSH(t *testing.T) {
	existing, info := sshFixturePeer(t)
	existing.Machine = "z-existing"
	p, _ := sshFixturePaths(t, existing)
	fakeCaddy(t)
	calls := fakeTeleportSSH(t, info)
	t.Setenv("FAKE_VALIDATE_EXIT", "1")
	before := readTestFile(t, p.config)
	if err := executeTeleport(p, []string{"register", "--host", "new.example", "work"}, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted failed Caddy validation")
	}
	if countSSHArgument(t, calls, "-M") != 0 {
		t.Fatal("connected before publication")
	}
	if !bytes.Equal(before, readTestFile(t, p.config)) {
		t.Fatal("failed publication changed source")
	}
	cfg := string(readTestFile(t, filepath.Join(filepath.Dir(p.config), "ssh/config")))
	if !strings.Contains(cfg, teleportAlias(existing)) || strings.Contains(cfg, "new.example") {
		t.Fatalf("derived config %s", cfg)
	}
}

func TestTeleportRemoveScopedAndPublicationFailure(t *testing.T) {
	d, info := sshFixturePeer(t)
	other := d
	other.Machine = "other"
	other.Host = "other.example"
	other.LocalPort++
	p, c := sshFixturePaths(t, d, other)
	fakeCaddy(t)
	fakeTeleportSSH(t, info)
	if err := connectTeleport(p, c, d, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	otherSocket, _, err := teleportRuntime(p, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherSocket+".fixture", []byte("active"), 0600); err != nil {
		t.Fatal(err)
	}
	before := readTestFile(t, p.config)
	t.Setenv("FAKE_VALIDATE_EXIT", "1")
	if err := executeTeleport(p, []string{"rm", d.Machine}, io.Discard, io.Discard); err == nil {
		t.Fatal("removal validation passed")
	}
	if !bytes.Equal(before, readTestFile(t, p.config)) {
		t.Fatal("failed removal lost registration")
	}
	cfg, err := prepareTeleportSSH(p, c.Teleports)
	if err != nil {
		t.Fatal(err)
	}
	socket, _, _ := teleportRuntime(p, d)
	if teleportMasterExists(cfg, socket, d) {
		t.Fatal("failed removal left destination connected")
	}
	if !teleportMasterExists(cfg, otherSocket, other) {
		t.Fatal("unrelated destination stopped")
	}
	t.Setenv("FAKE_VALIDATE_EXIT", "")
	if err := executeTeleport(p, []string{"rm", d.Machine}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	saved, err := readConfig(p.config)
	if err != nil || len(saved.Teleports) != 1 || saved.Teleports[0].Machine != other.Machine {
		t.Fatalf("removal %+v %v", saved, err)
	}
	if !teleportMasterExists(cfg, otherSocket, other) {
		t.Fatal("successful removal stopped unrelated destination")
	}
}

func TestTeleportCommandInputsAndHelp(t *testing.T) {
	p := paths{config: filepath.Join(t.TempDir(), "missing/config.json")}
	for _, args := range [][]string{{"--help"}, {"register", "--help"}, {"connect", "--help"}, {"info", "--help"}} {
		var out bytes.Buffer
		if err := executeTeleport(p, args, &out, io.Discard); err != nil || out.Len() == 0 {
			t.Fatalf("help %v: %s %v", args, out.String(), err)
		}
	}
	if _, err := os.Stat(filepath.Dir(p.config)); !os.IsNotExist(err) {
		t.Fatal("help wrote files")
	}
	for _, args := range [][]string{{"info"}, {"unknown"}, {"connect"}, {"disconnect", "a", "b"}, {"ls", "a"}, {"rm"}} {
		if err := executeTeleport(p, args, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	d, info := sshFixturePeer(t)
	p, c := sshFixturePaths(t, d)
	calls := fakeTeleportSSH(t, info)
	before := readTestFile(t, p.config)
	for _, path := range []string{"relative", "/tmp/new\nline", "/tmp/NUL\x00"} {
		if err := executeTeleport(p, []string{"register", "--remote-bin", path, "work"}, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted path %q", path)
		}
	}
	for _, port := range []string{"0", "-1", "65536"} {
		if err := executeTeleport(p, []string{"register", "--port", port, "work"}, io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted port %s", port)
		}
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) {
		t.Fatal("invalid remote path invoked SSH")
	}
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := connectTeleport(p, c, d, io.Discard, io.Discard); err == nil {
		t.Fatal("missing agent accepted")
	}
	if !bytes.Equal(before, readTestFile(t, p.config)) {
		t.Fatal("input errors changed source")
	}
	// Metadata errors do not create the selected incomplete home.
	p = paths{config: filepath.Join(t.TempDir(), "unprepared/config.json")}
	if err := executeTeleport(p, []string{"info", "--json"}, io.Discard, io.Discard); err == nil {
		t.Fatal("unprepared info passed")
	}
	if _, err := os.Stat(filepath.Dir(p.config)); !os.IsNotExist(err) {
		t.Fatal("info created home")
	}
}

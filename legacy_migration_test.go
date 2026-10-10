//go:build linux

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testLegacyAuthority(t *testing.T) map[string][]byte {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTemplate := *rootTemplate
	interTemplate.SerialNumber = big.NewInt(2)
	interTemplate.Subject.CommonName = "test intermediate"
	interDER, err := x509.CreateCertificate(rand.Reader, &interTemplate, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	rootPrivate, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		t.Fatal(err)
	}
	interPrivate, err := x509.MarshalPKCS8PrivateKey(interKey)
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"root.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), "root.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootPrivate}), "intermediate.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}), "intermediate.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: interPrivate})}
}

func writeLegacyAuthority(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLegacyAuthorityVerification(t *testing.T) {
	dir := t.TempDir()
	files := testLegacyAuthority(t)
	writeLegacyAuthority(t, dir, files)
	read, err := readLegacyAuthority(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if !bytes.Equal(read[name], data) {
			t.Fatalf("changed %s", name)
		}
	}
	if err := checkAuthorityDestination(filepath.Join(dir, "absent"), files); err != nil {
		t.Fatal(err)
	}
	if err := checkAuthorityDestination(dir, files); err != nil {
		t.Fatal(err)
	}
	other := testLegacyAuthority(t)
	if err := checkAuthorityDestination(dir, other); err == nil {
		t.Fatal("different destination CA accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "root.key"), files["intermediate.key"], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readLegacyAuthority(dir); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "root.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := readLegacyAuthority(dir); err == nil {
		t.Fatal("missing signing key accepted")
	}
}

func TestLegacyMigrationInspection(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "old-state")
	authority := filepath.Join(state, "caddy/pki/authorities/local")
	files := testLegacyAuthority(t)
	writeLegacyAuthority(t, authority, files)
	source := []byte("{\"version\":2,\"http_port\":80,\"https_port\":443,\"routes\":[{\"hostname\":\"app.sandbar.localhost\",\"upstream\":\"8000\"}]}\n")
	sourcePath := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(sourcePath, source, 0600); err != nil {
		t.Fatal(err)
	}
	generated := []byte("# legacy generated config\n")
	if err := os.WriteFile(filepath.Join(state, "Caddyfile"), generated, 0600); err != nil {
		t.Fatal(err)
	}
	options := setupOptions{MigrateConfig: sourcePath, MigrateState: state}
	account := &user.User{Username: "test", Uid: "1000", HomeDir: dir}
	installation := &installation{Binary: "/usr/bin/caddy", State: filepath.Join(dir, "installed"), Source: filepath.Join(dir, "new.json"), Storage: filepath.Join(dir, "service-storage")}
	m, err := inspectLegacyMigration(options, account, installation)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Source, source) || m.Config.Routes[0].Upstream != "http://127.0.0.1:8000" || m.running {
		t.Fatal("legacy state changed")
	}
	if !strings.Contains(m.RestartCommand, "start") || !strings.Contains(m.RestartCommand, "old-state/Caddyfile") {
		t.Fatal(m.RestartCommand)
	}
	var out bytes.Buffer
	m.describe(&out)
	if strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatal("secret in description")
	}
	if err := os.Mkdir(filepath.Join(state, "transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectLegacyMigration(options, account, installation); err == nil || !strings.Contains(err.Error(), "recovery") {
		t.Fatalf("recovery accepted: %v", err)
	}
	if err := os.Remove(filepath.Join(state, "transaction")); err != nil {
		t.Fatal(err)
	}
	writeLegacyAuthority(t, filepath.Join(installation.Storage, "pki/authorities/sandbar"), testLegacyAuthority(t))
	if _, err := inspectLegacyMigration(options, account, installation); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("CA conflict accepted: %v", err)
	}
}

func TestLegacyUnitIdentity(t *testing.T) {
	account := &user.User{HomeDir: "/home/example"}
	p := paths{config: "/home/example/.config/sandbar/config.json", state: "/home/example/.local/state/sandbar"}
	fields := map[string]string{"LoadState": "loaded", "ActiveState": "active", "Transient": "yes", "ExecStart": "{ path=/home/example/.local/bin/sandbar ; argv[]=/home/example/.local/bin/sandbar start ; ignore_errors=no ; }"}
	if err := verifyLegacyUnit(fields, p, account); err != nil {
		t.Fatal(err)
	}
	fields["ExecStart"] = "{ argv[]=/usr/bin/other start ; }"
	if err := verifyLegacyUnit(fields, p, account); err == nil {
		t.Fatal("unrelated command accepted")
	}
	fields["ExecStart"] = "{ argv[]=/usr/bin/sandbar --home /tmp/another start ; }"
	if err := verifyLegacyUnit(fields, p, account); err == nil {
		t.Fatal("different home accepted")
	}
	fields["ExecStart"] = "{ argv[]=/usr/bin/sandbar start ; }"
	fields["Transient"] = "no"
	if err := verifyLegacyUnit(fields, p, account); err == nil {
		t.Fatal("persistent unit accepted")
	}
}

func TestLegacyActiveIdentity(t *testing.T) {
	p := paths{state: "/tmp/legacy"}
	valid := []byte(`{"admin":{"listen":"unix//tmp/legacy/admin.sock"},"storage":{"module":"file_system","root":"/tmp/legacy/caddy"}}`)
	if err := verifyLegacyActive(valid, p); err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyActive(valid, paths{state: "/tmp/another"}); err == nil {
		t.Fatal("unrelated active router accepted")
	}
}

func TestLegacyFreshStorageDirectories(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(dir, ".local/share/caddy/pki/authorities/sandbar")
	if err := ensureAuthorityDirectory(leaf, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	for current := leaf; current != dir; current = filepath.Dir(current) {
		info, err := os.Stat(current)
		if err != nil {
			t.Fatal(err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		if int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() || info.Mode().Perm() != 0700 {
			t.Fatalf("incorrect new directory metadata: %s %v %d:%d", current, info.Mode(), stat.Uid, stat.Gid)
		}
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatal("existing parent mode changed")
	}
}

func TestLegacyMigrationPortOverridesRejectedBeforeState(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(source, []byte(`{"version":2,"http_port":8080,"https_port":8443,"routes":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	options := setupOptions{MigrateConfig: source, MigrateState: filepath.Join(dir, "missing-state")}
	_, err := inspectLegacyMigration(options, &user.User{Username: "example", HomeDir: dir}, &installation{Source: filepath.Join(dir, "installed.json"), State: filepath.Join(dir, "installed")})
	if err == nil || !strings.Contains(err.Error(), "ports 80 and 443") {
		t.Fatalf("port conflict did not stop before state reads: %v", err)
	}
}

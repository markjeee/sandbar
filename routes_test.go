package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestNormalizeUpstream(t *testing.T) {
	for input, want := range map[string]string{
		"8000": "http://127.0.0.1:8000", "08000": "http://127.0.0.1:8000",
		"LOCALHOST:8000": "http://localhost:8000", "127.0.0.2:8000": "http://127.0.0.2:8000",
		"[::1]:8000": "http://[::1]:8000", "http://[0:0:0:0:0:0:0:1]:8000": "http://[::1]:8000",
		"https://localhost:9443": "https://localhost:9443", "http://localhost": "http://localhost:80",
		"https://localhost": "https://localhost:443",
	} {
		got, err := normalizeUpstream(input, 8080, 8443)
		if err != nil || got != want {
			t.Errorf("%s: %s %v", input, got, err)
		}
	}
	for _, input := range []string{"", "localhost", "[::1]", "127.0.0.1", "0", "65536", "-1", "8000/path", "localhost:", "localhost:abc", "localhost:8080", "http://localhost:8443", "http://example.com:8000", "http://192.168.1.1:8000", "http://[::]:8000", "http://::1:8000", "http://localhost:8000/", "http://localhost:8000/a", "http://localhost:8000?", "http://localhost:8000?x=1", "http://localhost:8000#", "http://localhost:8000#x", "http://user@localhost:8000", "ftp://localhost:8000", "http://localhost:8000\\foo", "http://[::1%25lo]:8000"} {
		if got, err := normalizeUpstream(input, 8080, 8443); err == nil {
			t.Errorf("accepted %q as %s", input, got)
		}
	}
	for _, input := range []string{"http://localhost", "https://localhost"} {
		if _, err := normalizeUpstream(input, 80, 443); err == nil {
			t.Errorf("accepted router default port %s", input)
		}
	}
}

func TestVersion2Decode(t *testing.T) {
	c, err := decodeConfig(strings.NewReader(`{"version":2,"http_port":80,"https_port":443,"routes":[{"hostname":"Z.sandbar.localhost","upstream":"8000"},{"hostname":"a.sandbar.localhost","upstream":"localhost:9000"}]}`))
	if err != nil || len(c.Routes) != 2 || c.Routes[0].Hostname != "a.sandbar.localhost" || c.Routes[1].Upstream != "http://127.0.0.1:8000" {
		t.Fatalf("%+v %v", c, err)
	}
	for _, input := range []string{
		`{"version":2,"http_port":80,"https_port":443}`, `{"version":2,"http_port":80,"https_port":443,"routes":null}`,
		`{"version":2,"http_port":80,"https_port":443,"routes":[],"hostname":"a.sandbar.localhost"}`,
		`{"version":1,"http_port":80,"https_port":443,"hostname":"a.sandbar.localhost","upstream_port":8000,"routes":[]}`,
		`{"version":2,"http_port":80,"https_port":443,"routes":[{"hostname":"a.sandbar.localhost","upstream":"8000","extra":1}]}`,
		`{"version":2,"http_port":80,"https_port":443,"routes":[{"hostname":"A.sandbar.localhost","upstream":"8000"},{"hostname":"a.sandbar.localhost","upstream":"9000"}]}`,
	} {
		if _, err := decodeConfig(strings.NewReader(input)); err == nil {
			t.Errorf("accepted %s", input)
		}
	}
}

func routeCommand(t *testing.T, p paths, args ...string) (int, string, string) {
	t.Helper()
	return cli(t, append([]string{"--home", filepath.Dir(p.config)}, args...)...)
}

func TestRouteCommandsAndMigration(t *testing.T) {
	p := initialized(t)
	fakeCaddy(t)
	legacy := []byte("{\n  \"version\":1,\"hostname\":\"NETBOX.sandbar.localhost\",\"upstream_port\":8000,\"http_port\":8080,\"https_port\":8443\n}\n")
	if err := os.WriteFile(p.config, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "NETBOX.sandbar.localhost", "8000"}, {"add", "a.sandbar.localhost", "localhost:9000"}} {
		if code, _, errOut := routeCommand(t, p, args...); code != 0 {
			t.Fatal(errOut)
		}
	}
	if !bytes.Equal(readTestFile(t, filepath.Join(filepath.Dir(p.config), "config.v1.backup.json")), legacy) {
		t.Fatal("legacy backup changed")
	}
	c, err := readConfig(p.config)
	if err != nil || c.Version != 2 || len(c.Routes) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
	before := readTestFile(t, p.config)
	info, _ := os.Stat(p.config)
	if code, _, errOut := routeCommand(t, p, "add", "A.sandbar.localhost", "http://localhost:9000"); code != 0 {
		t.Fatal(errOut)
	}
	after, _ := os.Stat(p.config)
	if !bytes.Equal(before, readTestFile(t, p.config)) || info.ModTime() != after.ModTime() {
		t.Fatal("identical addition rewrote source")
	}
	if code, _, _ := routeCommand(t, p, "add", "a.sandbar.localhost", "9001"); code == 0 {
		t.Fatal("replaced without flag")
	}
	if code, _, errOut := routeCommand(t, p, "add", "--replace", "a.sandbar.localhost", "9001"); code != 0 {
		t.Fatal(errOut)
	}
	if code, out, errOut := routeCommand(t, p, "ls"); code != 0 || !strings.HasPrefix(out, "a.sandbar.localhost\thttps://a.sandbar.localhost:8443\thttp://127.0.0.1:9001\nnetbox.") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
	if code, _, _ := routeCommand(t, p, "rm", "unknown.sandbar.localhost"); code == 0 {
		t.Fatal("removed unknown route")
	}
	for _, host := range []string{"a.sandbar.localhost", "netbox.sandbar.localhost"} {
		if code, _, errOut := routeCommand(t, p, "rm", host); code != 0 {
			t.Fatal(errOut)
		}
	}
	c, err = readConfig(p.config)
	if err != nil || len(c.Routes) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	generated := string(readTestFile(t, p.file("Caddyfile")))
	if strings.Contains(generated, "reverse_proxy") || !strings.Contains(generated, "pki {") || !strings.Contains(generated, "admin ") {
		t.Fatal(generated)
	}
	if code, out, errOut := routeCommand(t, p, "ls"); code != 0 || out != "" {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
}

func TestConcurrentRouteMutations(t *testing.T) {
	p := initialized(t)
	fakeCaddy(t)
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var out, diagnostics bytes.Buffer
			code := run([]string{"--home", filepath.Dir(p.config), "add", fmt.Sprintf("app%d.sandbar.localhost", i), fmt.Sprint(9000 + i)}, &out, &diagnostics)
			if code != 0 {
				errs <- fmt.Errorf("%d: %s", code, &diagnostics)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	c, err := readConfig(p.config)
	if err != nil || len(c.Routes) != 13 {
		t.Fatalf("lost mutation: %+v %v", c, err)
	}
}

func transactionAdmin(t *testing.T, p paths, active string) string {
	t.Helper()
	activeFile := p.file("test-active.json")
	if err := os.WriteFile(activeFile, []byte(active), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", p.file("admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/config/" {
			t.Errorf("unexpected admin request %s %s", r.Method, r.URL)
		}
		data, err := os.ReadFile(activeFile)
		if err != nil {
			t.Error(err)
			http.Error(w, "failed", 500)
			return
		}
		_, _ = w.Write(data)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	t.Setenv("FAKE_ACTIVE_FILE", activeFile)
	return activeFile
}

func TestRouteFailurePreservesFiles(t *testing.T) {
	for _, failure := range []string{"validation", "reload", "ambiguous load", "manual reload"} {
		t.Run(failure, func(t *testing.T) {
			p := initialized(t)
			fakeCaddy(t)
			if code, _, errOut := routeCommand(t, p, "add", "second.sandbar.localhost", "9000"); code != 0 {
				t.Fatal(errOut)
			}
			source, generated := readTestFile(t, p.config), readTestFile(t, p.file("Caddyfile"))
			args := []string{"add", "third.sandbar.localhost", "9001"}
			if failure == "validation" {
				t.Setenv("FAKE_VALIDATE_EXIT", "23")
			} else {
				activeFile := transactionAdmin(t, p, `{"test":"previous"}`)
				t.Setenv("FAKE_RELOAD_EXIT", "24")
				if failure == "ambiguous load" {
					t.Setenv("FAKE_ACTIVE_AFTER_RELOAD", `{"unknown":true}`)
				}
				if failure == "manual reload" {
					c, err := readConfig(p.config)
					if err != nil {
						t.Fatal(err)
					}
					c.Routes[0].Upstream = "http://127.0.0.1:9999"
					source, err = configBytes(c)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p.config, source, 0600); err != nil {
						t.Fatal(err)
					}
					args = []string{"reload"}
				}
				_ = activeFile
			}
			if code, _, errOut := routeCommand(t, p, args...); code == 0 {
				t.Fatalf("accepted failed %s: %s", failure, errOut)
			}
			if !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(generated, readTestFile(t, p.file("Caddyfile"))) {
				t.Fatal("failed change replaced committed files")
			}
			_, err := os.Stat(p.file("transaction"))
			if failure == "ambiguous load" {
				if err != nil {
					t.Fatal("lost unresolved recovery", err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatal("retained resolved journal", err)
			}
		})
	}
}

func TestReloadUsesSelectedSocket(t *testing.T) {
	p := initialized(t)
	calls := fakeCaddy(t)
	transactionAdmin(t, p, `{"test":"previous"}`)
	t.Setenv("FAKE_ACTIVE_AFTER_RELOAD", `{"test":"candidate"}`)
	if code, _, errOut := routeCommand(t, p, "add", "second.sandbar.localhost", "9000"); code != 0 {
		t.Fatal(errOut)
	}
	got := readCalls(t, calls)
	last := got[len(got)-1]
	address, _ := p.adminAddress()
	if !reflect.DeepEqual(last, []string{"reload", "--config", p.file("transaction/candidate.Caddyfile"), "--adapter", "caddyfile", "--address", address}) {
		t.Fatal(last)
	}
	c, err := readConfig(p.config)
	if err != nil || len(c.Routes) != 2 {
		t.Fatalf("%+v %v", c, err)
	}
}

func testTransaction(t *testing.T, p paths, phase string, reload bool) transaction {
	t.Helper()
	previous := readTestFile(t, p.config)
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	c.Routes = append(c.Routes, route{"second.sandbar.localhost", "http://127.0.0.1:9000"})
	candidate, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	tx := transaction{Version: 1, Phase: "prepared", Reload: reload, PreviousSource: previous, CandidateSource: candidate, PreviousGenerated: []byte("previous generated"), CandidateGenerated: []byte("candidate generated"), PreviousActive: []byte(`{"old":true}`), CandidateActive: []byte(`{"new":true}`)}
	if err := os.WriteFile(p.file("Caddyfile"), tx.PreviousGenerated, 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveTransaction(p, tx); err != nil {
		t.Fatal(err)
	}
	tx.Phase = phase
	if phase != "prepared" {
		if err := saveTransaction(p, tx); err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

func TestInterruptedTransactionRecovery(t *testing.T) {
	for _, state := range []string{"prepared stopped", "loading stopped", "applied stopped", "candidate active", "previous active", "unknown active", "invalid admin", "source conflict", "generated conflict"} {
		t.Run(state, func(t *testing.T) {
			p := initialized(t)
			reload := strings.Contains(state, "active") || state == "invalid admin" || state == "loading stopped"
			phase := "loading"
			if state == "prepared stopped" {
				phase = "prepared"
			}
			if state == "applied stopped" {
				phase = "applied"
			}
			tx := testTransaction(t, p, phase, reload)
			switch state {
			case "candidate active":
				transactionAdmin(t, p, `{ "new" : true }`)
			case "previous active":
				transactionAdmin(t, p, `{"old":true}`)
			case "unknown active":
				transactionAdmin(t, p, `{"other":true}`)
			case "invalid admin":
				transactionAdmin(t, p, `invalid`)
			case "source conflict":
				if err := os.WriteFile(p.config, []byte("manual edit"), 0600); err != nil {
					t.Fatal(err)
				}
			case "generated conflict":
				if err := os.WriteFile(p.file("Caddyfile"), []byte("manual generated"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			beforeSource, beforeGenerated := readTestFile(t, p.config), readTestFile(t, p.file("Caddyfile"))
			err := withLock(p, func() error { return recoverTransaction(p, io.Discard) })
			unresolved := strings.Contains(state, "conflict") || state == "unknown active" || state == "invalid admin"
			if unresolved {
				if err == nil || !strings.Contains(err.Error(), p.file("transaction")) {
					t.Fatalf("missing recovery error: %v", err)
				}
				if state == "unknown active" && (!strings.Contains(err.Error(), "active configuration differs from both previous and candidate configurations") || strings.Contains(err.Error(), "<nil>")) {
					t.Fatalf("unclear active-state diagnostic: %v", err)
				}
				if !bytes.Equal(beforeSource, readTestFile(t, p.config)) || !bytes.Equal(beforeGenerated, readTestFile(t, p.file("Caddyfile"))) {
					t.Fatal("overwrote unresolved state")
				}
				if _, err := os.Stat(p.file("transaction/journal.json")); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantSource, wantGenerated := tx.PreviousSource, tx.PreviousGenerated
			if state == "candidate active" || state == "applied stopped" {
				wantSource, wantGenerated = tx.CandidateSource, tx.CandidateGenerated
			}
			if !bytes.Equal(wantSource, readTestFile(t, p.config)) || !bytes.Equal(wantGenerated, readTestFile(t, p.file("Caddyfile"))) {
				t.Fatal("recovery chose wrong state")
			}
			if _, err := os.Stat(p.file("transaction")); !os.IsNotExist(err) {
				t.Fatal("retained completed journal")
			}
		})
	}
}

func TestRecoveryBeforeStartupAndInvalidStateCommands(t *testing.T) {
	p := initialized(t)
	calls := fakeCaddy(t)
	if err := os.Mkdir(p.file("transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("transaction/journal.json"), []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"start", "init", "add"} {
		args := []string{command}
		if command == "add" {
			args = append(args, "second.sandbar.localhost", "9000")
		}
		if code, _, errOut := routeCommand(t, p, args...); code == 0 || !strings.Contains(errOut, "recovery journal") {
			t.Fatalf("%s %d %s", command, code, errOut)
		}
	}
	if _, err := os.Stat(calls); !os.IsNotExist(err) {
		t.Fatal("recovery failure invoked Caddy")
	}
	if err := os.WriteFile(p.config, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := routeCommand(t, p, "stop"); code != 0 {
		t.Fatal(errOut)
	}
	root := p.file("caddy/pki/authorities/local/root.crt")
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, []byte("certificate fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := routeCommand(t, p, "untrust"); code != 0 {
		t.Fatal(errOut)
	}
}

func TestMigrationBackupConflictPreventsLoad(t *testing.T) {
	p := initialized(t)
	calls := fakeCaddy(t)
	legacy, err := configBytes(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.config, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(filepath.Dir(p.config), "config.v1.backup.json")
	if err := os.WriteFile(backup, []byte("different old backup"), 0600); err != nil {
		t.Fatal(err)
	}
	transactionAdmin(t, p, `{"test":"previous"}`)
	if code, _, errOut := routeCommand(t, p, "add", "second.sandbar.localhost", "9000"); code == 0 || !strings.Contains(errOut, "legacy backup conflict") {
		t.Fatalf("%d %s", code, errOut)
	}
	for _, call := range readCalls(t, calls) {
		if call[0] == "reload" {
			t.Fatal("loaded candidate despite backup conflict")
		}
	}
	if !bytes.Equal(legacy, readTestFile(t, p.config)) || string(readTestFile(t, backup)) != "different old backup" {
		t.Fatal("overwrote legacy source or backup")
	}
	if _, err := os.Stat(p.file("transaction")); !os.IsNotExist(err) {
		t.Fatal("backup conflict published journal")
	}
}

func TestRecoveryAfterPartialCommit(t *testing.T) {
	for _, candidate := range []bool{false, true} {
		t.Run(fmt.Sprint(candidate), func(t *testing.T) {
			p := initialized(t)
			tx := testTransaction(t, p, "loading", true)
			// Model interruption between generated and source replacement.
			if err := atomicWrite(p.file("Caddyfile"), tx.CandidateGenerated); err != nil {
				t.Fatal(err)
			}
			active := string(tx.PreviousActive)
			if candidate {
				active = string(tx.CandidateActive)
			}
			transactionAdmin(t, p, active)
			if err := withLock(p, func() error { return recoverTransaction(p, io.Discard) }); err != nil {
				t.Fatal(err)
			}
			source, generated := tx.PreviousSource, tx.PreviousGenerated
			if candidate {
				source, generated = tx.CandidateSource, tx.CandidateGenerated
			}
			if !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(generated, readTestFile(t, p.file("Caddyfile"))) {
				t.Fatal("partial commit was not recovered")
			}
		})
	}
}

func TestRecoveryPreservesAbsentGeneratedFile(t *testing.T) {
	p := initialized(t)
	tx := testTransaction(t, p, "prepared", false)
	tx.PreviousGenerated = nil
	if err := os.Remove(p.file("Caddyfile")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(p.file("transaction")); err != nil {
		t.Fatal(err)
	}
	if err := saveTransaction(p, tx); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(p.file("Caddyfile"), tx.CandidateGenerated); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransaction(p, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.file("Caddyfile")); !os.IsNotExist(err) {
		t.Fatal("rollback invented previous generated file", err)
	}
}

func TestRecoveryAfterJournalRetirement(t *testing.T) {
	p := initialized(t)
	tx := testTransaction(t, p, "applied", false)
	if err := atomicWrite(p.config, tx.CandidateSource); err != nil {
		t.Fatal(err)
	}
	if err := atomicWrite(p.file("Caddyfile"), tx.CandidateGenerated); err != nil {
		t.Fatal(err)
	}
	// Model process termination after journal retirement and before cleanup.
	if err := os.Rename(p.file("transaction"), p.file("transaction-complete")); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransaction(p, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tx.CandidateSource, readTestFile(t, p.config)) {
		t.Fatal("retired journal changed committed state")
	}
	// A later completed transaction may remove the retired private data.
	tx.PreviousSource = tx.CandidateSource
	tx.PreviousGenerated = tx.CandidateGenerated
	tx.Phase = "prepared"
	if err := saveTransaction(p, tx); err != nil {
		t.Fatal(err)
	}
	if err := finishTransaction(p, tx, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.file("transaction-complete")); !os.IsNotExist(err) {
		t.Fatal("retired recovery files remain", err)
	}
}

func TestFailedRecoveryWritePreservesJournal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not block root writes")
	}
	p := initialized(t)
	tx := testTransaction(t, p, "applied", false)
	if err := os.Chmod(p.state, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p.state, 0700) })
	err := recoverTransaction(p, io.Discard)
	if err == nil {
		t.Fatal("recovery succeeded despite unwritable state")
	}
	if !bytes.Equal(tx.PreviousSource, readTestFile(t, p.config)) || !bytes.Equal(tx.PreviousGenerated, readTestFile(t, p.file("Caddyfile"))) {
		t.Fatal("failed recovery changed files")
	}
	if _, err := os.Stat(p.file("transaction/journal.json")); err != nil {
		t.Fatal("failed recovery discarded journal", err)
	}
	if err := os.Chmod(p.state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransaction(p, io.Discard); err != nil {
		t.Fatal("retry recovery:", err)
	}
	if !bytes.Equal(tx.CandidateSource, readTestFile(t, p.config)) {
		t.Fatal("recovery retry did not complete")
	}
}

func TestBackupNeverOverwritesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.json")
	if err := createBackup(path, []byte("previous")); err != nil {
		t.Fatal(err)
	}
	if err := createBackup(path, []byte("candidate")); err == nil {
		t.Fatal("overwrote existing backup")
	}
	if string(readTestFile(t, path)) != "previous" {
		t.Fatal("backup content changed")
	}
}

func TestInterruptedJournalPreparationLeavesCommittedFiles(t *testing.T) {
	p := initialized(t)
	before := readTestFile(t, p.config)
	staging := p.file(".transaction-interrupted")
	if err := os.Mkdir(staging, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "previous.config.json"), before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := recoverTransaction(p, io.Discard); err != nil {
		t.Fatal("unpublished preparation blocked recovery", err)
	}
	if !bytes.Equal(before, readTestFile(t, p.config)) {
		t.Fatal("unpublished transaction changed source")
	}
	fakeCaddy(t)
	if code, _, errOut := routeCommand(t, p, "add", "second.sandbar.localhost", "9000"); code != 0 {
		t.Fatal("unpublished preparation blocked mutation", errOut)
	}
}

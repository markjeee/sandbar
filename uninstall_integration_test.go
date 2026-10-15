package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestIntegrationUninstallCandidate(t *testing.T) {
	requireIntegration(t)
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	home := shortHome(t)
	p := paths{installed: &installation{Binary: binary, Storage: filepath.Join(home, "storage")}}
	for name, candidate := range map[string]string{
		"comments":     "# retain package configuration\n",
		"empty global": "# before\n{\n # retained global block\n}\n# after\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkUninstallCandidate(p, []byte(candidate), io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
	_, port := freePorts(t)
	topPath := filepath.Join(home, "Caddyfile")
	importPath := filepath.Join(home, "unrelated.caddyfile")
	top := []byte("# preserved import\nimport unrelated.caddyfile\n")
	site := []byte(fmt.Sprintf("http://unrelated.localhost:%d {\n bind 127.0.0.1\n respond unrelated\n}\n", port))
	for path, data := range map[string][]byte{topPath: top, importPath: site} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	candidate, manifest, err := composeCandidate(topPath, top, nil, filepath.Join(home, "removed-routes"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 2 || !bytes.Contains(candidate, site) {
		t.Fatal("static import was not inspected")
	}
	if err := checkUninstallCandidate(p, candidate, io.Discard); err == nil || !strings.Contains(err.Error(), "separate unrelated sites") {
		t.Fatalf("unrelated imported site: %v", err)
	}
	for path, expected := range map[string][]byte{topPath: top, importPath: site} {
		if !bytes.Equal(readTestFile(t, path), expected) {
			t.Fatalf("preview changed %s", path)
		}
	}
	if _, err := os.Stat(p.installed.Storage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("adaptation created storage: %v", err)
	}
}

func TestIntegrationUninstallCertificateStorage(t *testing.T) {
	requireIntegration(t)
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal(err)
	}
	home := shortHome(t)
	storage := filepath.Join(home, "storage")
	configPath := filepath.Join(home, "Caddyfile")
	_, port := freePorts(t)
	header := fmt.Sprintf(`{
	admin off
	persist_config off
	skip_install_trust
	auto_https disable_redirects
	storage file_system %q
	servers {
		protocols h1 h2
	}
	pki {
		ca sandbar {
			name "test Sandbar CA"
		}
		ca unrelated {
			name "test unrelated CA"
		}
	}
}
`, storage)
	site := func(host, authority string) string {
		return fmt.Sprintf("https://%s:%d {\n bind 127.0.0.1\n tls {\n issuer internal {\n ca %s\n }\n }\n respond %q\n}\n", host, port, authority, host)
	}
	active := site("active.sandbar.localhost", "sandbar")
	obsolete := site("obsolete.sandbar.localhost", "sandbar")
	unrelated := site("unrelated.localhost", "unrelated")
	if err := os.WriteFile(configPath, []byte(header+active+obsolete+unrelated), 0600); err != nil {
		t.Fatal(err)
	}
	// The explicit storage and subprocess environment are temporary. Trust is disabled.
	env := caddyEnv(paths{state: filepath.Join(home, "process")})
	var diagnostic bytes.Buffer
	if err := runBounded(binary, env, nil, io.Discard, &diagnostic, "validate", "--config", configPath, "--adapter", "caddyfile"); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	logs, err := os.Create(filepath.Join(home, "caddy.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logs.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	command := exec.CommandContext(ctx, binary, "run", "--config", configPath, "--adapter", "caddyfile")
	command.Env, command.Stdout, command.Stderr = env, logs, logs
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		defer cancel()
		if err := command.Process.Signal(os.Interrupt); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
		if err := command.Wait(); err != nil {
			t.Errorf("temporary Caddy: %v\n%s", err, readTestFile(t, logs.Name()))
		}
	}
	t.Cleanup(stop)
	roots := x509.NewCertPool()
	for _, authority := range []string{"sandbar", "unrelated"} {
		if !roots.AppendCertsFromPEM(readTestFile(t, filepath.Join(storage, "pki/authorities", authority, "root.crt"))) {
			t.Fatal("invalid temporary root", authority)
		}
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", port))
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for _, host := range []string{"active.sandbar.localhost", "obsolete.sandbar.localhost", "unrelated.localhost"} {
		url := fmt.Sprintf("https://%s:%d", host, port)
		waitForTLS(t, client, url)
		response, body := getResponse(t, client, url)
		if response.StatusCode != http.StatusOK || string(body) != host {
			t.Fatalf("temporary TLS route %s: %d %s", host, response.StatusCode, body)
		}
	}
	transport.CloseIdleConnections()
	stop()
	waitForClosed(t, port)
	// Retire a route while retaining its issued leaf in Caddy's native cache.
	if err := os.WriteFile(configPath, []byte(header+active+unrelated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runBounded(binary, env, nil, io.Discard, &diagnostic, "validate", "--config", configPath, "--adapter", "caddyfile"); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	for _, host := range []string{"active.sandbar.localhost", "obsolete.sandbar.localhost"} {
		for _, extension := range []string{".crt", ".key", ".json"} {
			if _, err := os.Stat(filepath.Join(storage, "certificates/sandbar", host, host+extension)); err != nil {
				t.Fatal("native Sandbar leaf cache", err)
			}
		}
	}
	snapshot := func() map[string][sha256.Size]byte {
		t.Helper()
		result := map[string][sha256.Size]byte{}
		for _, root := range []string{"pki/authorities/unrelated", "certificates/unrelated"} {
			err := filepath.Walk(filepath.Join(storage, root), func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.Mode().IsRegular() {
					result[path] = sha256.Sum256(readTestFile(t, path))
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	before := snapshot()
	plan := &uninstallPlan{}
	authority := filepath.Join(storage, "pki/authorities/sandbar")
	if err := plan.addTree(authority, func(rel string, info os.FileInfo) bool {
		return rel == "." || rel == "root.crt" || rel == "root.key" || rel == "intermediate.crt" || rel == "intermediate.key"
	}, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	leaves := filepath.Join(storage, "certificates/sandbar")
	if err := plan.addTree(leaves, uninstallLeafPath, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	for _, entry := range plan.Entries {
		if err := removeUninstallEntry(entry); err != nil {
			t.Fatal(err)
		}
	}
	sort.Slice(plan.Directories, func(a, b int) bool { return len(plan.Directories[a]) > len(plan.Directories[b]) })
	for _, dir := range plan.Directories {
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
	}
	for _, root := range []string{authority, leaves} {
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("selected CA or obsolete leaves remain at %s: %v", root, err)
		}
	}
	if !reflect.DeepEqual(before, snapshot()) {
		t.Fatal("cleanup changed unrelated authority or leaf cache")
	}
	if _, err := os.Stat(storage); err != nil {
		t.Fatal("removed shared storage root", err)
	}
}

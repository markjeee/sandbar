package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestInstalledRoutes(t *testing.T) {
	c := config{Version: 2, HTTPPort: 80, HTTPSPort: 443}
	text, err := renderInstalledRoutes(c, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"https://sandbar.localhost:443", "bind 127.0.0.1 [::1]", "ca sandbar", "sandbar add netbox.sandbar.localhost 8000", "redir https://sandbar.localhost{uri} 308"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{"storage ", "default_bind ", "http_port ", "tls internal"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("unexpected global %q", unwanted)
		}
	}
	c.Routes = []route{{"app.sandbar.localhost", "8000"}}
	text, err = renderInstalledRoutes(c, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "reverse_proxy http://127.0.0.1:8000") || strings.Contains(text, "[::1]") {
		t.Fatal(text)
	}
	if len(c.Routes) != 1 {
		t.Fatal("welcome leaked into routes")
	}
}

func TestInstalledComposition(t *testing.T) {
	dir := shortHome(t)
	topPath := filepath.Join(dir, "Caddyfile")
	globalPath := filepath.Join(dir, "global.Caddyfile")
	routePath := filepath.Join(dir, "routes.Caddyfile")
	top := []byte("# keep this\n{\n email test@example.com\n}\n# package site\n:80 {\n # root comment\n root * /usr/share/caddy\n file_server\n}\n# keep tail\n")
	if err := os.WriteFile(topPath, top, 0600); err != nil {
		t.Fatal(err)
	}
	globals := []byte(renderInstalledGlobals("unix/"+filepath.Join(dir, "admin.sock"), "", ""))
	routes, err := renderInstalledRoutes(config{Version: 2, HTTPPort: 80, HTTPSPort: 443}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := composeInstalledConfig(topPath, top, globalPath, routePath, globals, []byte(routes), false); err == nil {
		t.Fatal("stock replacement without approval")
	}
	composed, err := composeInstalledConfig(topPath, top, globalPath, routePath, globals, []byte(routes), true)
	if err != nil {
		t.Fatal(err)
	}
	if !composed.StockReplaced || !bytes.Contains(composed.Top, []byte("# keep this")) || !bytes.Contains(composed.Top, []byte("# keep tail")) {
		t.Fatal(string(composed.Top))
	}
	if bytes.Contains(composed.Top, []byte("root * /usr/share/caddy")) {
		t.Fatal("stock not removed")
	}
	again, err := composeInstalledConfig(topPath, composed.Top, globalPath, routePath, globals, []byte(routes), false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again.Top, composed.Top) {
		t.Fatalf("repeat changed bytes:\n%s\n%s", composed.Top, again.Top)
	}
	custom := []byte(":80 {\nroot * /srv/custom\nfile_server\n}\n")
	if err := os.WriteFile(topPath, custom, 0600); err != nil {
		t.Fatal(err)
	}
	keep, err := composeInstalledConfig(topPath, custom, globalPath, routePath, globals, []byte(routes), true)
	if err != nil {
		t.Fatal(err)
	}
	if keep.StockReplaced || !bytes.Contains(keep.Top, custom) {
		t.Fatal("custom site changed")
	}
}

func TestInstalledStaticImportsAndDrift(t *testing.T) {
	dir := shortHome(t)
	sites := filepath.Join(dir, "sites")
	if err := os.Mkdir(sites, 0700); err != nil {
		t.Fatal(err)
	}
	topPath := filepath.Join(dir, "Caddyfile")
	globalPath := filepath.Join(dir, "global")
	routePath := filepath.Join(dir, "routes")
	inputs := map[string]string{topPath: "{\nimport ./global\n}\nimport sites/*.caddy\nimport ./routes\n", globalPath: "admin unix/" + filepath.Join(dir, "admin.sock") + "\n", routePath: "", filepath.Join(sites, "a.caddy"): "http://other.localhost:19090 {\nrespond ok\n}\n", filepath.Join(sites, ".hidden.caddy"): "invalid hidden file"}
	for path, text := range inputs {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	candidate, manifest, err := stageInstalledCandidate(topPath, globalPath, routePath, []byte("# new routes\n"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(candidate, []byte("import ")) || !bytes.Contains(candidate, []byte("other.localhost")) || bytes.Contains(candidate, []byte("invalid hidden")) {
		t.Fatal(string(candidate))
	}
	if err := verifyInputManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sites, "b.caddy"), []byte("# new file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyInputManifest(manifest); err == nil {
		t.Fatal("changed glob accepted")
	}
	if err := os.Remove(filepath.Join(sites, "b.caddy")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalPath, []byte("admin off\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyInputManifest(manifest); err == nil {
		t.Fatal("changed global accepted")
	}
	if err := os.Remove(globalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(routePath, globalPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := stageInstalledCandidate(topPath, globalPath, routePath, nil); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestInstalledUnsupportedImports(t *testing.T) {
	for _, text := range []string{"import {$SITES}\n", "import {args[0]}\n", "import snippet\n", "import ./foo arg\n", "respond <<HTML\nx\nHTML\n"} {
		t.Run(text, func(t *testing.T) {
			dir := shortHome(t)
			top := filepath.Join(dir, "Caddyfile")
			if err := os.WriteFile(top, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := composeCandidate(top, []byte(text), nil, ""); err == nil {
				t.Fatal("unsupported input accepted")
			}
		})
	}
}

func TestInstalledAdaptedSafety(t *testing.T) {
	if _, err := exec.LookPath("caddy"); err != nil {
		t.Skip("Caddy not installed")
	}
	c := config{Version: 2, HTTPPort: 80, HTTPSPort: 443, Routes: []route{{"app.sandbar.localhost", "8000"}}}
	dir := shortHome(t)
	admin := "unix/" + filepath.Join(dir, "admin.sock")
	routes, err := renderInstalledRoutes(c, false)
	if err != nil {
		t.Fatal(err)
	}
	base := "{\n" + renderInstalledGlobals(admin, "", "") + "}\n" + routes
	adapt := func(text string) []byte {
		t.Helper()
		file := filepath.Join(dir, "candidate")
		if err := os.WriteFile(file, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("caddy", "adapt", "--config", file, "--adapter", "caddyfile")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("adapt: %v: %s", err, stderr.String())
		}
		return out
	}
	data := adapt(base)
	override := strings.Replace(base, "{\n", "{\nhttp_port 18081\n", 1)
	if err := checkInstalledAdapted(adapt(override), c, admin); err == nil {
		t.Fatal("global port override accepted")
	}
	disabled := strings.Replace(base, "{\n", "{\nauto_https off\n", 1)
	if err := checkInstalledAdapted(adapt(disabled), c, admin); err == nil {
		t.Fatal("disabled certificate automation accepted")
	}
	if err := checkInstalledAdapted(data, c, admin); err != nil {
		t.Fatalf("valid config rejected: %v\n%s", err, data)
	}
	unrelated := base + "\nhttp://other.localhost:19090 {\nrespond ok\n}\n"
	if err := checkInstalledAdapted(adapt(unrelated), c, admin); err != nil {
		t.Fatal(err)
	}
	for _, site := range []string{"http://:80 {\nrespond stock\n}\n", "http://*.sandbar.localhost:80 {\nbind 127.0.0.1\nrespond wildcard\n}\n"} {
		if err := checkInstalledAdapted(adapt(base+site), c, admin); err == nil {
			t.Fatal("conflict accepted")
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["storage"] = map[string]any{"module": "file_system", "root": "/tmp"}
	bad, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkInstalledAdapted(bad, c, admin); err == nil {
		t.Fatal("custom storage accepted")
	}
	if err := checkInstalledAdapted(data, c, "unix/wrong"); err == nil {
		t.Fatal("wrong admin accepted")
	}
}

func TestInstalledStockOnly(t *testing.T) {
	dir := shortHome(t)
	top := filepath.Join(dir, "Caddyfile")
	source := []byte("# Caddy welcome\n:80 {\n# default root\nroot * /usr/share/caddy\nfile_server\n}\n# preserve\n")
	if err := os.WriteFile(top, source, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := composeInstalledConfig(top, source, filepath.Join(dir, "globals"), filepath.Join(dir, "routes"), []byte("skip_install_trust\n"), []byte("# routes\n"), true)
	if err != nil {
		t.Fatal(err)
	}
	if !result.StockReplaced || !bytes.Contains(result.Top, []byte("# preserve")) {
		t.Fatal(string(result.Top))
	}
}

func TestInstalledRelativeResources(t *testing.T) {
	for _, source := range []string{"http://other.localhost:19090 {\nroot * ./public\nfile_server\n}\n", "other.localhost {\ntls ./cert.pem ./key.pem\n}\n"} {
		tokens, err := scanCaddyfile([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		if err := checkCaddyInputPaths("Caddyfile", tokens); err == nil {
			t.Fatal("relative resource accepted")
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

func TestInstalledWelcomeAndUnknownHost(t *testing.T) {
	if _, err := exec.LookPath("caddy"); err != nil {
		t.Skip("Caddy not installed")
	}
	// Run the generated sites on disposable high ports. Native service acceptance
	// separately verifies installed ports 80/443 without touching personal services.
	port := func() int {
		t.Helper()
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	httpPort, httpsPort := port(), port()
	dir := shortHome(t)
	admin := "unix/" + filepath.Join(dir, "admin.sock")
	routes, err := renderInstalledRoutes(config{Version: 2, HTTPPort: 80, HTTPSPort: 443}, false)
	if err != nil {
		t.Fatal(err)
	}
	routes = strings.ReplaceAll(routes, ":443", ":"+strconv.Itoa(httpsPort))
	routes = strings.ReplaceAll(routes, ":80", ":"+strconv.Itoa(httpPort))
	routes = strings.ReplaceAll(routes, "redir https://sandbar.localhost{uri}", "redir https://sandbar.localhost:"+strconv.Itoa(httpsPort)+"{uri}")
	global := renderInstalledGlobals(admin, "", "")
	text := "{\n" + global + "http_port " + strconv.Itoa(httpPort) + "\nhttps_port " + strconv.Itoa(httpsPort) + "\nstorage file_system " + strconv.Quote(filepath.Join(dir, "storage")) + "\n}\n" + routes
	text += "http://other.localhost:" + strconv.Itoa(httpPort) + " {\nbind 127.0.0.1\nrespond unrelated\n}\n"
	file := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(file, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "caddy", "run", "--config", file, "--adapter", "caddyfile")
	command.Env = append(os.Environ(), "HOME="+dir, "XDG_DATA_HOME="+filepath.Join(dir, "data"), "XDG_CONFIG_HOME="+filepath.Join(dir, "config"))
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Signal(syscall.SIGTERM)
		if err := command.Wait(); err != nil && ctx.Err() != nil {
			t.Errorf("Caddy test timed out: %v", err)
		}
		if t.Failed() {
			t.Log(diagnostic.String())
		}
	}()
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(host string) (int, string, string, error) {
		req, err := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/test?item=1", nil)
		if err != nil {
			return 0, "", "", err
		}
		req.Host = host
		response, err := client.Do(req)
		if err != nil {
			return 0, "", "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return response.StatusCode, response.Header.Get("Location"), string(body), err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, _, err = request("sandbar.localhost")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Caddy did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	socketInfo, err := os.Stat(filepath.Join(dir, "admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if socketInfo.Mode().Perm() != installedFileMode {
		t.Fatalf("admin socket mode: %v", socketInfo.Mode())
	}
	code, location, _, err := request("sandbar.localhost")
	if err != nil || code != 308 || location != "https://sandbar.localhost:"+strconv.Itoa(httpsPort)+"/test?item=1" {
		t.Fatalf("configured host: %d %q %v", code, location, err)
	}
	code, location, _, err = request("unknown.localhost")
	if err != nil || code != 404 || location != "" {
		t.Fatalf("unknown host: %d %q %v", code, location, err)
	}
	code, _, body, err := request("other.localhost")
	if err != nil || code != 200 || body != "unrelated" {
		t.Fatalf("unrelated site: %d %q %v", code, body, err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "storage/pki/authorities/sandbar/root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("invalid generated root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)))
	}}
	defer transport.CloseIdleConnections()
	httpsClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	var response *http.Response
	deadline = time.Now().Add(5 * time.Second)
	for {
		response, err = httpsClient.Get("https://sandbar.localhost:" + strconv.Itoa(httpsPort) + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer response.Body.Close()
	welcome, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 || !bytes.Contains(welcome, []byte("sandbar add netbox.sandbar.localhost 8000")) {
		t.Fatalf("welcome: %d %v", response.StatusCode, err)
	}
}

func TestInstalledCustomCatchallRejected(t *testing.T) {
	if _, err := exec.LookPath("caddy"); err != nil {
		t.Skip("Caddy not installed")
	}
	c := config{Version: 2, HTTPPort: 80, HTTPSPort: 443}
	routes, err := renderInstalledRoutes(c, false)
	if err != nil {
		t.Fatal(err)
	}
	dir := shortHome(t)
	admin := "unix/" + filepath.Join(dir, "admin.sock")
	source := "{\n" + renderInstalledGlobals(admin, "", "") + "}\n" + routes + "http://:80 {\nbind 127.0.0.1\nrespond custom\n}\n"
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("caddy", "adapt", "--config", path, "--adapter", "caddyfile")
	output, err := command.Output()
	if err == nil && checkInstalledAdapted(output, c, admin) == nil {
		t.Fatal("custom catchall accepted alongside Sandbar fallback")
	}
}

func TestInstalledStaticFilenameImport(t *testing.T) {
	dir := shortHome(t)
	top := filepath.Join(dir, "Caddyfile")
	source := []byte("import sites\n")
	if err := os.WriteFile(top, source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sites"), []byte("# static file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	output, manifest, err := composeCandidate(top, source, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output, []byte("# static file")) || len(manifest.Files) != 2 {
		t.Fatal("static filename import lost")
	}
}

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func requireIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("SANDBAR_INTEGRATION") != "1" {
		t.Skip("set SANDBAR_INTEGRATION=1 to run real Caddy acceptance")
	}
	if _, err := exec.LookPath("caddy"); err != nil {
		t.Fatal("integration requires Caddy:", err)
	}
}

func TestIntegrationGoldenValidation(t *testing.T) {
	requireIntegration(t)
	fixtures, err := filepath.Glob("testdata/*.caddyfile")
	if err != nil || len(fixtures) != 4 {
		t.Fatalf("fixtures: %v %v", fixtures, err)
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			home := filepath.Join(shortHome(t), "quoted \"home\"")
			p, err := resolvePaths(home)
			if err != nil {
				t.Fatal(err)
			}
			if err := withLock(p, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			content := strings.ReplaceAll(string(data), "@STATE@", strings.TrimSuffix(strings.TrimPrefix(strconv.Quote(p.state), `"`), `"`))
			if !strings.Contains(content, "skip_install_trust") {
				t.Fatal("fixture permits trust installation")
			}
			if err := checkCaddy(p, io.Discard); err != nil {
				t.Fatal(err)
			}
			if err := validateAndReplace(p, content, io.Discard, os.Stderr); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(p.file("caddy/pki/authorities/local/root.crt")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(shortHome(t), "sandbar")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", bin, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return bin
}

func runBinary(t *testing.T, bin, home string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, append([]string{"--home", home}, args...)...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("CLI did not exit: %s: %s", args, output)
	}
	if err != nil {
		if result, ok := err.(*exec.ExitError); ok {
			return result.ExitCode(), string(output)
		}
		t.Fatalf("CLI launch: %v", err)
	}
	return 0, string(output)
}

func freePorts(t *testing.T) (int, int) {
	t.Helper()
	first, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	return first.Addr().(*net.TCPAddr).Port, second.Addr().(*net.TCPAddr).Port
}

func initRouter(t *testing.T, bin string, upstream int) (paths, config) {
	t.Helper()
	home := shortHome(t)
	httpPort, httpsPort := freePorts(t)
	code, output := runBinary(t, bin, home, "init", "--http-port", strconv.Itoa(httpPort), "--https-port", strconv.Itoa(httpsPort), "netbox.sandbar.localhost", strconv.Itoa(upstream))
	if code != 0 {
		t.Fatalf("init %d: %s", code, output)
	}
	p := testPaths(t, home)
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	return p, c
}

func startRouter(t *testing.T, bin string, p paths) {
	t.Helper()
	cleanupRouter(t, bin, p)
	code, output := runBinary(t, bin, filepath.Dir(p.config), "start")
	if code != 0 {
		t.Fatalf("start %d: %s", code, output)
	}
	for _, value := range []string{"HTTPS:", p.file("caddy/pki/authorities/local/root.crt"), p.file("caddy.log")} {
		if !strings.Contains(output, value) {
			t.Fatal(output)
		}
	}
}

func routerClient(t *testing.T, p paths, ip string) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(p.file("caddy/pki/authorities/local/root.crt"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("invalid root certificate")
	}
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func getResponse(t *testing.T, client *http.Client, url string) (*http.Response, []byte) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func waitForTLS(t *testing.T, client *http.Client, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := client.Get(url)
		if err == nil {
			response.Body.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("TLS never became available: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitForClosed(t *testing.T, ports ...int) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for {
		open := false
		for _, port := range ports {
			for _, ip := range []string{"127.0.0.1", "::1"} {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 100*time.Millisecond)
				if err == nil {
					conn.Close()
					open = true
				}
			}
		}
		if !open {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("listeners remain open after stop", ports)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestIntegrationLifecycle(t *testing.T) {
	requireIntegration(t)
	bin := buildCLI(t)
	isolated := shortHome(t)
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		t.Setenv(key, isolated)
	}
	var requests atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "proto": r.Header.Get("X-Forwarded-Proto"), "forwarded_host": r.Header.Get("X-Forwarded-Host"), "client": r.Header.Get("X-Forwarded-For"), "uri": r.RequestURI})
	}))
	defer backend.Close()
	upstream := backend.Listener.Addr().(*net.TCPAddr).Port
	p, c := initRouter(t, bin, upstream)
	startRouter(t, bin, p)
	socketInfo, err := os.Stat(p.file("admin.sock"))
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm()&0077 != 0 {
		t.Fatalf("private admin socket: %v %v", socketInfo, err)
	}
	client := routerClient(t, p, "127.0.0.1")
	// Readiness waits belong only to this acceptance test, never the CLI.
	waitForTLS(t, client, c.httpsURL()+"/ready")
	before := requests.Load()
	uri := "/api/items%20here?limit=1&value=a%2Fb"
	httpURL := fmt.Sprintf("http://%s:%d%s", c.Hostname, c.HTTPPort, uri)
	response, body := getResponse(t, client, httpURL)
	if response.StatusCode != 308 || response.Header.Get("Location") != c.httpsURL()+uri {
		t.Fatalf("redirect: %d %v %s", response.StatusCode, response.Header, body)
	}
	if requests.Load() != before {
		t.Fatal("HTTP request reached backend")
	}
	response, body = getResponse(t, client, fmt.Sprintf("http://unrelated.localhost:%d/", c.HTTPPort))
	if response.Header.Get("Location") != "" || len(body) != 0 || requests.Load() != before {
		t.Fatalf("unmatched host reached route: %v %s", response.Header, body)
	}
	client.CheckRedirect = nil
	response, body = getResponse(t, client, httpURL)
	if response.StatusCode != 200 || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		t.Fatalf("unverified HTTPS: %d %s", response.StatusCode, body)
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", response.Proto)
	}
	var headers map[string]string
	if err := json.Unmarshal(body, &headers); err != nil {
		t.Fatal(err)
	}
	host := fmt.Sprintf("%s:%d", c.Hostname, c.HTTPSPort)
	for key, want := range map[string]string{"host": host, "proto": "https", "forwarded_host": host, "client": "127.0.0.1", "uri": uri} {
		if headers[key] != want {
			t.Fatalf("%s=%q, want %q", key, headers[key], want)
		}
	}
	pidData, err := os.ReadFile(p.file("caddy.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid := strings.TrimSpace(string(pidData))
	executable, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil || filepath.Base(executable) != "caddy" {
		t.Fatalf("persistent process: %s %v", executable, err)
	}
	checkListenerEvidence(t, c, pid)
	t.Run("non-loopback", func(t *testing.T) { checkNonLoopback(t, c) })
	t.Run("IPv6", func(t *testing.T) {
		available, err := ipv6Available(probeIPv6, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !available {
			t.Skip("IPv6 loopback is unavailable")
		}
		v6 := routerClient(t, p, "::1")
		response, _ := getResponse(t, v6, httpURL)
		if response.StatusCode != 308 {
			t.Fatal(response.StatusCode)
		}
		response, _ = getResponse(t, v6, c.httpsURL()+uri)
		if response.StatusCode != 200 || response.TLS == nil {
			t.Fatal("IPv6 TLS route failed")
		}
	})
	// A second private instance must survive a stop of the first instance.
	other, otherConfig := initRouter(t, bin, upstream)
	startRouter(t, bin, other)
	otherClient := routerClient(t, other, "127.0.0.1")
	waitForTLS(t, otherClient, otherConfig.httpsURL())
	if code, output := runBinary(t, bin, filepath.Dir(p.config), "start"); code == 0 || !strings.Contains(output, "already running") {
		t.Fatalf("repeated start: %d %s", code, output)
	}
	// Source changes and stale PID contents must not change stop's destination.
	if err := os.WriteFile(p.config, []byte("malformed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("caddy.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if code, output := runBinary(t, bin, filepath.Dir(p.config), "stop"); code != 0 {
		t.Fatalf("stop: %d %s", code, output)
	}
	waitForClosed(t, c.HTTPPort, c.HTTPSPort)
	response, _ = getResponse(t, otherClient, otherConfig.httpsURL())
	if response.StatusCode != 200 {
		t.Fatal("other instance was affected")
	}
	if code, output := runBinary(t, bin, filepath.Dir(p.config), "stop"); code == 0 {
		t.Fatalf("repeated stop became success: %s", output)
	}
	if _, err := os.Stat(p.file("caddy/pki/authorities/local/root.crt")); err != nil {
		t.Fatal("stop removed CA", err)
	}
	if err := filepath.WalkDir(p.state, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() && info.Mode().Perm() != 0700 {
			return fmt.Errorf("directory %s mode %o", path, info.Mode().Perm())
		}
		if info.Mode().IsRegular() && info.Mode().Perm() != 0600 {
			return fmt.Errorf("file %s mode %o", path, info.Mode().Perm())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".pki", ".local", "caddy", ".config", ".mozilla"} {
		if _, err := os.Stat(filepath.Join(isolated, name)); !os.IsNotExist(err) {
			t.Fatalf("Caddy wrote outside router state: %s", name)
		}
	}
	t.Logf("native lifecycle verified with Caddy PID %s; Sandbar invocations exited before requests", pid)
}

func checkListenerEvidence(t *testing.T, c config, pid string) {
	t.Helper()
	output, err := exec.Command("ss", "-H", "-ltnp").CombinedOutput()
	if err != nil {
		t.Fatalf("ss required: %v %s", err, output)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		address := fields[3]
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		if port != strconv.Itoa(c.HTTPPort) && port != strconv.Itoa(c.HTTPSPort) {
			continue
		}
		if host != "127.0.0.1" && host != "::1" {
			t.Fatalf("non-loopback listener: %s", line)
		}
		if !strings.Contains(line, "pid="+pid+",") {
			t.Fatalf("listener is not owned by Caddy: %s", line)
		}
		seen[address] = true
		t.Log(line)
	}
	ips := []string{"127.0.0.1"}
	available, err := ipv6Available(probeIPv6, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if available {
		ips = append(ips, "::1")
	}
	for _, ip := range ips {
		for _, port := range []int{c.HTTPPort, c.HTTPSPort} {
			if !seen[net.JoinHostPort(ip, strconv.Itoa(port))] {
				t.Fatalf("missing listener: %s:%d", ip, port)
			}
		}
	}
	output, err = exec.Command("ss", "-H", "-lun").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		_, port, _ := net.SplitHostPort(fields[3])
		if port == strconv.Itoa(c.HTTPPort) || port == strconv.Itoa(c.HTTPSPort) {
			t.Fatalf("unexpected UDP listener: %s", line)
		}
	}
}

func checkNonLoopback(t *testing.T, c config) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	checked := false
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		for _, port := range []int{c.HTTPPort, c.HTTPSPort} {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)), 500*time.Millisecond)
			if err == nil {
				conn.Close()
				t.Fatalf("non-loopback connection accepted: %s:%d", ip, port)
			}
		}
		checked = true
	}
	if !checked {
		t.Skip("no non-loopback IPv4 interface is available")
	}
}

func TestIntegrationPortConflicts(t *testing.T) {
	requireIntegration(t)
	bin := buildCLI(t)
	for _, field := range []string{"HTTP", "HTTPS"} {
		t.Run(field, func(t *testing.T) {
			p, c := initRouter(t, bin, 8000)
			port := c.HTTPPort
			if field == "HTTPS" {
				port = c.HTTPSPort
			}
			listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			cleanupRouter(t, bin, p)
			code, output := runBinary(t, bin, filepath.Dir(p.config), "start")
			if code == 0 || !strings.Contains(output, "address already in use") || !strings.Contains(output, "Caddy log:") {
				t.Fatalf("conflict: %d %s", code, output)
			}
			listener.Close()
			waitForClosed(t, c.HTTPPort, c.HTTPSPort)
		})
	}
}

// Register before startup so an assertion failure still stops the owned router.
func cleanupRouter(t *testing.T, bin string, p paths) {
	t.Helper()
	t.Cleanup(func() {
		conn, err := net.DialTimeout("unix", p.file("admin.sock"), time.Second)
		// Failed Caddy startup can leave a socket file without a server.
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return
		}
		if err != nil {
			t.Errorf("connect to admin socket during cleanup: %v", err)
			return
		}
		conn.Close()
		if code, output := runBinary(t, bin, filepath.Dir(p.config), "stop"); code != 0 {
			t.Errorf("cleanup stop %d: %s", code, output)
		}
	})
}

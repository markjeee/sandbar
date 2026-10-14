package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func teleportTestRouter(t *testing.T, bin, machine string, routes []route) (paths, config) {
	t.Helper()
	p := testPaths(t, shortHome(t))
	httpPort, httpsPort := freePorts(t)
	c := config{Version: 3, Machine: machine, HTTPPort: httpPort, HTTPSPort: httpsPort, Routes: routes}
	if err := withLock(p, func() error { return writeConfig(p.config, c) }); err != nil {
		t.Fatal(err)
	}
	startRouter(t, bin, p)
	client := routerClient(t, p, "127.0.0.1")
	waitForTLS(t, client, c.routeURL(machineHostname(machine)))
	return p, c
}

func publishTeleportTestConfig(t *testing.T, p paths, c config) error {
	t.Helper()
	return withLock(p, func() error {
		source, err := os.ReadFile(p.config)
		if err != nil {
			return err
		}
		return publishConfig(p, source, c, false, io.Discard, os.Stderr)
	})
}

// This forwarding fixture copies TCP bytes only. SSH authentication and
// connection ownership are covered separately by command and host acceptance.
func teleportTestForward(t *testing.T, target int) (int, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	closed := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			incoming, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				incoming.Close()
				return
			}
			connections[incoming] = true
			mu.Unlock()
			go func() {
				defer incoming.Close()
				outgoing, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(target)), time.Second)
				if err != nil {
					return
				}
				mu.Lock()
				if closed {
					mu.Unlock()
					outgoing.Close()
					return
				}
				connections[outgoing] = true
				mu.Unlock()
				defer outgoing.Close()
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(outgoing, incoming); outgoing.Close(); close(copied) }()
				_, _ = io.Copy(incoming, outgoing)
				incoming.Close()
				<-copied
			}()
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			mu.Lock()
			closed = true
			listener.Close()
			for connection := range connections {
				connection.Close()
			}
			mu.Unlock()
			<-done
		})
	}
	t.Cleanup(stop)
	return listener.Addr().(*net.TCPAddr).Port, stop
}

func TestIntegrationTeleportRouting(t *testing.T) {
	requireIntegration(t)
	bin := buildCLI(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/socket" {
			teleportWebSocketBackend(t, w, r)
			return
		}
		w.Header().Set("Location", "/app-login?from=remote")
		http.SetCookie(w, &http.Cookie{Name: "app", Value: "remote", Path: "/", SameSite: http.SameSiteLaxMode})
		_ = json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "uri": r.URL.RequestURI(), "proto": r.Header.Get("X-Forwarded-Proto"), "forwarded_host": r.Header.Get("X-Forwarded-Host")})
	}))
	defer backend.Close()
	remote, remoteConfig := teleportTestRouter(t, bin, "remote", []route{{Hostname: "api.website.sandbar.localhost", Upstream: backend.URL}})
	forwardPort, disconnect := teleportTestForward(t, remoteConfig.HTTPSPort)
	local, localConfig := teleportTestRouter(t, bin, "local", nil)
	localClient := routerClient(t, local, "127.0.0.1")
	remoteRoot := readTestFile(t, remote.file("caddy/pki/authorities/local/root.crt"))
	localRoot := readTestFile(t, local.file("caddy/pki/authorities/local/root.crt"))
	if bytes.Equal(localRoot, remoteRoot) {
		t.Fatal("routers share a CA")
	}
	destination := teleportDestination{Machine: "remote", Host: "127.0.0.1", User: "developer", Port: 22, HTTPSPort: remoteConfig.HTTPSPort, LocalPort: forwardPort, RootPEM: string(remoteRoot)}
	localConfig.Teleports = []teleportDestination{destination}
	if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(string(readTestFile(t, local.file("caddy.log"))))
			t.Log(string(readTestFile(t, remote.file("caddy.log"))))
		}
	})
	host := "api.website.sandbar-remote.localhost"
	permission := func(domain, address string) int {
		t.Helper()
		request, err := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(localConfig.HTTPPort)+teleportCertificatePath+"?domain="+url.QueryEscape(domain), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = address
		response, err := localClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if code := permission(host, "127.0.0.1"); code != 204 {
		t.Fatalf("permission: got %d, want204", code)
	}
	for _, denied := range []string{"api.website.sandbar-unknown.localhost", "-bad.sandbar-remote.localhost", "a..sandbar-remote.localhost", strings.Repeat("a", 64) + ".sandbar-remote.localhost", strings.Repeat("a.", 130) + "sandbar-remote.localhost"} {
		if code := permission(denied, "127.0.0.1"); code == 204 {
			t.Fatalf("permission admitted %s", denied)
		}
	}
	if code := permission(host, "unknown.localhost"); code == 204 {
		t.Fatal("permission accepts non-loopback Host")
	}
	response, body := getResponse(t, localClient, localConfig.routeURL(host)+"/path?q=1")
	if response.StatusCode != 200 {
		t.Fatalf("on-demand nested routing: %d %s", response.StatusCode, body)
	}
	var echo map[string]string
	if err := json.Unmarshal(body, &echo); err != nil {
		t.Fatal(err)
	}
	expectedHost := host + ":" + strconv.Itoa(localConfig.HTTPSPort)
	if echo["host"] != expectedHost || echo["uri"] != "/path?q=1" || echo["proto"] != "https" || echo["forwarded_host"] != expectedHost {
		t.Fatalf("changed external URL: %v", echo)
	}
	if response.Header.Get("Location") != "/app-login?from=remote" || !strings.Contains(response.Header.Get("Set-Cookie"), "app=remote") {
		t.Fatal("changed app response headers")
	}
	if response.TLS == nil || response.TLS.PeerCertificates[0].VerifyHostname(host) != nil {
		t.Fatal("nested certificate does not match")
	}
	if err := response.TLS.PeerCertificates[0].VerifyHostname("other." + host); err == nil {
		t.Fatal("nested certificate is not exact")
	}
	response, _ = getResponse(t, localClient, "http://"+host+":"+strconv.Itoa(localConfig.HTTPPort)+"/path?q=1")
	if response.StatusCode != 308 || response.Header.Get("Location") != localConfig.routeURL(host)+"/path?q=1" {
		t.Fatalf("redirect %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	response, _ = getResponse(t, localClient, localConfig.routeURL(machineHostname("remote")))
	if response.StatusCode != 200 {
		t.Fatalf("destination welcome: %d", response.StatusCode)
	}
	// A newly added remote app needs no client source or generated-file update.
	beforeSource := readTestFile(t, local.config)
	beforeGenerated := readTestFile(t, local.file("Caddyfile"))
	remoteConfig.Routes = append(remoteConfig.Routes, route{Hostname: "new.api.sandbar.localhost", Upstream: backend.URL})
	if err := publishTeleportTestConfig(t, remote, remoteConfig); err != nil {
		t.Fatal(err)
	}
	response, body = getResponse(t, localClient, localConfig.routeURL("new.api.sandbar-remote.localhost")+"/new")
	if response.StatusCode != 200 {
		t.Fatalf("new app: %d %s", response.StatusCode, body)
	}
	if !bytes.Equal(beforeSource, readTestFile(t, local.config)) || !bytes.Equal(beforeGenerated, readTestFile(t, local.file("Caddyfile"))) {
		t.Fatal("new app changed client registration")
	}
	teleportWebSocketClient(t, localClient, localConfig, host)
	// Remote trust is confined to its proxy. Local root remains browser-facing.
	localConfig.Teleports[0].RootPEM = string(localRoot)
	if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
		t.Fatal(err)
	}
	response, _ = getResponse(t, localClient, localConfig.routeURL(host))
	if response.StatusCode != 502 {
		t.Fatalf("wrong remote root: %d", response.StatusCode)
	}
	localConfig.Teleports[0].RootPEM = string(remoteRoot)
	if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
		t.Fatal(err)
	}
	// Trust alone is insufficient when the fixed remote TLS identity differs.
	localConfig.Teleports[0].Machine = "wrong-identity"
	if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
		t.Fatal(err)
	}
	response, _ = getResponse(t, localClient, localConfig.routeURL("app.sandbar-wrong-identity.localhost"))
	if response.StatusCode != 502 {
		t.Fatalf("wrong remote TLS identity: %d", response.StatusCode)
	}
	localConfig.Teleports[0].Machine = "remote"
	if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
		t.Fatal(err)
	}
	// An unmatched namespace cannot obtain a new certificate.
	response, err := localClient.Get(localConfig.routeURL("app.sandbar-unknown.localhost"))
	if err == nil {
		response.Body.Close()
		t.Fatal("unregistered namespace obtained TLS")
	}
	disconnect()
	response, body = getResponse(t, localClient, localConfig.routeURL(host))
	if response.StatusCode != 502 || len(body) != 0 {
		t.Fatalf("disconnected response: %d %q", response.StatusCode, body)
	}
	localConfig.Teleports = nil
	if err := publishTeleportTestConfig(t, local, localConfig); err != nil {
		t.Fatal(err)
	}
	if code := permission(host, "127.0.0.1"); code == 204 {
		t.Fatal("removed destination retains issuance permission")
	}
	if bytes.Contains(readTestFile(t, local.file("Caddyfile")), []byte("tls_trust_pool")) {
		t.Fatal("removed destination retained trust")
	}
	if !bytes.Equal(localRoot, readTestFile(t, local.file("caddy/pki/authorities/local/root.crt"))) || !bytes.Equal(remoteRoot, readTestFile(t, remote.file("caddy/pki/authorities/local/root.crt"))) {
		t.Fatal("CA identity changed")
	}
	// The endpoint shares the existing HTTP listener. No extra state listener exists.
	if _, err := os.Stat(filepath.Join(local.state, "admin.sock")); err != nil {
		t.Fatal(err)
	}
}

func teleportWebSocketBackend(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "upgrade required", 400)
		return
	}
	connection, buffer, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Error(err)
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
	if err := buffer.Flush(); err != nil {
		t.Error(err)
		return
	}
	frame := make([]byte, 8)
	if _, err := io.ReadFull(buffer, frame); err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(frame, []byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}) {
		t.Errorf("changed WebSocket frame %x", frame)
		return
	}
	_, err = connection.Write([]byte{0x81, 2, 'o', 'k'})
	if err != nil {
		t.Error(err)
	}
}

func teleportWebSocketClient(t *testing.T, client *http.Client, c config, host string) {
	t.Helper()
	transport := client.Transport.(*http.Transport)
	tlsConfig := transport.TLSClientConfig.Clone()
	tlsConfig.ServerName = host
	tlsConfig.NextProtos = []string{"http/1.1"}
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(c.HTTPSPort)), tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(connection, "GET /socket HTTP/1.1\r\nHost: %s:%d\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", host, c.HTTPSPort)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("WebSocket upgrade: %d", response.StatusCode)
	}
	if _, err := connection.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}); err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4)
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame, []byte{0x81, 2, 'o', 'k'}) {
		t.Fatalf("WebSocket reply %x", frame)
	}
}

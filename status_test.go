package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func statusCertificate(t *testing.T, hostname string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func statusHTTPS(t *testing.T, hostname string, handler http.Handler) (config, *x509.CertPool, []byte) {
	t.Helper()
	certificate, root := statusCertificate(t, hostname)
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	httpsPort, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	c := config{Version: 2, HTTPPort: 80, HTTPSPort: httpsPort, Routes: []route{{Hostname: hostname, Upstream: "http://127.0.0.1:8000"}}}
	return c, roots, root
}

func TestStatusHTTPSResponses(t *testing.T) {
	for _, code := range []int{200, 301, 404, 500, 503} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var requests atomic.Int32
			c, roots, _ := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodHead || r.URL.RequestURI() != "/" || !strings.HasPrefix(r.Host, "app.sandbar.localhost:") {
					t.Errorf("unexpected route check: %s %s %s", r.Method, r.Host, r.URL)
				}
				w.Header().Set("Location", "/redirect-target")
				w.WriteHeader(code)
			}))
			got, err := checkHTTPSRoute(c, c.Routes[0], roots)
			if err != nil || got != code || requests.Load() != 1 {
				t.Fatalf("code=%d err=%v requests=%d", got, err, requests.Load())
			}
		})
	}
}

func TestStatusHTTPSVerification(t *testing.T) {
	c, roots, _ := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for _, mismatch := range []bool{false, true} {
		name := "untrusted root"
		pool := x509.NewCertPool()
		r := c.Routes[0]
		if mismatch {
			name = "hostname mismatch"
			pool = roots
			r.Hostname = "other.sandbar.localhost"
		}
		t.Run(name, func(t *testing.T) {
			_, err := checkHTTPSRoute(c, r, pool)
			var tlsErr *routeTLSError
			if !errors.As(err, &tlsErr) {
				t.Fatalf("want TLS error, got %v", err)
			}
		})
	}
	// No proxy or resolver can substitute the checked endpoint.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	if code, err := checkHTTPSRoute(c, c.Routes[0], roots); err != nil || code != 200 {
		t.Fatalf("proxy environment changed check: %d %v", code, err)
	}
}

func TestStatusConnectionAndTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	c := config{HTTPSPort: port}
	r := route{Hostname: "app.sandbar.localhost"}
	_, err = checkHTTPSRoute(c, r, x509.NewCertPool())
	var tlsErr *routeTLSError
	if err == nil || errors.As(err, &tlsErr) {
		t.Fatalf("want connection error, got %v", err)
	}
	listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c.HTTPSPort = listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	start := time.Now()
	_, err = checkHTTPSRoute(c, r, x509.NewCertPool())
	if err == nil || time.Since(start) > routeCheckTimeout+2*time.Second {
		t.Fatalf("unbounded route check: %s %v", time.Since(start), err)
	}
	select {
	case conn := <-accepted:
		conn.Close()
	default:
		t.Fatal("route did not dial loopback")
	}
}

func statusAdmin(t *testing.T, p paths, active string) {
	t.Helper()
	listener, err := net.Listen("unix", p.file("admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/config/" {
			t.Errorf("unexpected admin query: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, active)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
}

func statusGenerated(t *testing.T, p paths, c config) {
	t.Helper()
	generated, err := renderCaddyfile(c, p, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("Caddyfile"), []byte(generated), 0600); err != nil {
		t.Fatal(err)
	}
}

func statusAdapt(t *testing.T, adapted string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "caddy"), []byte("#!/bin/sh\ncase \"$1\" in\nversion) printf '%s\\n' 'v2.11.7' ;;\nadapt) printf '%s\\n' \"$STATUS_ADAPTED\" ;;\n*) exit 90 ;;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("STATUS_ADAPTED", adapted)
}

func TestStatusStoppedAndInaccessible(t *testing.T) {
	for _, inaccessible := range []bool{false, true} {
		t.Run(strconv.FormatBool(inaccessible), func(t *testing.T) {
			p := initialized(t)
			if inaccessible {
				if err := os.Symlink("admin.sock", p.file("admin.sock")); err != nil {
					t.Fatal(err)
				}
			}
			var out, errOut bytes.Buffer
			err := status(p, &out, &errOut)
			state := "Router: stopped"
			if inaccessible {
				state = "Router: inaccessible"
			}
			if err == nil || !strings.Contains(out.String(), state) {
				t.Fatalf("%v %s %s", err, &out, &errOut)
			}
		})
	}
}

func TestStatusPendingAndRecovery(t *testing.T) {
	p := initialized(t)
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	statusGenerated(t, p, c)
	statusAdmin(t, p, `{"apps":{}}`)
	statusAdapt(t, `{"apps":{}}`)
	if err := os.Mkdir(p.file("transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("transaction/journal.json"), []byte("invalid journal"), 0600); err != nil {
		t.Fatal(err)
	}
	// A valid manual source edit must remain available after a read-only status.
	c.Routes[0].Upstream = "http://127.0.0.1:8001"
	data, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.config, data, 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if err := status(p, &out, &errOut); err == nil {
		t.Fatal("accepted pending source and recovery")
	}
	for _, want := range []string{"Router: running", "Recovery: pending:", p.file("transaction"), "source differs from generated"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, &out)
		}
	}
	if !bytes.Equal(readTestFile(t, p.config), data) || string(readTestFile(t, p.file("transaction/journal.json"))) != "invalid journal" {
		t.Fatal("status changed pending files")
	}
}

func TestStatusHTTPResultAndActivePending(t *testing.T) {
	for _, code := range []int{301, 404, 503} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			c, _, root := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
			p := initialized(t)
			data, err := configBytes(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.config, data, 0600); err != nil {
				t.Fatal(err)
			}
			statusGenerated(t, p, c)
			rootPath := p.file("caddy/pki/authorities/local/root.crt")
			if err := os.MkdirAll(filepath.Dir(rootPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(rootPath, root, 0600); err != nil {
				t.Fatal(err)
			}
			statusAdmin(t, p, `{"apps":{}}`)
			statusAdapt(t, `{"apps":{}}`)
			var out, errOut bytes.Buffer
			err = status(p, &out, &errOut)
			if (err != nil) != (code >= 500) || !strings.Contains(out.String(), "HTTP "+strconv.Itoa(code)) || !strings.Contains(out.String(), "Configuration: current") {
				t.Fatalf("%v %s %s", err, &out, &errOut)
			}
			t.Setenv("STATUS_ADAPTED", `{"apps":{"http":{}}}`)
			out.Reset()
			if err := status(p, &out, &errOut); err == nil || !strings.Contains(out.String(), "generated configuration differs from active") {
				t.Fatalf("missing pending active state: %v %s", err, &out)
			}
		})
	}
}

func TestStatusInvalidSourceAndRoot(t *testing.T) {
	p := initialized(t)
	if err := os.WriteFile(p.config, []byte("invalid source"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := status(p, &out, io.Discard); err == nil || !strings.Contains(out.String(), "Router: stopped") || !strings.Contains(out.String(), "Configuration: invalid") {
		t.Fatalf("%v %s", err, &out)
	}
	path := filepath.Join(t.TempDir(), "root.crt")
	if _, err := selectedStatusRoots(path); err == nil {
		t.Fatal("accepted missing root")
	}
	if err := os.WriteFile(path, []byte("not PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := selectedStatusRoots(path); err == nil {
		t.Fatal("accepted invalid root")
	}
}

func TestStatusAdminTimeout(t *testing.T) {
	p := initialized(t)
	listener, err := net.Listen("unix", p.file("admin.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	var out bytes.Buffer
	start := time.Now()
	err = status(p, &out, io.Discard)
	if err == nil || !strings.Contains(out.String(), "Router: inaccessible") || time.Since(start) > 5*time.Second {
		t.Fatalf("admin check: %s %v %s", time.Since(start), err, &out)
	}
	select {
	case conn := <-accepted:
		conn.Close()
	default:
		t.Fatal("status did not query private endpoint")
	}
}

func TestStatusReportsTLSError(t *testing.T) {
	c, _, _ := statusHTTPS(t, "other.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	c.Routes[0].Hostname = "app.sandbar.localhost"
	p := initialized(t)
	data, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.config, data, 0600); err != nil {
		t.Fatal(err)
	}
	statusGenerated(t, p, c)
	_, root := statusCertificate(t, "app.sandbar.localhost")
	rootPath := p.file("caddy/pki/authorities/local/root.crt")
	if err := os.MkdirAll(filepath.Dir(rootPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rootPath, root, 0600); err != nil {
		t.Fatal(err)
	}
	statusAdmin(t, p, `{}`)
	statusAdapt(t, `{}`)
	var out bytes.Buffer
	if err := status(p, &out, io.Discard); err == nil || !strings.Contains(out.String(), "TLS error:") || strings.Contains(out.String(), "connection error:") {
		t.Fatalf("%v %s", err, &out)
	}
}

func TestStatusEmptyRouter(t *testing.T) {
	p := initialized(t)
	c := config{Version: 2, HTTPPort: 8080, HTTPSPort: 8443, Routes: []route{}}
	data, err := configBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.config, data, 0600); err != nil {
		t.Fatal(err)
	}
	generated, err := renderCaddyfile(c, p, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("Caddyfile"), []byte(generated), 0600); err != nil {
		t.Fatal(err)
	}
	statusAdmin(t, p, `{}`)
	statusAdapt(t, `{}`)
	code, out, errOut := cli(t, "--home", filepath.Dir(p.config), "status")
	if code != 0 || !strings.Contains(out, "Router: running") || !strings.Contains(out, "Configuration: current") || !strings.Contains(out, "Routes: none") {
		t.Fatalf("%d %s %s", code, out, errOut)
	}
}

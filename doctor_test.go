package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoctorMissingHomeDoesNotPrepareRuntime(t *testing.T) {
	home := filepath.Join(t.TempDir(), "missing")
	var out bytes.Buffer
	err := doctor(home, &out, io.Discard)
	if err == nil {
		t.Fatal("missing prerequisites succeeded")
	}
	if _, err := os.Stat(home); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("home changed: %v", err)
	}
	for _, want := range []string{"failure: source:", "Caddy:", "private admin:", "recovery:", "unknown: browser:", "--home '" + home + "' config --print"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "run sandbar --home '"+home+"' start") {
		t.Fatal("start suggested before invalid source was fixed")
	}
}

func TestDoctorInvalidSourceContinuesIndependentChecks(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "config.json")
	original := []byte("{bad\n")
	if err := os.WriteFile(source, original, 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := doctor(home, &out, io.Discard); err == nil {
		t.Fatal("invalid source succeeded")
	}
	after, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, actual) || before.Mode() != after.Mode() || len(entries) != 1 {
		t.Fatal("observation changed source or directory entries")
	}
	for _, want := range []string{"failure: source:", "Caddy:", "private admin:", "recovery: none"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func TestDoctorHTTPSLayers(t *testing.T) {
	for _, code := range []int{200, 301, 404, 502} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			var count atomic.Int32
			c, roots, _ := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count.Add(1)
				if r.Method != http.MethodHead || r.URL.RequestURI() != "/" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				}
				w.Header().Set("Location", "https://elsewhere.invalid/")
				w.WriteHeader(code)
			}))
			got, err := checkHTTPSAt(c, "app.sandbar.localhost", "127.0.0.1", roots, time.Second)
			if err != nil || got != code || count.Load() != 1 {
				t.Fatalf("code=%d count=%d err=%v", got, count.Load(), err)
			}
			var out bytes.Buffer
			report := &doctorReport{out: &out}
			doctorHTTPSResult(report, c, "app.sandbar.localhost", "127.0.0.1", "IPv4 selected CA", roots)
			if report.failed != (code >= 500) {
				t.Fatalf("failure=%v: %s", report.failed, out.String())
			}
		})
	}
}

func TestDoctorHTTPSVerificationAndDeadline(t *testing.T) {
	c, roots, _ := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	for _, pool := range []*x509.CertPool{nil, x509.NewCertPool()} {
		if _, err := checkHTTPSAt(c, "app.sandbar.localhost", "127.0.0.1", pool, time.Second); err == nil {
			t.Fatal("untrusted root succeeded")
		}
	}
	if _, err := checkHTTPSAt(c, "wrong.sandbar.localhost", "127.0.0.1", roots, time.Second); err == nil {
		t.Fatal("wrong hostname succeeded")
	}
	c, roots, _ = statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	start := time.Now()
	if _, err := checkHTTPSAt(c, "app.sandbar.localhost", "127.0.0.1", roots, 30*time.Millisecond); err == nil {
		t.Fatal("deadline succeeded")
	}
	if time.Since(start) > time.Second {
		t.Fatal("HTTPS check exceeded deadline")
	}
}

func TestDoctorResolutionIsIndependentFromDirectHTTPS(t *testing.T) {
	_, err := doctorResolve("app.sandbar.localhost", func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > routeCheckTimeout {
			t.Error("missing bounded resolver context")
		}
		return nil, errors.New("resolver fixture unavailable")
	})
	if err == nil {
		t.Fatal("resolver failure missing")
	}
	c, roots, _ := statusHTTPS(t, "app.sandbar.localhost", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	if _, err := checkHTTPSAt(c, "app.sandbar.localhost", "127.0.0.1", roots, time.Second); err != nil {
		t.Fatal(err)
	}
	values, err := doctorResolve("fixture", func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}, nil
	})
	if err == nil || len(values) != 1 {
		t.Fatal("non-loopback result was not identified")
	}
	values, err = doctorResolve("fixture", func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.IPv6loopback}, {IP: net.ParseIP("127.0.0.1")}}, nil
	})
	if err != nil || len(values) != 2 {
		t.Fatalf("loopback resolution=%v,%v", values, err)
	}
}

func TestDoctorRootAndIPv6Selection(t *testing.T) {
	home := shortHome(t)
	p, err := resolvePaths(home)
	if err != nil {
		t.Fatal(err)
	}
	c := config{Version: 3, Machine: "fixture", HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}}
	if err := os.MkdirAll(p.state, 0700); err != nil {
		t.Fatal(err)
	}
	for _, want := range []bool{false, true} {
		generated, err := renderCaddyfile(c, p, want)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p.generatedPath(), []byte(generated), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := doctorIPv6(p, c)
		if err != nil || got != want {
			t.Fatalf("IPv6=%v err=%v", got, err)
		}
	}
	_, root := statusCertificate(t, machineHostname(c.Machine))
	path := filepath.Join(home, "root.crt")
	if err := os.WriteFile(path, root, 0600); err != nil {
		t.Fatal(err)
	}
	roots, fingerprint, err := doctorRoot(path)
	if err != nil || roots == nil || len(fingerprint) != 64 {
		t.Fatalf("root=%v fingerprint=%q err=%v", roots, fingerprint, err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := doctorRoot(path); err == nil {
		t.Fatal("invalid certificate accepted")
	}
}

func TestDoctorProxyOutputRedactsValues(t *testing.T) {
	request, err := http.NewRequest(http.MethodHead, "https://app.sandbar.localhost/", nil)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(name string) (string, bool) {
		if name == "HTTPS_PROXY" {
			return "https://secret:password@proxy.invalid:4443", true
		}
		return "", false
	}
	for _, applies := range []bool{false, true} {
		var out bytes.Buffer
		report := &doctorReport{out: &out}
		doctorProxyResult(report, request, func(*http.Request) (*url.URL, error) {
			if applies {
				return url.Parse("https://secret:password@proxy.invalid:4443")
			}
			return nil, nil
		}, lookup)
		if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "password") || strings.Contains(out.String(), "proxy.invalid") {
			t.Fatal("proxy value leaked")
		}
		want := "no Go HTTPS proxy applies"
		if applies {
			want = "Go HTTPS proxy applies"
		}
		if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), "HTTPS_PROXY") {
			t.Fatal(out.String())
		}
	}
	var out bytes.Buffer
	doctorProxyResult(&doctorReport{out: &out}, request, func(*http.Request) (*url.URL, error) { return nil, errors.New("secret:password") }, lookup)
	if strings.Contains(out.String(), "password") || !strings.Contains(out.String(), "unknown:") {
		t.Fatal(out.String())
	}
}

func TestDoctorNativePortEvidence(t *testing.T) {
	for _, fixture := range []struct{ platform, output, want string }{
		{"darwin", "p1\nclaunchd\nn127.0.0.1:443\n", "pass:"},
		{"linux", `tcp LISTEN 0 4096 127.0.0.1:443 0.0.0.0:* users:(("caddy",pid=42,fd=8))`, "pass:"},
		{"linux", "tcp LISTEN 0 4096 127.0.0.1:443 0.0.0.0:*", "unknown:"},
		{"linux", "tcp LISTEN 0 4096 127.0.0.1:443 0.0.0.0:* users:((\"caddy\",pid=42,fd=8))\ntcp LISTEN 0 4096 127.0.0.1:80 0.0.0.0:*", "unknown:"},
		{"darwin", "", "unknown:"},
	} {
		var out bytes.Buffer
		report := &doctorReport{out: &out}
		doctorPortOutput(report, "TCP", fixture.platform, []byte(fixture.output), nil)
		if report.failed || !strings.HasPrefix(out.String(), fixture.want) {
			t.Fatal(out.String())
		}
	}
}

func TestDoctorDisconnectedDoesNotFail(t *testing.T) {
	p, err := resolvePaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := config{Teleports: []teleportDestination{{Machine: "peer"}}}
	var out bytes.Buffer
	report := &doctorReport{out: &out}
	doctorTeleports(report, p, c, true)
	if report.failed || !strings.Contains(out.String(), "disconnected; run "+selectedCommand(p, "teleport", "connect", "peer")) {
		t.Fatal(out.String())
	}
	if _, err := os.Stat(p.state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime created: %v", err)
	}
}

func TestDoctorIncompatibleCaddyAndMissingOwnerTool(t *testing.T) {
	home := t.TempDir()
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "caddy"), []byte("#!/bin/sh\nprintf 'v2.10.0\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools)
	p, err := resolvePaths(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeConfig(p.config, config{Version: 2, HTTPPort: 18080, HTTPSPort: 18443, Routes: []route{}}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := doctor(home, &out, io.Discard); err == nil {
		t.Fatal("incompatible Caddy succeeded")
	}
	for _, want := range []string{"failure: Caddy:", "v2.11.7", "unknown: port ownership:"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func TestDoctorServiceDeniedDoesNotControlService(t *testing.T) {
	p, service := testInstalledPaths(t)
	service.InspectErr = errors.New("inspection denied")
	var out bytes.Buffer
	d := &doctorReport{out: &out}
	doctorRuntime(d, p, config{}, errors.New("invalid source"), "", errors.New("binary unavailable"))
	if !d.failed || !strings.Contains(out.String(), "inspection denied") {
		t.Fatal(out.String())
	}
	if len(service.Actions) != 0 {
		t.Fatalf("service actions: %v", service.Actions)
	}
}

func TestDoctorCommandTimeout(t *testing.T) {
	if os.Getenv("SANDBAR_DOCTOR_TIMEOUT_HELPER") == "1" {
		time.Sleep(time.Hour)
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "SANDBAR_DOCTOR_TIMEOUT_HELPER=1")
	start := time.Now()
	if _, err := doctorCommand(binary, env, "-test.run=^TestDoctorCommandTimeout$"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 29*time.Second || elapsed > 35*time.Second {
		t.Fatalf("command timeout took %s", elapsed)
	}
}

func TestDoctorLocalPortFilter(t *testing.T) {
	output := []byte("p8\ncChrome\nn127.0.0.1:55000->127.0.0.1:443\np1\nclaunchd\nn127.0.0.1:443\n")
	got := string(doctorLocalLsof(output, []int{80, 443}))
	if strings.Contains(got, "Chrome") || !strings.Contains(got, "launchd") {
		t.Fatal(got)
	}
}

func TestDoctorForwardedWelcomeResults(t *testing.T) {
	c, _, root := statusHTTPS(t, machineHostname("peer"), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	destination := teleportDestination{Machine: "peer", HTTPSPort: 443, LocalPort: c.HTTPSPort, RootPEM: string(root)}
	p, err := resolvePaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	report := &doctorReport{out: &out}
	doctorTeleportResult(report, p, destination, "connected", nil)
	if report.failed || !strings.Contains(out.String(), "pass: Teleport peer forwarded HTTPS:") {
		t.Fatal(out.String())
	}
	_, wrongRoot := statusCertificate(t, machineHostname("wrong"))
	destination.RootPEM = string(wrongRoot)
	out.Reset()
	doctorTeleportResult(report, p, destination, "connected", nil)
	if !report.failed || !strings.Contains(out.String(), "pass: Teleport peer SSH control:") || !strings.Contains(out.String(), "failure: Teleport peer forwarded HTTPS:") {
		t.Fatal(out.String())
	}
	out.Reset()
	report.failed = false
	doctorTeleportResult(report, p, destination, "unknown", errors.New("inspection denied"))
	if report.failed || !strings.Contains(out.String(), "unknown: Teleport peer:") {
		t.Fatal(out.String())
	}
}

func TestDoctorDeniedPortInspectionIsUnknown(t *testing.T) {
	tools := t.TempDir()
	for _, name := range []string{"lsof", "ss"} {
		if err := os.WriteFile(filepath.Join(tools, name), []byte("#!/bin/sh\nprintf 'permission denied\\n' >&2\nexit 2\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", tools)
	var out bytes.Buffer
	report := &doctorReport{out: &out}
	doctorPorts(report, config{HTTPPort: 18080, HTTPSPort: 18443})
	if report.failed || !strings.Contains(out.String(), "unknown:") || !strings.Contains(out.String(), "exit status 2") {
		t.Fatal(out.String())
	}
}

func TestDoctorPortOwnershipFormatting(t *testing.T) {
	fixture := []byte("p579\nccaddy\nn127.0.0.1:443\nn127.0.0.1:443\nn[::1]:443\np1\nclaunchd\nn127.0.0.1:80\n")
	var out bytes.Buffer
	report := &doctorReport{out: &out}
	doctorPortOutput(report, "TCP", "darwin", fixture, []int{80, 443})
	for _, want := range []string{"PID 579, process caddy, address 127.0.0.1:443", "PID 579, process caddy, address [::1]:443", "PID 1, process launchd, address 127.0.0.1:80"} {
		if strings.Count(out.String(), want) != 1 {
			t.Errorf("expected one %q in %s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "p579;") || report.failed {
		t.Fatal(out.String())
	}
	out.Reset()
	doctorPortOutput(report, "UDP", "darwin", []byte("n127.0.0.1:443\n"), []int{443})
	if !strings.HasPrefix(out.String(), "unknown:") || !strings.Contains(out.String(), "PID unknown, process unknown, address 127.0.0.1:443") {
		t.Fatal(out.String())
	}
}

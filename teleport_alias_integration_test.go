package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestIntegrationOwnMachineAliases(t *testing.T) {
	requireIntegration(t)
	bin := buildCLI(t)
	backend := func(label string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "%s %s %s", label, r.Host, r.RequestURI) }))
	}
	first, second := backend("first"), backend("second")
	defer first.Close()
	defer second.Close()
	home := shortHome(t)
	httpPort, httpsPort := freePorts(t)
	if code, output := runBinary(t, bin, home, "init", "--machine", "alias-peer", "--http-port", strconv.Itoa(httpPort), "--https-port", strconv.Itoa(httpsPort)); code != 0 {
		t.Fatalf("init: %d %s", code, output)
	}
	p := testPaths(t, home)
	c, err := readConfig(p.config)
	if err != nil {
		t.Fatal(err)
	}
	startRouter(t, bin, p)
	client := routerClient(t, p, "127.0.0.1")
	welcome := c.routeURL(machineHostname(c.Machine))
	waitForTLS(t, client, welcome)
	root, pid := readTestFile(t, p.rootCertificate()), readTestFile(t, p.file("caddy.pid"))
	command := func(args ...string) {
		t.Helper()
		if code, output := runBinary(t, bin, home, args...); code != 0 {
			t.Fatalf("%v: %d %s", args, code, output)
		}
	}
	check := func(host, label string) {
		t.Helper()
		url := c.routeURL(host) + "/path?q=1"
		waitForTLS(t, client, url)
		response, body := getResponse(t, client, url)
		want := fmt.Sprintf("%s %s:%d /path?q=1", label, host, c.HTTPSPort)
		if response.StatusCode != 200 || string(body) != want {
			t.Fatalf("%s: HTTP %d %s, want %s", url, response.StatusCode, body, want)
		}
	}
	command("add", "kept.sandbar.localhost", first.URL)
	check("kept.sandbar.localhost", "first")
	check("kept.sandbar-alias-peer.localhost", "first")
	canonical := "api.app.sandbar.localhost"
	alias := ownMachineHostname(canonical, c.Machine)
	command("add", canonical, first.URL)
	check(canonical, "first")
	check(alias, "first")
	for _, host := range []string{canonical, alias} {
		response, _ := getResponse(t, client, fmt.Sprintf("http://%s:%d/path?q=1", host, httpPort))
		if response.StatusCode != 308 || response.Header.Get("Location") != c.routeURL(host)+"/path?q=1" {
			t.Fatal("alias redirect changed hostname", response.Header)
		}
	}
	command("add", "--replace", canonical, second.URL)
	check(canonical, "second")
	check(alias, "second")
	command("rm", canonical)
	for _, host := range []string{canonical, alias} {
		response, _ := getResponse(t, client, fmt.Sprintf("http://%s:%d/", host, httpPort))
		if response.Header.Get("Location") != "" {
			t.Fatal("removed alias still redirects", host)
		}
		if response, err := client.Get(c.routeURL(host)); err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				t.Fatal("removed alias still routes", host)
			}
		}
	}
	check("kept.sandbar.localhost", "first")
	check("kept.sandbar-alias-peer.localhost", "first")
	command("rm", "kept.sandbar.localhost")
	response, body := getResponse(t, client, welcome)
	if response.StatusCode != 200 || !strings.Contains(string(body), "Sandbar is running") {
		t.Fatal("lost welcome", response.StatusCode, string(body))
	}
	response, _ = getResponse(t, client, fmt.Sprintf("http://sandbar.localhost:%d/", httpPort))
	if response.Header.Get("Location") != "" {
		t.Fatal("private router gained installed welcome")
	}
	if !bytes.Equal(root, readTestFile(t, p.rootCertificate())) || !bytes.Equal(pid, readTestFile(t, p.file("caddy.pid"))) {
		t.Fatal("aliases changed CA or Caddy process")
	}
	command("stop")
	waitForClosed(t, httpPort, httpsPort)
	t.Logf("direct canonical and nested own-machine aliases verified in %s", filepath.Base(home))
}

//go:build linux

package main

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func checkProcessEvidence(t *testing.T, pid string) {
	t.Helper()
	executable, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil || filepath.Base(executable) != "caddy" {
		t.Fatalf("persistent process: %s %v", executable, err)
	}
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

func checkListenerClosure(t *testing.T, ports ...int) { t.Helper(); waitForClosed(t, ports...) }

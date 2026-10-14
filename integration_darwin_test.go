package main

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func checkProcessEvidence(t *testing.T, pid string) {
	t.Helper()
	output, err := exec.Command("/bin/ps", "-p", pid, "-o", "comm=").Output()
	if err != nil || filepath.Base(strings.TrimSpace(string(output))) != "caddy" {
		t.Fatalf("persistent Caddy process: %s %v", output, err)
	}
}

func checkListenerEvidence(t *testing.T, c config, pid string) {
	t.Helper()
	seen := map[string]bool{}
	for _, port := range []int{c.HTTPPort, c.HTTPSPort} {
		output, err := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fpn").CombinedOutput()
		if err != nil {
			t.Fatalf("lsof required: %v %s", err, output)
		}
		owner := ""
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "p") {
				owner = strings.TrimPrefix(line, "p")
			}
			if !strings.HasPrefix(line, "n") {
				continue
			}
			address := strings.TrimPrefix(line, "n")
			host, _, err := net.SplitHostPort(address)
			if err != nil || (host != "127.0.0.1" && host != "::1") || owner != pid {
				t.Fatalf("unexpected listener owner/address: pid=%s %s", owner, line)
			}
			seen[address] = true
			t.Logf("Caddy PID %s TCP %s", owner, address)
		}
		output, err = exec.Command("/usr/sbin/lsof", "-nP", "-iUDP:"+strconv.Itoa(port), "-Fpn").CombinedOutput()
		if len(output) > 0 {
			t.Fatalf("unexpected UDP listener: %s", output)
		}
		if err != nil {
			if status, ok := err.(*exec.ExitError); !ok || status.ExitCode() != 1 {
				t.Fatal(err)
			}
		}
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
			address := net.JoinHostPort(ip, strconv.Itoa(port))
			if !seen[address] {
				t.Fatal(fmt.Errorf("missing Caddy listener: %s", address))
			}
		}
	}
}

func checkListenerClosure(t *testing.T, ports ...int) {
	t.Helper()
	for _, port := range ports {
		output, err := exec.Command("/usr/sbin/lsof", "-nP", "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN", "-Fpn").CombinedOutput()
		if len(output) > 0 {
			t.Fatalf("listener remains after stop: %s", output)
		}
		if status, ok := err.(*exec.ExitError); !ok || status.ExitCode() != 1 {
			t.Fatalf("cannot establish listener closure: %v", err)
		}
	}
}

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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

// The subprocess confines descriptor moves and exec to a test-owned process.
func TestBridgeProcess(t *testing.T) {
	mode := os.Getenv("SANDBAR_BRIDGE_TEST")
	if mode == "" {
		return
	}
	var plan socketPlan
	if err := json.Unmarshal([]byte(os.Getenv("SANDBAR_BRIDGE_PLAN")), &plan); err != nil {
		t.Fatal(err)
	}
	bindings := socketBindings(plan)
	groups := map[string][]int{}
	for n, binding := range bindings {
		groups[binding.Group] = append([]int{3 + n}, groups[binding.Group]...)
	}
	if mode == "collision" {
		// Occupy every destination in a cycle. Each move would overwrite another source.
		for n := range bindings {
			if err := syscall.Dup2(3+n, bindings[(n+1)%len(bindings)].FD); err != nil {
				t.Fatal(err)
			}
		}
		groups = map[string][]int{}
		for n := range bindings {
			_ = syscall.Close(3 + n)
		}
		for n, binding := range bindings {
			groups[binding.Group] = append(groups[binding.Group], bindings[(n+1)%len(bindings)].FD)
		}
	}
	mapping, err := matchSocketDescriptors(groups, plan)
	if err != nil {
		t.Fatal(err)
	}
	openExtraDescriptors := func() map[int]bool {
		entries, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Fatal(err)
		}
		open := map[int]bool{}
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil || fd < 106 {
				continue
			}
			_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
			if errno == 0 {
				open[fd] = true
			}
		}
		return open
	}
	priorDescriptors := openExtraDescriptors()
	if err := normalizeSocketDescriptors(mapping); err != nil {
		t.Fatal(err)
	}
	for fd := range openExtraDescriptors() {
		if !priorDescriptors[fd] {
			t.Fatalf("temporary descriptor %d remains open", fd)
		}
	}
	for _, source := range mapping {
		if _, reused := mapping[source]; !reused {
			if _, err := syscall.Getsockname(source); err != syscall.EBADF {
				t.Fatalf("source descriptor %d remains open: %v", source, err)
			}
		}
	}
	for _, binding := range bindings {
		address, err := syscall.Getsockname(binding.FD)
		if err != nil {
			t.Fatal(err)
		}
		port := 0
		switch a := address.(type) {
		case *syscall.SockaddrInet4:
			port = a.Port
		case *syscall.SockaddrInet6:
			port = a.Port
		}
		if port != binding.Port {
			t.Fatalf("slot %d port %d want %d", binding.FD, port, binding.Port)
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(binding.FD), syscall.F_GETFD, 0)
		if errno != 0 || flags&syscall.FD_CLOEXEC != 0 {
			t.Fatalf("slot %d not inherited: %d %v", binding.FD, flags, errno)
		}
	}
	if mode == "collision" {
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	installed := installation{Binary: os.Getenv("SANDBAR_BRIDGE_CADDY"), State: os.Getenv("SANDBAR_BRIDGE_STATE"), Storage: filepath.Join(os.Getenv("SANDBAR_BRIDGE_STATE"), "caddy")}
	if err := execCaddyRuntime(&installed, data); err != nil {
		t.Fatal(err)
	}
}

func bridgeSockets(t *testing.T, ipv6 bool) (socketPlan, []*os.File) {
	t.Helper()
	http, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer http.Close()
	https, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer https.Close()
	plan := socketPlan{HTTPPort: http.Addr().(*net.TCPAddr).Port, HTTPSPort: https.Addr().(*net.TCPAddr).Port, IPv6: ipv6}
	files := []*os.File{}
	for _, binding := range socketBindings(plan) {
		var file *os.File
		var err error
		if binding.Family == syscall.AF_INET && binding.Group == "HTTP" {
			file, err = http.File()
		} else if binding.Family == syscall.AF_INET && binding.Group == "HTTPS" {
			file, err = https.File()
		} else {
			ip, network := net.IPv4(127, 0, 0, 1), "tcp4"
			if binding.Family == syscall.AF_INET6 {
				ip, network = net.IPv6loopback, "tcp6"
			}
			if binding.Type == syscall.SOCK_STREAM {
				var listener *net.TCPListener
				listener, err = net.ListenTCP(network, &net.TCPAddr{IP: ip, Port: binding.Port})
				if err == nil {
					file, err = listener.File()
					listener.Close()
				}
			} else {
				network = strings.Replace(network, "tcp", "udp", 1)
				var listener *net.UDPConn
				listener, err = net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: binding.Port})
				if err == nil {
					file, err = listener.File()
					listener.Close()
				}
			}
		}
		if err != nil {
			for _, file := range files {
				file.Close()
			}
			t.Fatal(err)
		}
		files = append(files, file)
	}
	t.Cleanup(func() {
		for _, file := range files {
			file.Close()
		}
	})
	return plan, files
}

func bridgeGroups(plan socketPlan, files []*os.File) map[string][]int {
	groups := map[string][]int{}
	for n, binding := range socketBindings(plan) {
		groups[binding.Group] = append([]int{int(files[n].Fd())}, groups[binding.Group]...)
	}
	return groups
}

func TestBridgeDescriptorValidation(t *testing.T) {
	ipv6, err := ipv6Available(probeIPv6, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for _, v6 := range []bool{false, ipv6} {
		plan, files := bridgeSockets(t, v6)
		groups := bridgeGroups(plan, files)
		mapping, err := matchSocketDescriptors(groups, plan)
		if err != nil || len(mapping) != len(files) {
			t.Fatalf("mapping: %v %v", mapping, err)
		}
		cases := map[string]func(map[string][]int, socketPlan) (map[string][]int, socketPlan){
			"missing": func(g map[string][]int, p socketPlan) (map[string][]int, socketPlan) { g["HTTP"] = nil; return g, p },
			"wildcard address": func(g map[string][]int, p socketPlan) (map[string][]int, socketPlan) {
				listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
				if err != nil {
					t.Fatal(err)
				}
				file, err := listener.File()
				listener.Close()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { file.Close() })
				g["HTTP"][0] = int(file.Fd())
				p.HTTPPort = listener.Addr().(*net.TCPAddr).Port
				return g, p
			},
			"wrong port": func(g map[string][]int, p socketPlan) (map[string][]int, socketPlan) { p.HTTPPort++; return g, p },
			"wrong type": func(g map[string][]int, p socketPlan) (map[string][]int, socketPlan) {
				g["HTTPS"], g["QUIC"] = g["QUIC"], g["HTTPS"]
				return g, p
			},
			"repeated": func(g map[string][]int, p socketPlan) (map[string][]int, socketPlan) {
				g["HTTPS"] = g["HTTP"]
				return g, p
			},
			"not socket": func(g map[string][]int, p socketPlan) (map[string][]int, socketPlan) {
				f, err := os.CreateTemp(t.TempDir(), "regular")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { f.Close() })
				g["HTTP"][0] = int(f.Fd())
				return g, p
			},
		}
		for name, change := range cases {
			t.Run(fmt.Sprintf("ipv6=%t/%s", v6, name), func(t *testing.T) {
				g := bridgeGroups(plan, files)
				g, p := change(g, plan)
				if _, err := matchSocketDescriptors(g, p); err == nil {
					t.Fatal("invalid handoff accepted")
				}
			})
		}
	}
}

func TestBridgeCollisionSafeNormalization(t *testing.T) {
	plan, files := bridgeSockets(t, false)
	data, _ := json.Marshal(plan)
	cmd := exec.Command(os.Args[0], "-test.run=^TestBridgeProcess$")
	cmd.Env = append(os.Environ(), "SANDBAR_BRIDGE_TEST=collision", "SANDBAR_BRIDGE_PLAN="+string(data))
	cmd.ExtraFiles = files
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("normalization: %v %s", err, output)
	}
}

func TestBridgeDirectInvocation(t *testing.T) {
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	installed := installation{ID: "sandbar-launchd-v1", Binary: executable, CLI: executable, Config: filepath.Join(dir, "Caddyfile"), State: dir, UID: os.Geteuid()}
	plan := socketPlan{HTTPPort: 18080, HTTPSPort: 18443}
	record := setupRecord{Identity: installed.identity(), SocketPlan: &plan}
	data, _ := json.Marshal(record)
	path := filepath.Join(dir, "setup.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDBAR_HOME", "{invalid development home}")
	err = execute([]string{"_launchd-caddy", "--caddy", executable, "--config", installed.Config, "--setup-record", path}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "launchd socket activation HTTP") {
		t.Fatalf("direct invocation: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "caddy")); !os.IsNotExist(err) {
		t.Fatalf("direct invocation created storage: %v", err)
	}
}

func bridgeCurl(t *testing.T) string {
	t.Helper()
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal("descriptor integration requires curl with HTTP2 and HTTP3")
	}
	output, err := exec.Command(curl, "--version").Output()
	if err != nil || !strings.Contains(string(output), "HTTP3") || !strings.Contains(string(output), "HTTP2") {
		t.Fatalf("curl requires HTTP2 and HTTP3: %v %s", err, output)
	}
	return curl
}

func bridgeCurlRequest(t *testing.T, curl, root, ip, scheme string, port int, protocol string) string {
	t.Helper()
	address := ip
	if strings.Contains(ip, ":") {
		address = "[" + ip + "]"
	}
	args := []string{"--noproxy", "*", "--silent", "--show-error", "--max-time", "5", "--cacert", root, "--resolve", "netbox.sandbar.localhost:" + strconv.Itoa(port) + ":" + address, "--dump-header", "-", "--write-out", "\nprotocol=%{http_version}\n"}
	if protocol != "" {
		args = append(args, protocol)
	}
	args = append(args, scheme+"://netbox.sandbar.localhost:"+strconv.Itoa(port)+"/path?query=1")
	output, err := exec.Command(curl, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("curl %s %s: %v %s", ip, protocol, err, output)
	}
	return string(output)
}

func TestIntegrationBridgeHandoff(t *testing.T) {
	requireIntegration(t)
	curl := bridgeCurl(t)
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal(err)
	}
	available, err := ipv6Available(probeIPv6, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	modes := []bool{false}
	if available {
		modes = append(modes, true)
	}
	for _, ipv6 := range modes {
		t.Run(fmt.Sprintf("ipv6=%t", ipv6), func(t *testing.T) {
			state := shortHome(t)
			plan, files := bridgeSockets(t, ipv6)
			independent, _ := freePorts(t)
			addresses := "127.0.0.1"
			if ipv6 {
				addresses += " ::1"
			}
			admin := "unix/" + filepath.Join(state, "admin.sock")
			content := fmt.Sprintf(`{
 admin %q
 storage file_system %q
 persist_config off
 skip_install_trust
 http_port %d
 https_port %d
 default_bind %s
 grace_period 1s
 pki {
  ca sandbar {
   name "sandbar local CA"
  }
 }
}
https://netbox.sandbar.localhost:%d {
 tls {
  issuer internal {
   ca sandbar
  }
 }
 respond "first response"
}
http://netbox.sandbar.localhost:%d {
 redir https://netbox.sandbar.localhost:%d{uri} 308
}
http://other.localhost:%d {
 respond "shared response"
}
http://independent.localhost:%d {
 respond "independent response"
}
`, admin, filepath.Join(state, "caddy"), plan.HTTPPort, plan.HTTPSPort, addresses, plan.HTTPSPort, plan.HTTPPort, plan.HTTPSPort, plan.HTTPPort, independent)
			adapt := func(content string) []byte {
				t.Helper()
				cmd := exec.Command(caddy, "adapt", "--config", "-", "--adapter", "caddyfile")
				cmd.Stdin = strings.NewReader(content)
				output, err := cmd.Output()
				if err != nil {
					t.Fatalf("adapt: %v", err)
				}
				result, err := convertSocketRuntime(output, plan)
				if err != nil {
					t.Fatal(err)
				}
				validate := exec.Command(caddy, "validate", "--config", "-")
				validate.Stdin = bytes.NewReader(result)
				if output, err := validate.CombinedOutput(); err != nil {
					t.Fatalf("validate without inherited descriptors: %v %s", err, output)
				}
				return result
			}
			runtime := adapt(content)
			encoded, _ := json.Marshal(plan)
			logPath := filepath.Join(state, "caddy.log")
			log, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestBridgeProcess$")
			cmd.Env = append(os.Environ(), "SANDBAR_BRIDGE_TEST=handoff", "SANDBAR_BRIDGE_PLAN="+string(encoded), "SANDBAR_BRIDGE_CADDY="+caddy, "SANDBAR_BRIDGE_STATE="+state)
			cmd.ExtraFiles = files
			cmd.Stdin = bytes.NewReader(runtime)
			cmd.Stdout, cmd.Stderr = log, log
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				file.Close()
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			stopped := false
			t.Cleanup(func() {
				if stopped {
					return
				}
				stop := exec.Command(caddy, "stop", "--address", admin)
				if output, err := stop.CombinedOutput(); err != nil {
					t.Logf("cleanup stop: %v %s", err, output)
				}
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					_ = cmd.Process.Kill()
					<-done
				}
			})
			root := filepath.Join(state, "caddy/pki/authorities/sandbar/root.crt")
			deadline := time.Now().Add(8 * time.Second)
			for {
				if _, err := os.Stat(root); err == nil {
					break
				}
				if time.Now().After(deadline) {
					output, _ := os.ReadFile(logPath)
					t.Fatalf("CA not ready: %s", output)
				}
				time.Sleep(20 * time.Millisecond)
			}
			ips := []string{"127.0.0.1"}
			if ipv6 {
				ips = append(ips, "::1")
			}
			for _, ip := range ips {
				waitForTLS(t, bridgeTLSClient(t, root, ip), "https://netbox.sandbar.localhost:"+strconv.Itoa(plan.HTTPSPort)+"/")
				output := bridgeCurlRequest(t, curl, root, ip, "http", plan.HTTPPort, "")
				expected := "Location: https://netbox.sandbar.localhost:" + strconv.Itoa(plan.HTTPSPort) + "/path?query=1"
				if !strings.Contains(output, "308 Permanent Redirect") || !strings.Contains(output, expected) {
					t.Fatalf("redirect: %s", output)
				}
				for _, protocol := range []struct{ flag, version string }{{"--http1.1", "1.1"}, {"--http2", "2"}, {"--http3-only", "3"}} {
					output := bridgeCurlRequest(t, curl, root, ip, "https", plan.HTTPSPort, protocol.flag)
					t.Logf("%s verified TLS %s, HTTPS port %d", ip, protocol.flag, plan.HTTPSPort)
					if !strings.Contains(output, "first response") || !strings.Contains(output, "protocol="+protocol.version+"\n") {
						t.Fatalf("%s response: %s", protocol.flag, output)
					}
					if protocol.flag != "--http3-only" && !strings.Contains(output, fmt.Sprintf("h3=\":%d\"", plan.HTTPSPort)) {
						t.Fatalf("Alt-Svc: %s", output)
					}
				}
			}
			for _, port := range []int{plan.HTTPPort, plan.HTTPSPort} {
				args := []string{"-nP", "-a", "-p", strconv.Itoa(cmd.Process.Pid), "-iTCP:" + strconv.Itoa(port), "-sTCP:LISTEN", "-Fpn"}
				output, err := exec.Command("/usr/sbin/lsof", args...).CombinedOutput()
				if err != nil || !strings.Contains(string(output), "127.0.0.1:") {
					t.Fatalf("inherited TCP evidence: %v %s", err, output)
				}
				if ipv6 && !strings.Contains(string(output), "[::1]:") {
					t.Fatalf("inherited IPv6 TCP evidence: %s", output)
				}
			}
			output, err := exec.Command("/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(cmd.Process.Pid), "-iUDP:"+strconv.Itoa(plan.HTTPSPort), "-Fpn").CombinedOutput()
			if err != nil || !strings.Contains(string(output), "127.0.0.1:") {
				t.Fatalf("inherited UDP evidence: %v %s", err, output)
			}
			if ipv6 && !strings.Contains(string(output), "[::1]:") {
				t.Fatalf("inherited IPv6 UDP evidence: %s", output)
			}
			checkProcessEvidence(t, strconv.Itoa(cmd.Process.Pid))
			checkUnrelated := func(host string, port int, want string) {
				t.Helper()
				resolve := host + ":" + strconv.Itoa(port) + ":127.0.0.1"
				output, err := exec.Command(curl, "--noproxy", "*", "--silent", "--show-error", "--max-time", "3", "--resolve", resolve, "http://"+host+":"+strconv.Itoa(port)).CombinedOutput()
				if err != nil || string(output) != want {
					t.Fatalf("unrelated site: %v %s", err, output)
				}
			}
			checkUnrelated("other.localhost", plan.HTTPPort, "shared response")
			checkUnrelated("independent.localhost", independent, "independent response")
			rootBefore, err := os.ReadFile(root)
			if err != nil {
				t.Fatal(err)
			}
			updated := adapt(strings.Replace(content, "first response", "second response", 1))
			reload := exec.Command(caddy, "reload", "--config", "-", "--address", admin, "--force")
			reload.Stdin = bytes.NewReader(updated)
			if output, err := reload.CombinedOutput(); err != nil {
				t.Fatalf("reload: %v %s", err, output)
			}
			checkProcessEvidence(t, strconv.Itoa(cmd.Process.Pid))
			for _, ip := range ips {
				for _, protocol := range []string{"--http1.1", "--http2", "--http3-only"} {
					output := bridgeCurlRequest(t, curl, root, ip, "https", plan.HTTPSPort, protocol)
					if !strings.Contains(output, "second response") {
						t.Fatalf("reload response: %s", output)
					}
				}
			}
			checkUnrelated("other.localhost", plan.HTTPPort, "shared response")
			checkUnrelated("independent.localhost", independent, "independent response")
			rootAfter, err := os.ReadFile(root)
			if err != nil || !bytes.Equal(rootBefore, rootAfter) {
				t.Fatalf("CA changed across reload: %v", err)
			}
			stop := exec.Command(caddy, "stop", "--address", admin)
			if output, err := stop.CombinedOutput(); err != nil {
				t.Fatalf("stop: %v %s", err, output)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Caddy exit: %v", err)
				}
				stopped = true
			case <-time.After(5 * time.Second):
				t.Fatal("Caddy did not stop")
			}
			checkListenerClosure(t, plan.HTTPPort, plan.HTTPSPort, independent)
			output, err = exec.Command("/usr/sbin/lsof", "-nP", "-iUDP:"+strconv.Itoa(plan.HTTPSPort), "-Fpn").CombinedOutput()
			if len(output) > 0 {
				t.Fatalf("UDP remains after stop: %s", output)
			}
			if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatalf("UDP closure evidence: %v", err)
			}
		})
	}
}

func bridgeTLSClient(t *testing.T, root, ip string) *http.Client {
	t.Helper()
	roots, err := selectedStatusRoots(root)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			_, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 3 * time.Second}
}

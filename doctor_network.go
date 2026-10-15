package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

func doctorEndpoints(d *doctorReport, p paths, c config, roots *x509.CertPool, rootErr error, installed, usable bool) {
	var ipv6 bool
	var ipv6Err error
	if usable {
		ipv6, ipv6Err = doctorIPv6(p, c)
	} else {
		ipv6Err = rootErr
	}

	for _, site := range c.localSites(installed) {
		hostname := site.Hostname
		addresses, err := doctorResolve(hostname, net.DefaultResolver.LookupIPAddr)
		if err != nil {
			d.result("failure", hostname+" system resolution", doctorDetail(err)+"; review system resolver and hosts settings")
		} else {
			d.result("pass", hostname+" system resolution", strings.Join(addresses, ", "))
		}
		doctorProxy(d, c.routeURL(hostname))
		if rootErr != nil {
			d.result("not applicable", hostname+" HTTPS", "readable selected CA is required")
			continue
		}
		doctorHTTPSResult(d, c, hostname, "127.0.0.1", "IPv4 selected CA", roots)
		if ipv6Err != nil {
			d.result("unknown", hostname+" IPv6", ipv6Err.Error())
		} else if !ipv6 {
			d.result("not applicable", hostname+" IPv6", "selected listener configuration uses IPv4 only")
		} else {
			doctorHTTPSResult(d, c, hostname, "::1", "IPv6 selected CA", roots)
		}
		code, err := checkHTTPSAt(c, hostname, "127.0.0.1", nil, routeCheckTimeout)
		if err != nil {
			detail := doctorDetail(err)
			var tlsErr *routeTLSError
			if errors.As(err, &tlsErr) {
				detail += "; if this is the expected CA, run " + selectedCommand(p, "trust") + "; then verify the browser separately"
			}
			d.result("failure", hostname+" system verifier", detail)
		} else if code >= 500 {
			d.result("failure", hostname+" system verifier", fmt.Sprintf("TLS verified; HTTP %d", code))
		} else {
			d.result("pass", hostname+" system verifier", fmt.Sprintf("TLS verified; HTTP %d; browser trust is unverified", code))
		}
	}
}

func doctorHTTPSResult(d *doctorReport, c config, hostname, address, label string, roots *x509.CertPool) {
	code, err := checkHTTPSAt(c, hostname, address, roots, routeCheckTimeout)
	if err != nil {
		kind := "connection error"
		var tlsErr *routeTLSError
		if errors.As(err, &tlsErr) {
			kind = "TLS error"
		}
		d.result("failure", hostname+" "+label, kind+"; "+doctorDetail(err))
	} else if code >= 500 {
		d.result("failure", hostname+" "+label, fmt.Sprintf("HTTP %d", code))
	} else {
		d.result("pass", hostname+" "+label, fmt.Sprintf("HTTP %d; reachable", code))
	}
}

func checkHTTPSAt(c config, hostname, address string, roots *x509.CertPool, timeout time.Duration) (int, error) {
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{Timeout: min(timeout, time.Second)}).DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(c.HTTPSPort)))
		if err != nil {
			return nil, err
		}
		secured := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: hostname, MinVersion: tls.VersionTLS12})
		if err := secured.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, &routeTLSError{err}
		}
		return secured, nil
	}, ResponseHeaderTimeout: timeout}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequest(http.MethodHead, c.routeURL(hostname)+"/", nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	response.Body.Close()
	return response.StatusCode, nil
}

func doctorResolve(hostname string, lookup func(context.Context, string) ([]net.IPAddr, error)) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), routeCheckTimeout)
	defer cancel()
	addresses, err := lookup(ctx, hostname)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("system resolver returned no addresses")
	}
	values := make([]string, 0, len(addresses))
	nonloopback := false
	for _, address := range addresses {
		values = append(values, address.String())
		if !address.IP.IsLoopback() {
			nonloopback = true
		}
	}
	sort.Strings(values)
	if nonloopback {
		return values, fmt.Errorf("system resolver returned non-loopback addresses: %s", strings.Join(values, ", "))
	}
	return values, nil
}

func doctorProxy(d *doctorReport, rawURL string) {
	request, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		d.result("unknown", "proxy applicability", "checked URL is invalid")
		return
	}
	doctorProxyResult(d, request, http.ProxyFromEnvironment, os.LookupEnv)
}

func doctorProxyResult(d *doctorReport, request *http.Request, proxy func(*http.Request) (*url.URL, error), lookup func(string) (string, bool)) {
	var settings []string
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		if value, present := lookup(name); present && value != "" {
			settings = append(settings, name)
		}
	}
	label := request.URL.Hostname() + " proxy"
	selected, err := proxy(request)
	if err != nil {
		d.result("unknown", label, "Go proxy selection failed; check proxy settings (values omitted)")
		return
	}
	detail := "no Go HTTPS proxy applies"
	if selected != nil {
		detail = "Go HTTPS proxy applies"
	}
	if len(settings) > 0 {
		detail += "; settings: " + strings.Join(settings, ", ")
	}
	detail += "; direct probes bypass proxies; browser rules can differ"
	state := "pass"
	if selected != nil {
		state = "warning"
	}
	d.result(state, label, detail)
}

func doctorPorts(d *doctorReport, c config) {
	if runtime.GOOS == "darwin" {
		binary, err := exec.LookPath("lsof")
		if err != nil {
			d.result("unknown", "port ownership", "lsof is unavailable")
			return
		}
		for _, protocol := range []string{"TCP", "UDP"} {
			args := []string{"-nP", "-a", "-i" + protocol + ":" + strconv.Itoa(c.HTTPPort), "-i" + protocol + ":" + strconv.Itoa(c.HTTPSPort), "-Fpcn"}
			if protocol == "TCP" {
				args = append(args, "-sTCP:LISTEN")
			}
			output, err := doctorCommand(binary, os.Environ(), args...)
			if err != nil {
				d.result("unknown", protocol+" port ownership", err.Error()+"; no owner information obtained")
				continue
			}
			doctorPortOutput(d, protocol, "darwin", output, []int{c.HTTPPort, c.HTTPSPort})
		}
		return
	}
	binary, err := exec.LookPath("ss")
	if err != nil {
		d.result("unknown", "port ownership", "ss is unavailable")
		return
	}
	output, err := doctorCommand(binary, os.Environ(), "-H", "-lntup", fmt.Sprintf("( sport = :%d or sport = :%d )", c.HTTPPort, c.HTTPSPort))
	if err != nil {
		d.result("unknown", "port ownership", err.Error())
		return
	}
	doctorPortOutput(d, "TCP/UDP", "linux", output, nil)
}

func doctorPortOutput(d *doctorReport, protocol, platform string, output []byte, ports []int) {
	if platform == "darwin" && len(ports) > 0 {
		output = doctorLocalLsof(output, ports)
	}
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		d.result("unknown", protocol+" port ownership", "no listener owner was returned")
		return
	}
	owned := true
	for _, line := range strings.Split(detail, "\n") {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "users:((") {
			owned = false
			break
		}
	}
	if platform == "darwin" {
		detail, owned = doctorLsofDetail(output)
	}

	state := "pass"
	if !owned {
		state = "unknown"
	}
	detail = strings.ReplaceAll(detail, "\n", "; ")
	if platform == "darwin" {
		detail += "; launchd ownership can be expected for registered Sandbar sockets"
	}
	d.result(state, protocol+" port ownership", detail+"; ownership does not prove reachability")
}

// lsof can match a remote port too. Keep only selected local socket ports.
func doctorLocalLsof(output []byte, ports []int) []byte {
	var selected []string
	process, command := "", ""
	for _, line := range strings.Split(string(output), "\n") {
		switch {
		case strings.HasPrefix(line, "p"):
			process = line
			command = ""
		case strings.HasPrefix(line, "c"):
			command = line
		case strings.HasPrefix(line, "n"):
			local, _, _ := strings.Cut(strings.TrimPrefix(line, "n"), "->")
			_, portText, err := net.SplitHostPort(local)
			if err != nil {
				continue
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				continue
			}
			for _, want := range ports {
				if port == want {
					selected = append(selected, process, command, line)
					break
				}
			}
		}
	}
	return []byte(strings.Join(selected, "\n"))
}

func doctorLsofDetail(output []byte) (string, bool) {
	var rows []string
	seen := map[string]bool{}
	pid, process := "unknown", "unknown"
	owned := false
	for _, line := range strings.Split(string(output), "\n") {
		switch {
		case strings.HasPrefix(line, "p") && len(line) > 1:
			pid, process = line[1:], "unknown"
			owned = true
		case strings.HasPrefix(line, "c") && len(line) > 1:
			process = line[1:]
		case strings.HasPrefix(line, "n") && len(line) > 1:
			row := fmt.Sprintf("PID %s, process %s, address %s", pid, process, line[1:])
			if !seen[row] {
				rows = append(rows, row)
				seen[row] = true
			}
		}
	}
	if len(rows) == 0 {
		return "no socket addresses were returned", false
	}
	return strings.Join(rows, " | "), owned
}

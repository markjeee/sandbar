package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type caddyError struct {
	code int
	err  error
}

func (e *caddyError) Error() string { return e.err.Error() }
func (e *caddyError) Unwrap() error { return e.err }

// invokeCaddy is the single subprocess boundary. Caddy owns command behavior.
func invokeCaddy(env []string, in io.Reader, out, errOut io.Writer, args ...string) error {
	cmd := exec.Command("caddy", args...)
	cmd.Env, cmd.Stdin = env, in
	cmd.Stdout, cmd.Stderr = out, errOut
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() > 0 {
			return &caddyError{exit.ExitCode(), fmt.Errorf("caddy %s: %w", args[0], err)}
		}
		return fmt.Errorf("run caddy %s (install Caddy v2.11.7 or later v2): %w", args[0], err)
	}
	return nil
}

func caddyEnv(p paths) []string {
	if p.installed != nil {
		return installedCaddyEnv(p.installed)
	}
	env := make([]string, 0, len(os.Environ())+5)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		switch key {
		case "HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME":
			continue
		}
		env = append(env, item)
	}
	return append(env, "HOME="+p.file("home"), "XDG_CONFIG_HOME="+p.file("config"),
		"XDG_DATA_HOME="+p.file("data"), "XDG_STATE_HOME="+p.file("state"), "XDG_CACHE_HOME="+p.file("cache"))
}

var caddyVersionPattern = regexp.MustCompile(`^v2\.([0-9]+)\.([0-9]+)(\+[A-Za-z0-9.-]+)?$`)

func checkCaddy(env []string, errOut io.Writer) error {
	var out bytes.Buffer
	if err := invokeCaddy(env, nil, &out, errOut, "version"); err != nil {
		return err
	}
	return checkCaddyVersion(out.String())
}

func checkCaddyVersion(value string) error {
	fields := strings.Fields(value)
	if len(fields) != 0 {
		match := caddyVersionPattern.FindStringSubmatch(fields[0])
		if match != nil {
			minor, minorErr := strconv.Atoi(match[1])
			patch, patchErr := strconv.Atoi(match[2])
			if minorErr == nil && patchErr == nil && (minor > 11 || minor == 11 && patch >= 7) {
				return nil
			}
		}
	}
	return fmt.Errorf("requires Caddy v2.11.7 or later v2; got %q", strings.TrimSpace(value))
}

func probeIPv6() error {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return err
	}
	return listener.Close()
}

func ipv6Available(probe func() error, errOut io.Writer) (bool, error) {
	err := probe()
	if err == nil {
		return true, nil
	}
	if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) {
		fmt.Fprintln(errOut, "sandbar: warning: IPv6 loopback is unavailable; using IPv4 loopback")
		return false, nil
	}
	return false, fmt.Errorf("probe IPv6 loopback: %w", err)
}

func renderCaddyfile(c config, p paths, ipv6 bool) (string, error) {
	if p.installed != nil {
		return renderInstalledRoutes(c, ipv6)
	}
	address, err := p.adminAddress()
	if err != nil {
		return "", err
	}
	bind := "127.0.0.1"
	if ipv6 {
		bind += " [::1]"
	}
	if err := c.validate(); err != nil {
		return "", err
	}
	var content strings.Builder
	fmt.Fprintf(&content, `{
	admin %s
	storage file_system %s
	persist_config off
	skip_install_trust
	auto_https disable_redirects
	http_port %d
	https_port %d
	default_bind %s
	grace_period 5s
	servers {
		protocols h1 h2
	}
	pki {
		ca local {
			name "sandbar local CA"
		}
	}
%s}

`, strconv.Quote(address), strconv.Quote(p.file("caddy")), c.HTTPPort, c.HTTPSPort, bind, renderTeleportGlobals(c))
	for _, r := range c.localSites(false) {
		fmt.Fprintf(&content, "https://%s:%d {\n\ttls internal\n", r.Hostname, c.HTTPSPort)
		if r.Upstream == "" {
			fmt.Fprintf(&content, "\theader Content-Type \"text/html; charset=utf-8\"\n\trespond %s 200\n", strconv.Quote(welcomeHTML))
		} else {
			fmt.Fprintf(&content, "\treverse_proxy %s {\n\t\theader_up Host {hostport}\n\t}\n", r.Upstream)
		}
		fmt.Fprintf(&content, "}\n\nhttp://%s:%d {\n\tredir %s{uri} 308\n}\n\n", r.Hostname, c.HTTPPort, c.routeURL(r.Hostname))
	}
	content.WriteString(renderTeleportHTTPSRoutes(c, bind, "local"))
	if c.Version == 3 {
		fmt.Fprintf(&content, "http://:%d {\n\tbind %s\n%s\trespond 404\n}\n", c.HTTPPort, bind, renderTeleportHTTPHandlers(c))
	}
	return strings.TrimRight(content.String(), "\n") + "\n", nil
}

func validateAndReplace(p paths, content string, out, errOut io.Writer) error {
	file, err := os.CreateTemp(p.state, ".Caddyfile-*")
	if err != nil {
		return fmt.Errorf("create Caddyfile candidate: %w", err)
	}
	defer os.Remove(file.Name())
	_, writeErr := io.WriteString(file, content)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := invokeCaddy(caddyEnv(p), nil, out, errOut, "validate", "--config", file.Name(), "--adapter", "caddyfile"); err != nil {
		return err
	}
	return os.Rename(file.Name(), p.file("Caddyfile"))
}

// checkAdminSocket prevents Caddy from unlinking a live instance's socket.
// The command lock serializes this check with other Sandbar commands.
func checkAdminSocket(p paths) error {
	conn, err := net.DialTimeout("unix", p.file("admin.sock"), time.Second)
	if err == nil {
		conn.Close()
		return errors.New("router is already running; stop it before starting again")
	}
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil
	}
	return fmt.Errorf("check private admin socket: %w", err)
}

func start(p paths, out, errOut io.Writer) error {
	if p.installed != nil {
		return startInstalled(p, out, errOut)
	}
	if err := recoverTransaction(p, errOut); err != nil {
		return err
	}
	c, err := readConfig(p.config)
	if err != nil {
		return err
	}
	if _, err := p.adminAddress(); err != nil {
		return err
	}
	if err := checkAdminSocket(p); err != nil {
		return err
	}
	if err := checkCaddy(caddyEnv(p), errOut); err != nil {
		return err
	}
	ipv6, err := ipv6Available(probeIPv6, errOut)
	if err != nil {
		return err
	}
	content, err := renderCaddyfile(c, p, ipv6)
	if err != nil {
		return err
	}
	if err := validateAndReplace(p, content, out, errOut); err != nil {
		return err
	}
	log, err := os.OpenFile(p.file("caddy.log"), os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("open Caddy log: %w", err)
	}
	defer log.Close()
	offset, err := log.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if err := invokeCaddy(caddyEnv(p), nil, log, log, "start", "--config", p.file("Caddyfile"), "--adapter", "caddyfile", "--pidfile", p.file("caddy.pid")); err != nil {
		// Read only this attempt's diagnostics. Never attach a pipe to the daemon.
		if _, seekErr := log.Seek(offset, io.SeekStart); seekErr == nil {
			_, _ = io.Copy(errOut, log)
		}
		fmt.Fprintln(errOut, "Caddy log:", log.Name())
		return err
	}
	for _, r := range c.Routes {
		fmt.Fprintln(out, "HTTPS:", c.routeURL(r.Hostname))
	}
	if len(c.Routes) == 0 {
		fmt.Fprintln(out, "HTTPS: no routes configured")
	}
	fmt.Fprintln(out, "Root certificate:", p.file("caddy/pki/authorities/local/root.crt"))
	fmt.Fprintln(out, "Caddy log:", log.Name())
	return nil
}

func stop(p paths, out, errOut io.Writer) error {
	if p.installed != nil {
		fmt.Fprintf(out, "Stopping Caddy stops all routes served by %s.\n", p.installed.Unit)
		return p.installed.Service.Control("stop", out, errOut)
	}
	address, err := p.adminAddress()
	if err != nil {
		return err
	}
	return invokeCaddy(caddyEnv(p), nil, out, errOut, "stop", "--address", address)
}

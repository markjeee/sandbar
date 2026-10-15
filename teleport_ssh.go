package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
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
	"time"
)

func teleportID(value string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(value)))[:16] }

func teleportAlias(d teleportDestination) string {
	return "sandbar-" + teleportID(d.Host+"\x00"+d.User+"\x00"+strconv.Itoa(d.Port))
}

// SSH expands percent tokens in configuration values. Direct endpoint values do
// not need that syntax, and must not introduce configuration quoting either.
func validateSSHEndpoint(value string) error {
	if value == "" || strings.HasPrefix(value, "-") {
		return errors.New("SSH host and user must be nonempty direct connection values")
	}
	for _, ch := range value {
		if ch <= 32 || ch == 127 || strings.ContainsRune("%\"\\", ch) {
			return errors.New("SSH host and user cannot contain whitespace, quotes, backslashes, or percent tokens")
		}
	}
	return nil
}

func sshConfigPath(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "\\", "\\\\")
	return "\"" + strings.ReplaceAll(value, "\"", "\\\"") + "\""
}

func privateSSHDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return checkPrivateSSHDir(path)
}

func checkPrivateSSHDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("SSH directory must be owned by the current user with mode 0700: %s", path)
	}
	return nil
}

func checkPrivateSSHFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("SSH file must be owned by the current user with mode 0600: %s", path)
	}
	return nil
}

func prepareTeleportSSH(p paths, destinations []teleportDestination) (string, error) {
	dir := filepath.Join(filepath.Dir(p.config), "ssh")
	if strings.IndexFunc(dir, func(ch rune) bool { return ch < 32 || ch == 127 }) >= 0 {
		return "", errors.New("SSH configuration path cannot contain control characters")
	}
	if err := privateSSHDir(dir); err != nil {
		return "", err
	}
	known := filepath.Join(dir, "known_hosts")
	if err := checkPrivateSSHFile(known); err != nil {
		return "", err
	}
	f, err := os.OpenFile(known, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	content, err := renderTeleportSSH(dir, destinations)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "config")
	if err := checkPrivateSSHFile(path); err != nil {
		return "", err
	}
	if err := atomicWriteMode(path, content, 0600, -1, -1); err != nil {
		return "", err
	}
	return path, nil
}

// Render without preparing files, so inspection can verify the owned configuration.
func renderTeleportSSH(dir string, destinations []teleportDestination) ([]byte, error) {
	known := filepath.Join(dir, "known_hosts")
	var b strings.Builder
	b.WriteString("Host *\n  IdentityAgent SSH_AUTH_SOCK\n  IdentityFile none\n  IdentitiesOnly no\n  PreferredAuthentications publickey\n  PubkeyAuthentication yes\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  ForwardAgent no\n  AddKeysToAgent no\n  ControlMaster no\n  ControlPath none\n  StrictHostKeyChecking ask\n  GlobalKnownHostsFile /dev/null\n  UserKnownHostsFile " + sshConfigPath(known) + "\n  ServerAliveInterval 15\n  ServerAliveCountMax 3\n  ExitOnForwardFailure yes\n  ConnectTimeout 15\n\n")
	seen := map[string]bool{}
	for _, d := range destinations {
		if err := validateSSHEndpoint(d.Host); err != nil {
			return nil, err
		}
		if err := validateSSHEndpoint(d.User); err != nil {
			return nil, err
		}
		if d.Port < 1 || d.Port > 65535 {
			return nil, errors.New("SSH port must be from 1 through 65535")
		}
		alias := teleportAlias(d)
		if seen[alias] {
			continue
		}
		seen[alias] = true
		fmt.Fprintf(&b, "Host %s\n  HostName %s\n  User %s\n  Port %d\n\n", alias, sshConfigPath(d.Host), sshConfigPath(d.User), d.Port)
	}
	return []byte(b.String()), nil
}

func runTeleportSSH(out, errOut io.Writer, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = out
	cmd.Stderr = errOut
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("SSH command timed out: %w", ctx.Err())
		}
		return fmt.Errorf("SSH: %w", err)
	}
	return nil
}

func resolveTeleportSSH(alias, host, user string, port int, errOut io.Writer) (teleportDestination, error) {
	if alias == "" || strings.HasPrefix(alias, "-") || strings.ContainsAny(alias, "\r\n\x00") {
		return teleportDestination{}, errors.New("register requires a direct SSH host or alias")
	}
	var output bytes.Buffer
	if err := runTeleportSSH(&output, errOut, "-G", "--", alias); err != nil {
		return teleportDestination{}, err
	}
	d := teleportDestination{}
	for _, line := range strings.Split(output.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "hostname":
			d.Host = fields[1]
		case "user":
			d.User = fields[1]
		case "port":
			d.Port, _ = strconv.Atoi(fields[1])
		case "proxyjump", "proxycommand":
			if fields[1] != "none" {
				return d, errors.New("teleport supports direct SSH only; jump hosts and proxy commands are not supported")
			}
		}
	}
	if host != "" {
		d.Host = host
	}
	if user != "" {
		d.User = user
	}
	if port != 0 {
		d.Port = port
	}
	if err := validateSSHEndpoint(d.Host); err != nil {
		return d, err
	}
	if err := validateSSHEndpoint(d.User); err != nil {
		return d, err
	}
	if d.Port < 1 || d.Port > 65535 {
		return d, errors.New("SSH port must be from 1 through 65535")
	}
	return d, nil
}

func quoteRemoteArg(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func teleportRemoteCommand(d teleportDestination) string {
	bin := d.RemoteBin
	if bin == "" {
		bin = "sandbar"
	}
	args := []string{bin}
	if d.RemoteHome != "" {
		args = append(args, "--home", d.RemoteHome)
	}
	args = append(args, "teleport", "info", "--json")
	for i := range args {
		args[i] = quoteRemoteArg(args[i])
	}
	return strings.Join(args, " ")
}

func readTeleportPeer(configPath string, d teleportDestination, errOut io.Writer) (teleportInfo, error) {
	var output bytes.Buffer
	if err := runTeleportSSH(&output, errOut, "-F", configPath, teleportAlias(d), teleportRemoteCommand(d)); err != nil {
		return teleportInfo{}, fmt.Errorf("read compatible Teleport peer; check remote setup and --remote-bin: %w", err)
	}
	var info teleportInfo
	dec := json.NewDecoder(&output)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&info); err != nil {
		return info, fmt.Errorf("invalid Teleport peer metadata: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return info, errors.New("teleport metadata must contain exactly one JSON object")
	}
	if info.Protocol != 1 {
		return info, errors.New("remote Sandbar must support Teleport protocol 1")
	}
	machine, err := normalizeMachine(info.Machine)
	if err != nil || machine != info.Machine {
		return info, errors.New("remote Teleport machine name is invalid")
	}
	if info.HTTPSPort < 1 || info.HTTPSPort > 65535 {
		return info, errors.New("remote Teleport HTTPS port is invalid")
	}
	if err := validateTeleportRoot(info.RootPEM); err != nil {
		return info, err
	}
	return info, nil
}

// OpenSSH muxserver_listen binds a temporary ControlPath with a dot and
// 16 random characters before linking it to the final socket name.
// https://github.com/openssh/openssh-portable/blob/V_10_3_P1/mux.c#L1236-L1266
const sshControlSocketSuffixLength = 1 + 16

// Control paths are also used by observers that must not prepare runtime files.
func teleportControlPaths(p paths, d teleportDestination) (string, string, error) {
	base := p.state
	if p.installed != nil && p.installed.ID == "apt-systemd-v1" {
		base = p.workDir()
	}
	dir := filepath.Join(base, "teleport", teleportID(d.Machine))
	socket := filepath.Join(dir, "control.sock")
	if len(socket)+sshControlSocketSuffixLength > socketPathLimit {
		base := filepath.Join("/tmp", fmt.Sprintf("sandbar-%d-%s", os.Getuid(), teleportID(filepath.Dir(p.config))))
		socket = filepath.Join(base, teleportID(d.Machine)+".sock")
	}
	return socket, filepath.Join(dir, "ssh.log"), nil
}

func teleportRuntime(p paths, d teleportDestination) (string, string, error) {
	socket, log, err := teleportControlPaths(p, d)
	if err != nil {
		return "", "", err
	}
	for _, dir := range []string{filepath.Dir(log), filepath.Dir(socket)} {
		if err := privateSSHDir(dir); err != nil {
			return "", "", err
		}
	}
	return socket, log, nil
}

// Observe only the caller's existing control connection. No SSH agent is needed.
func observeTeleport(p paths, d teleportDestination) (string, error) {
	socket, _, err := teleportControlPaths(p, d)
	if err != nil {
		return "unknown", err
	}
	if err := checkPrivateSSHDir(filepath.Dir(socket)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "disconnected", nil
		}
		return "unknown", err
	}
	info, err := os.Lstat(socket)
	if errors.Is(err, os.ErrNotExist) {
		return "disconnected", nil
	}
	if err != nil {
		return "unknown", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || int(st.Uid) != os.Getuid() {
		return "unknown", fmt.Errorf("SSH control socket must be owned by the current user with mode 0600: %s", socket)
	}
	configPath := filepath.Join(filepath.Dir(p.config), "ssh", "config")
	if err := checkPrivateSSHDir(filepath.Dir(configPath)); err != nil {
		return "unknown", err
	}
	if _, err := os.Lstat(configPath); err != nil {
		return "unknown", err
	}
	if err := checkPrivateSSHFile(configPath); err != nil {
		return "unknown", err
	}
	var diagnostic bytes.Buffer
	if err := runTeleportSSH(io.Discard, &diagnostic, "-F", configPath, "-S", socket, "-O", "check", teleportAlias(d)); err != nil {
		text := strings.TrimSpace(diagnostic.String())
		// OpenSSH uses these errors for a socket left after a closed master.
		if strings.Contains(text, "Control socket connect(") && (strings.Contains(text, "Connection refused") || strings.Contains(text, "No such file or directory")) {
			return "disconnected", nil
		}
		if text != "" {
			return "unknown", fmt.Errorf("%w: %s", err, text)
		}
		return "unknown", err
	}
	return "connected", nil
}

func teleportMasterExists(configPath, socket string, d teleportDestination) bool {
	return runTeleportSSH(io.Discard, io.Discard, "-F", configPath, "-S", socket, "-O", "check", teleportAlias(d)) == nil
}

func exitTeleportMaster(configPath, socket string, d teleportDestination, errOut io.Writer) error {
	if !teleportMasterExists(configPath, socket, d) {
		return nil
	}
	return runTeleportSSH(io.Discard, errOut, "-F", configPath, "-S", socket, "-O", "exit", teleportAlias(d))
}

func probeTeleportWelcome(d teleportDestination) error {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(d.RootPEM)) {
		return errors.New("invalid destination root")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: machineHostname(d.Machine), MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(d.LocalPort)))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(fmt.Sprintf("https://%s:%d/", machineHostname(d.Machine), d.HTTPSPort))
	if err != nil {
		return fmt.Errorf("verify forwarded welcome: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("forwarded welcome returned HTTP %d", response.StatusCode)
	}
	return nil
}

func connectTeleport(p paths, c config, d teleportDestination, out, errOut io.Writer) error {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return errors.New("teleport requires the caller's existing SSH agent (SSH_AUTH_SOCK)")
	}
	cfg, err := prepareTeleportSSH(p, c.Teleports)
	if err != nil {
		return err
	}
	peer, err := readTeleportPeer(cfg, d, errOut)
	if err != nil {
		return err
	}
	if peer.Machine != d.Machine || peer.HTTPSPort != d.HTTPSPort || peer.RootPEM != d.RootPEM {
		return errors.New("remote Teleport identity, HTTPS port, or CA changed; remove and register the destination again")
	}
	socket, log, err := teleportRuntime(p, d)
	if err != nil {
		return err
	}
	created := !teleportMasterExists(cfg, socket, d)
	if created {
		if err := startTeleportMaster(cfg, socket, log, d, errOut); err != nil {
			return err
		}
	}
	if err := probeTeleportWelcome(d); err != nil {
		if created {
			return errors.Join(err, exitTeleportMaster(cfg, socket, d, errOut))
		}
		return err
	}
	fmt.Fprintln(out, "Connected:", d.Machine, c.routeURL(machineHostname(d.Machine)))
	return nil
}

// A background ssh child can retain stdout and stderr after its parent exits.
// Attach files directly so exec.Cmd does not wait for inherited writer pipes.
func startTeleportMaster(configPath, socket, log string, d teleportDestination, errOut io.Writer) error {
	if err := checkPrivateSSHFile(log); err != nil {
		return err
	}
	file, err := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	forward := fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", d.LocalPort, d.HTTPSPort)
	if err := runTeleportSSH(file, file, "-F", configPath, "-M", "-S", socket, "-E", log, "-f", "-N", "-L", forward, teleportAlias(d)); err != nil {
		if _, seekErr := file.Seek(offset, io.SeekStart); seekErr == nil {
			_, _ = io.Copy(errOut, file)
		}
		return fmt.Errorf("start destination connection; SSH log %s: %w", log, err)
	}
	return nil
}

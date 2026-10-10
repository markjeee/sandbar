//go:build linux

package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type legacyMigration struct {
	Source         []byte
	Config         config
	RestartCommand string
	paths          paths
	account        *user.User
	binary         string
	authority      map[string][]byte
	generated      []byte
	active         []byte
	unit           bool
	running        bool
}

func inspectLegacyMigration(options setupOptions, account *user.User, i *installation) (*legacyMigration, error) {
	if options.MigrateConfig == "" || options.MigrateState == "" {
		return nil, errors.New("migration requires both --migrate-config and --migrate-state")
	}
	if !filepath.IsAbs(options.MigrateConfig) || !filepath.IsAbs(options.MigrateState) {
		return nil, errors.New("migration paths must be absolute")
	}
	m := &legacyMigration{paths: paths{config: filepath.Clean(options.MigrateConfig), state: filepath.Clean(options.MigrateState)}, account: account, binary: i.Binary}
	if m.paths.state == i.State || m.paths.config == i.Source {
		return nil, errors.New("legacy migration source must differ from installed state")
	}
	source, err := readConfigInput(m.paths.config)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeConfig(bytes.NewReader(source))
	if err != nil {
		return nil, err
	}
	if err := validateInstalledPorts(cfg); err != nil {
		return nil, fmt.Errorf("legacy migration: %w", err)
	}
	m.Source, m.Config = source, cfg
	if _, err := os.Lstat(m.paths.file("transaction")); err == nil {
		return nil, fmt.Errorf("legacy recovery is pending at %s; resolve it with the legacy router before migration", m.paths.file("transaction"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	m.authority, err = readLegacyAuthority(m.paths.file("caddy/pki/authorities/local"))
	if err != nil {
		return nil, err
	}
	destination := filepath.Join(i.Storage, "pki/authorities/sandbar")
	if err := checkAuthorityDestination(destination, m.authority); err != nil {
		return nil, err
	}
	m.generated, err = readConfigInput(m.paths.generatedPath())
	if err != nil {
		return nil, fmt.Errorf("read legacy generated configuration: %w", err)
	}
	active, err := readActiveConfig(m.paths)
	if err != nil && !isRouterStopped(err) {
		return nil, fmt.Errorf("inspect legacy router: %w", err)
	}
	if err == nil {
		m.running = true
		m.active = active
		if err := verifyLegacyActive(active, m.paths); err != nil {
			return nil, err
		}
		var adapted bytes.Buffer
		if err := runBounded(i.Binary, caddyEnv(m.paths), nil, &adapted, io.Discard, "adapt", "--config", m.paths.generatedPath(), "--adapter", "caddyfile"); err != nil {
			return nil, fmt.Errorf("adapt legacy generated configuration: %w", err)
		}
		if !jsonEqual(active, adapted.Bytes()) {
			return nil, errors.New("legacy generated configuration differs from active routing; reconcile it before migration")
		}
		pid, uid, err := legacySocketPeer(m.paths.file("admin.sock"))
		if err != nil {
			return nil, err
		}
		expectedUID, err := strconv.Atoi(account.Uid)
		if err != nil {
			return nil, err
		}
		if uid != expectedUID {
			return nil, errors.New("legacy admin socket belongs to another account")
		}
		group, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return nil, fmt.Errorf("identify legacy process: %w", err)
		}
		for _, line := range strings.Split(string(group), "\n") {
			if strings.HasSuffix(line, "/sandbar-router.service") {
				m.unit = true
			}
		}
		if m.unit {
			properties, err := m.userSystemOutput("show", "sandbar-router.service", "--property=LoadState,ActiveState,ExecStart,Environment,Transient")
			if err != nil {
				return nil, fmt.Errorf("inspect temporary legacy user service: %w", err)
			}
			fields, err := parseProperties(properties)
			if err != nil {
				return nil, err
			}
			if err := verifyLegacyUnit(fields, m.paths, account); err != nil {
				return nil, err
			}
		}
	}
	args := []string{"/usr/sbin/runuser", "-u", account.Username, "--", "/usr/bin/env"}
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
		for _, entry := range caddyEnv(m.paths) {
			if strings.HasPrefix(entry, key+"=") {
				args = append(args, entry)
			}
		}
	}
	args = append(args, i.Binary, "start", "--config", m.paths.generatedPath(), "--adapter", "caddyfile", "--pidfile", m.paths.file("caddy.pid"))
	quoted := make([]string, len(args))
	for n, arg := range args {
		quoted[n] = shellQuote(arg)
	}
	m.RestartCommand = strings.Join(quoted, " ")
	return m, nil
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func readLegacyAuthority(dir string) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, name := range []string{"root.crt", "root.key", "intermediate.crt", "intermediate.key"} {
		data, err := readConfigInput(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("legacy CA signing material %s: %w", name, err)
		}
		files[name] = data
	}
	root, err := verifyAuthorityKeyPair(files["root.crt"], files["root.key"])
	if err != nil {
		return nil, fmt.Errorf("legacy root: %w", err)
	}
	intermediate, err := verifyAuthorityKeyPair(files["intermediate.crt"], files["intermediate.key"])
	if err != nil {
		return nil, fmt.Errorf("legacy intermediate: %w", err)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("legacy root is not self-signed: %w", err)
	}
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("legacy intermediate does not use the selected root: %w", err)
	}
	return files, nil
}

func verifyAuthorityKeyPair(certPEM, keyPEM []byte) (*x509.Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("certificate cannot sign certificates")
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid CA private key PEM")
	}
	var key any
	switch keyBlock.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, errors.New("unsupported CA private key PEM")
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key cannot sign certificates")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
		return nil, errors.New("CA private key does not match its certificate")
	}
	return cert, nil
}

func checkAuthorityDestination(dir string, authority map[string][]byte) error {
	for _, name := range []string{"root.crt", "root.key", "intermediate.crt", "intermediate.key"} {
		path := filepath.Join(dir, name)
		data, err := readConfigInput(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(data, authority[name]) {
			return fmt.Errorf("installed CA conflicts at %s; preserve both authorities and review manually", path)
		}
	}
	return nil
}

func verifyLegacyActive(data []byte, p paths) error {
	var active struct {
		Admin struct {
			Listen string `json:"listen"`
		} `json:"admin"`
		Storage struct {
			Module string `json:"module"`
			Root   string `json:"root"`
		} `json:"storage"`
	}
	if err := json.Unmarshal(data, &active); err != nil {
		return err
	}
	address, err := p.adminAddress()
	if err != nil {
		return err
	}
	if active.Admin.Listen != address || active.Storage.Module != "file_system" || active.Storage.Root != p.file("caddy") {
		return errors.New("selected admin endpoint is not the identified legacy Sandbar router")
	}
	return nil
}

func legacySocketPeer(path string) (int, int, error) {
	rawConn, err := net.DialTimeout("unix", path, 3*time.Second)
	if err != nil {
		return 0, 0, err
	}
	conn := rawConn.(*net.UnixConn)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		cred, socketErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if socketErr != nil {
		return 0, 0, socketErr
	}
	return int(cred.Pid), int(cred.Uid), nil
}

func verifyLegacyUnit(fields map[string]string, p paths, account *user.User) error {
	if fields["LoadState"] != "loaded" || fields["ActiveState"] != "active" || fields["Transient"] != "yes" {
		return errors.New("sandbar-router.service is not the identified active temporary unit")
	}
	command := fields["ExecStart"]
	_, args, ok := strings.Cut(command, "argv[]=")
	if !ok {
		return errors.New("temporary user service command cannot be identified")
	}
	args, _, _ = strings.Cut(args, " ;")
	words := strings.Fields(args)
	if len(words) != 2 && len(words) != 4 {
		return errors.New("temporary user service uses unsupported command arguments")
	}
	if !filepath.IsAbs(words[0]) || filepath.Base(words[0]) != "sandbar" || words[len(words)-1] != "start" {
		return errors.New("temporary user service is not Sandbar startup")
	}
	selected := paths{}
	if len(words) == 4 {
		if words[1] != "--home" {
			return errors.New("temporary user service has unsupported options")
		}
		resolved, err := resolvePaths(words[2])
		if err != nil {
			return err
		}
		selected = resolved
	} else {
		if fields["Environment"] != "" {
			return errors.New("temporary user service environment needs manual migration")
		}
		selected = paths{config: filepath.Join(account.HomeDir, ".config/sandbar/config.json"), state: filepath.Join(account.HomeDir, ".local/state/sandbar")}
	}
	if selected.config != p.config || selected.state != p.state {
		return errors.New("temporary user service uses a different Sandbar home")
	}
	return nil
}

func (m *legacyMigration) describe(out io.Writer) {
	block, _ := pem.Decode(m.authority["root.crt"])
	digest := sha256.Sum256(block.Bytes)
	fmt.Fprintln(out, "Legacy source:", m.paths.config)
	fmt.Fprintln(out, "Legacy state:", m.paths.state)
	fmt.Fprintln(out, "Preserve legacy root SHA-256:", hex.EncodeToString(digest[:]))
	fmt.Fprintln(out, "Legacy routing will pause briefly during service cutover.")
	if m.unit {
		fmt.Fprintln(out, "Retire identified temporary user service: sandbar-router.service after verification")
	}
	fmt.Fprintln(out, "Legacy restart after rollback:", m.RestartCommand)
}

func (m *legacyMigration) copyAuthority(i *installation, undo *setupUndo) error {
	current, err := readConfigInput(m.paths.config)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, m.Source) {
		return errors.New("legacy source changed during migration preview")
	}
	generated, err := readConfigInput(m.paths.generatedPath())
	if err != nil {
		return err
	}
	if !bytes.Equal(generated, m.generated) {
		return errors.New("legacy generated configuration changed during migration preview")
	}
	currentAuthority, err := readLegacyAuthority(m.paths.file("caddy/pki/authorities/local"))
	if err != nil {
		return err
	}
	for name, data := range m.authority {
		if !bytes.Equal(currentAuthority[name], data) {
			return errors.New("legacy CA changed during migration preview")
		}
	}
	dest := filepath.Join(i.Storage, "pki/authorities/sandbar")
	if err := checkAuthorityDestination(dest, m.authority); err != nil {
		return err
	}
	backup := filepath.Join(undo.Dir, "legacy")
	if err := setupDirectory(backup, 0700, 0, 0); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"config.json": m.Source, "Caddyfile": m.generated} {
		if err := atomicWriteMode(filepath.Join(backup, name), data, 0600, 0, 0); err != nil {
			return err
		}
	}
	for _, dir := range []string{i.Storage, filepath.Join(i.Storage, "pki"), filepath.Join(i.Storage, "pki/authorities"), dest} {
		if err := ensureAuthorityDirectory(dir, i.UID, i.GID); err != nil {
			return err
		}
	}
	for _, name := range []string{"root.crt", "root.key", "intermediate.crt", "intermediate.key"} {
		data := m.authority[name]
		if err := atomicWriteMode(filepath.Join(backup, name), data, 0600, 0, 0); err != nil {
			return err
		}
		if err := undo.write(filepath.Join(dest, name), data, 0600, i.UID, i.GID); err != nil {
			return err
		}
	}
	return nil
}

func (m *legacyMigration) stop(out, errOut io.Writer) error {
	if !m.running {
		return nil
	}
	active, err := readActiveConfig(m.paths)
	if err != nil {
		return err
	}
	if !jsonEqual(active, m.active) {
		return errors.New("legacy active configuration changed before cutover")
	}
	if m.unit {
		properties, err := m.userSystemOutput("show", "sandbar-router.service", "--property=LoadState,ActiveState,ExecStart,Environment,Transient")
		if err != nil {
			return err
		}
		fields, err := parseProperties(properties)
		if err != nil {
			return err
		}
		if err := verifyLegacyUnit(fields, m.paths, m.account); err != nil {
			return err
		}
		return m.userControl("stop", out, errOut)
	}
	address, err := m.paths.adminAddress()
	if err != nil {
		return err
	}
	return runBounded("/usr/sbin/runuser", caddyEnv(m.paths), nil, out, errOut, "-u", m.account.Username, "--", m.binary, "stop", "--address", address)
}

func (m *legacyMigration) restart(out, errOut io.Writer) error {
	if !m.running {
		return nil
	}
	generated, err := readConfigInput(m.paths.generatedPath())
	if err != nil {
		return err
	}
	if !bytes.Equal(generated, m.generated) {
		return errors.New("legacy generated file changed; restore the backup before restarting")
	}
	// Restart the validated legacy Caddyfile directly. A collected transient unit is not durable startup state.
	return runBounded("/usr/sbin/runuser", caddyEnv(m.paths), nil, out, errOut, "-u", m.account.Username, "--", m.binary, "start", "--config", m.paths.generatedPath(), "--adapter", "caddyfile", "--pidfile", m.paths.file("caddy.pid"))
}

func (m *legacyMigration) userEnv() []string {
	runtime := filepath.Join("/run/user", m.account.Uid)
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "HOME=" + m.account.HomeDir, "XDG_RUNTIME_DIR=" + runtime, "DBUS_SESSION_BUS_ADDRESS=unix:path=" + filepath.Join(runtime, "bus")}
}
func (m *legacyMigration) userSystemOutput(args ...string) ([]byte, error) {
	var out, errOut bytes.Buffer
	command := append([]string{"-u", m.account.Username, "--", "/usr/bin/systemctl", "--user"}, args...)
	err := runBounded("/usr/sbin/runuser", m.userEnv(), nil, &out, &errOut, command...)
	if err != nil {
		return nil, fmt.Errorf("legacy user service: %w: %s", err, strings.TrimSpace(errOut.String()))
	}
	return out.Bytes(), nil
}
func (m *legacyMigration) userControl(action string, out, errOut io.Writer) error {
	return runBounded("/usr/sbin/runuser", m.userEnv(), nil, out, errOut, "-u", m.account.Username, "--", "/usr/bin/systemctl", "--user", action, "sandbar-router.service")
}
func (m *legacyMigration) retire() error {
	if !m.unit {
		return nil
	}
	data, err := m.userSystemOutput("show", "sandbar-router.service", "--property=LoadState,ActiveState")
	if err != nil {
		return err
	}
	fields, err := parseProperties(data)
	if err != nil {
		return err
	}
	if fields["LoadState"] == "not-found" {
		return nil
	}
	if fields["ActiveState"] != "inactive" {
		return errors.New("temporary legacy user service is still active after migration")
	}
	_, err = m.userSystemOutput("reset-failed", "sandbar-router.service")
	return err
}

func ensureAuthorityDirectory(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(path)
		if parent != path {
			if err := ensureAuthorityDirectory(parent, uid, gid); err != nil {
				return err
			}
		}
		return setupDirectory(path, 0700, uid, gid)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("CA directory is not a regular directory: %s", path)
	}
	return nil
}

func (m *legacyMigration) verifyRoot(path string) error {
	data, err := readConfigInput(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, m.authority["root.crt"]) {
		return errors.New("migrated service root differs from the selected legacy root")
	}
	return nil
}

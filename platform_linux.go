//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// Package discovery supplies layout. Service control does not infer package paths.
func inspectInstallation() (*installation, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, errors.New("installed mode supports apt-packaged Caddy with systemd on Linux amd64; use --home for development")
	}
	data, err := systemOutput("/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}\n${Architecture}\n", "caddy")
	if err != nil || string(data) != "installed\namd64\n" {
		return nil, fmt.Errorf("unsupported Caddy package: require installed apt package caddy for amd64 (inspection error: %v)", err)
	}
	owner, err := systemOutput("/usr/bin/dpkg-query", "-S", "/usr/bin/caddy")
	if err != nil || strings.TrimSpace(string(owner)) != "caddy: /usr/bin/caddy" {
		return nil, errors.New("/usr/bin/caddy is not owned by the supported caddy package")
	}
	for _, path := range []string{"/", "/usr", "/usr/bin", "/usr/bin/caddy"} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&0022 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unsupported writable or unowned Caddy executable path: %s", path)
		}
	}
	account, err := user.Lookup("caddy")
	if err != nil || account.HomeDir != "/var/lib/caddy" {
		return nil, errors.New("supported Caddy service requires caddy account with home /var/lib/caddy")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, err
	}
	properties, err := systemOutput("/usr/bin/systemctl", "show", "caddy.service", "--property=LoadState,FragmentPath,User,Group,ExecStart,ExecReload,Environment,DropInPaths")
	if err != nil {
		return nil, fmt.Errorf("inspect caddy.service: %w", err)
	}
	fields, err := parseProperties(properties)
	if err != nil {
		return nil, err
	}
	fragment := fields["FragmentPath"]
	if fields["LoadState"] != "loaded" || (fragment != "/usr/lib/systemd/system/caddy.service" && fragment != "/lib/systemd/system/caddy.service") || fields["User"] != "caddy" || fields["Group"] != "caddy" {
		return nil, errors.New("unsupported caddy.service identity or package layout")
	}
	if err := checkServiceCommands(fields); err != nil {
		return nil, err
	}
	unitOwner, err := systemOutput("/usr/bin/dpkg-query", "-S", fragment)
	if err != nil && fragment == "/usr/lib/systemd/system/caddy.service" {
		unitOwner, err = systemOutput("/usr/bin/dpkg-query", "-S", "/lib/systemd/system/caddy.service")
	}
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(unitOwner)), "caddy: ") {
		return nil, errors.New("standard caddy.service is not owned by the caddy package")
	}

	if fields["Environment"] != "" {
		return nil, errors.New("unsupported caddy.service environment overrides")
	}
	for _, path := range strings.Fields(fields["DropInPaths"]) {
		if path != "/etc/systemd/system/caddy.service.d/sandbar.conf" {
			return nil, fmt.Errorf("unsupported caddy.service override: %s", path)
		}
	}
	i := &installation{ID: "apt-systemd-v1", Binary: "/usr/bin/caddy", Unit: "caddy.service", Fragment: fragment, Config: "/etc/caddy/Caddyfile", Globals: "/etc/caddy/sandbar-global.Caddyfile", Source: "/etc/sandbar/config.json", State: "/var/lib/sandbar", Storage: "/var/lib/caddy/.local/share/caddy", Account: "caddy", UID: uid, GID: gid, GroupID: -1}
	if group, err := user.LookupGroup("sandbar"); err == nil {
		i.GroupID, err = strconv.Atoi(group.Gid)
		if err != nil {
			return nil, err
		}
	}
	i.Service = &systemdService{unit: i.Unit, binary: i.Binary, candidate: filepath.Join(i.State, "validation/Caddyfile")}
	return i, nil
}

func parseProperties(data []byte) (map[string]string, error) {
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			return nil, errors.New("systemd returned invalid service properties")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("systemd returned duplicate service properties")
		}
		fields[key] = value
	}
	return fields, nil
}

type systemdService struct{ unit, binary, candidate string }

func (s *systemdService) Inspect() (serviceState, error) {
	data, err := systemOutput("/usr/bin/systemctl", "show", s.unit, "--property=LoadState,ActiveState,UnitFileState")
	if err != nil {
		return serviceState{State: "inaccessible", Diagnostic: err.Error()}, err
	}
	fields, err := parseProperties(data)
	if err != nil {
		return serviceState{State: "unknown"}, err
	}
	state := serviceState{Boot: fields["UnitFileState"]}
	if fields["LoadState"] != "loaded" {
		state.State = "missing"
		return state, errors.New("caddy.service is not loaded")
	}
	switch fields["ActiveState"] {
	case "active":
		state.State = "active"
	case "inactive":
		state.State = "inactive"
	case "failed":
		state.State = "failed"
	default:
		state.State = "unknown"
	}
	return state, nil
}
func (s *systemdService) Control(action string, out, errOut io.Writer) error {
	switch action {
	case "start", "stop", "reload":
	default:
		return fmt.Errorf("unsupported service action %q", action)
	}
	return runBounded("/usr/bin/systemctl", []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}, nil, out, errOut, "--no-ask-password", action, s.unit)
}
func (s *systemdService) Validate(out, errOut io.Writer) error {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/var/lib/caddy", "USER=caddy", "LOGNAME=caddy", "LANG=C"}
	args := []string{"validate", "--config", s.candidate, "--adapter", "caddyfile"}
	if os.Geteuid() == 0 {
		return runBounded("/usr/sbin/runuser", env, nil, out, errOut, append([]string{"-u", "caddy", "--", s.binary}, args...)...)
	}
	return runBounded("/usr/bin/sudo", env, nil, out, errOut, append([]string{"-n", "-H", "-u", "caddy", "--", s.binary}, args...)...)
}

var serviceArgvPattern = regexp.MustCompile(`argv\[\]=(.*?) ; ignore_errors=`)

func checkServiceCommands(fields map[string]string) error {
	start, err := serviceArgv(fields["ExecStart"])
	if err != nil {
		return err
	}
	if start != "/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile" {
		return errors.New("unsupported caddy.service ExecStart; require the exact packaged Caddyfile command")
	}
	reload, err := serviceArgv(fields["ExecReload"])
	if err != nil {
		return err
	}
	standard := "/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force"
	owned := standard + " --address unix//var/lib/sandbar/admin/admin.sock"
	if reload != standard && reload != owned {
		return errors.New("unsupported caddy.service ExecReload; require the packaged reload command or Sandbar's fixed address")
	}
	return nil
}
func serviceArgv(value string) (string, error) {
	matches := serviceArgvPattern.FindAllStringSubmatch(value, -1)
	if len(matches) != 1 || strings.Count(value, "path=") != 1 || !strings.Contains(value, "path=/usr/bin/caddy ;") {
		return "", errors.New("unsupported or ambiguous Caddy service command")
	}
	return matches[0][1], nil
}

const installedFileMode os.FileMode = 0660
const installedDirectoryMode os.FileMode = 0770 | os.ModeSetgid
const installedSocketMode = "0660"
const socketPathLimit = 107
const startupLabel = "Boot startup"
const setupCommand = "sudo /absolute/path/to/sandbar setup --user <name>"

func installedLogGuidance(i *installation) string { return "journalctl -u caddy.service" }
func installedCaddyEnv(i *installation) []string  { return os.Environ() }

const installedRootMode os.FileMode = 0644
const installedRootUID = 0

const registerLoginStartup = false

func systemOutput(binary string, args ...string) ([]byte, error) {
	var out, diagnostic bytes.Buffer
	err := runBounded(binary, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}, nil, &out, &diagnostic, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(binary), err, strings.TrimSpace(diagnostic.String()))
	}
	return out.Bytes(), nil
}

func waitForInstalledStartup(p paths, c config) error { return nil }

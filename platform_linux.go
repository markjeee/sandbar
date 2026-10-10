//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type serviceState struct {
	State      string
	Boot       string
	Diagnostic string
}

type serviceOperations interface {
	Inspect() (serviceState, error)
	Control(string, io.Writer, io.Writer) error
	Validate(io.Writer, io.Writer) error
}

type installation struct {
	ID       string            `json:"id"`
	Binary   string            `json:"binary"`
	Unit     string            `json:"unit"`
	Fragment string            `json:"fragment"`
	Config   string            `json:"config"`
	Globals  string            `json:"globals"`
	Source   string            `json:"source"`
	State    string            `json:"state"`
	Storage  string            `json:"storage"`
	Account  string            `json:"account"`
	UID      int               `json:"uid"`
	GID      int               `json:"gid"`
	GroupID  int               `json:"group_id"`
	Service  serviceOperations `json:"-"`
}

func (i installation) identity() string {
	data, _ := json.Marshal(i)
	return string(data)
}

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

func systemOutput(binary string, args ...string) ([]byte, error) {
	var out, diagnostic bytes.Buffer
	err := runBounded(binary, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}, nil, &out, &diagnostic, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(binary), err, strings.TrimSpace(diagnostic.String()))
	}
	return out.Bytes(), nil
}

func runBounded(binary string, env []string, in io.Reader, out, errOut io.Writer, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = env
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = errOut
	err := cmd.Run()
	if ctx.Err() != nil {
		return fmt.Errorf("command timed out; service state is unknown: %w", ctx.Err())
	}
	return err
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

func installedPaths(i *installation) paths {
	return paths{config: i.Source, state: i.State, installed: i}
}
func (p paths) rootCertificate() string {
	if p.installed != nil {
		return p.file("root.crt")
	}
	return p.file("caddy/pki/authorities/local/root.crt")
}
func (p paths) caID() string {
	if p.installed != nil {
		return "sandbar"
	}
	return "local"
}
func (p paths) generatedPath() string { return p.file("Caddyfile") }
func (p paths) requireSetup() error {
	if p.installed == nil {
		return nil
	}
	data, err := os.ReadFile(p.file("setup.json"))
	if err != nil {
		return fmt.Errorf("service setup for Sandbar is missing or inaccessible; run sudo /absolute/path/to/sandbar setup --user <name>: %w", err)
	}
	var record setupRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("invalid setup record: %w", err)
	}
	if record.Identity != p.installed.identity() {
		return errors.New("the Caddy installation differs from setup; review sandbar setup --check --user <name>")
	}
	return nil
}

func (p paths) writeFile(path string, data []byte) error {
	mode := os.FileMode(0600)
	if p.installed != nil {
		mode = 0660
	}
	return atomicWriteMode(path, data, mode, -1, -1)
}
func atomicWriteMode(path string, data []byte, mode os.FileMode, uid, gid int) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".sandbar-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := file.Chown(uid, gid); err != nil {
			file.Close()
			return err
		}
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
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

func createSelectedConfig(p paths, c config) error {
	if p.installed == nil {
		return writeConfig(p.config, c)
	}
	data, err := configBytes(c)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(p.config, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0660)
	if err != nil {
		return fmt.Errorf("create shared configuration: %w", err)
	}
	if err := file.Chmod(0660); err != nil {
		file.Close()
		return err
	}
	if err := file.Chown(-1, p.installed.GroupID); err != nil {
		file.Close()
		return err
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return err
	}
	return syncDir(filepath.Dir(p.config))
}

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
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const installedFileMode os.FileMode = 0600
const installedDirectoryMode os.FileMode = 0700
const installedSocketMode = "0600"
const socketPathLimit = 103
const startupLabel = "Login startup"
const setupCommand = "sandbar setup"

func installedLogGuidance(i *installation) string { return i.Log }
func installedCaddyEnv(i *installation) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		switch key {
		case "HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CADDY_ADMIN":
			continue
		}
		env = append(env, item)
	}
	return append(env, "HOME="+filepath.Dir(i.Storage), "XDG_DATA_HOME="+filepath.Dir(i.Storage))
}
func brewOutput(binary string, args ...string) ([]byte, error) {
	var out, diagnostic bytes.Buffer
	err := runBounded(binary, os.Environ(), nil, &out, &diagnostic, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", filepath.Base(binary), err, strings.TrimSpace(diagnostic.String()))
	}
	return out.Bytes(), nil
}
func inspectInstallation() (*installation, error) {
	if runtime.GOARCH != "arm64" {
		return nil, errors.New("installed mode requires Homebrew Caddy on macOS arm64; use --home for development")
	}
	if os.Geteuid() == 0 {
		return nil, errors.New("macOS setup and installed commands require the current non-root user")
	}
	if err := checkHomebrewEnvironmentOverride(); err != nil {
		return nil, err
	}
	brew, err := exec.LookPath("brew")
	if err != nil {
		return nil, errors.New("installed mode requires Homebrew Caddy; use --home for development")
	}
	prefix, err := brewOutput(brew, "--prefix")
	if err != nil {
		return nil, err
	}
	metadata, err := brewOutput(brew, "info", "--json=v2", "caddy")
	if err != nil {
		return nil, err
	}
	account, err := user.Current()
	if err != nil {
		return nil, err
	}
	i, err := homebrewInstallation(strings.TrimSpace(string(prefix)), metadata, account)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(i.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return nil, errors.New("the Homebrew Caddy executable is missing or not executable")
	}
	service := &homebrewService{brew: brew, installation: i}
	i.Service = service
	selected, err := recordedDarwinInstallation(i, brew)
	if err != nil {
		return nil, err
	}
	if _, err := selected.Service.Inspect(); err != nil {
		return nil, err
	}
	return selected, nil
}
func homebrewInstallation(prefix string, data []byte, account *user.User) (*installation, error) {
	var document struct {
		Formulae []struct {
			Name      string `json:"name"`
			Installed []struct {
				Version string `json:"version"`
			} `json:"installed"`
			Service struct {
				Run         []string          `json:"run"`
				Environment map[string]string `json:"environment_variables"`
				Log         string            `json:"log_path"`
				ErrorLog    string            `json:"error_log_path"`
			} `json:"service"`
		} `json:"formulae"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("read Homebrew Caddy metadata: %w", err)
	}
	if !filepath.IsAbs(prefix) || len(document.Formulae) != 1 {
		return nil, errors.New("unsupported Homebrew Caddy metadata")
	}
	formula := document.Formulae[0]
	binary, configPath, storageHome := filepath.Join(prefix, "opt/caddy/bin/caddy"), filepath.Join(prefix, "etc/Caddyfile"), filepath.Join(prefix, "var/lib")
	if formula.Name != "caddy" || len(formula.Installed) == 0 || !reflect.DeepEqual(formula.Service.Run, []string{binary, "run", "--config", configPath}) || !reflect.DeepEqual(formula.Service.Environment, map[string]string{"HOME": storageHome, "XDG_DATA_HOME": storageHome}) || formula.Service.Log != filepath.Join(prefix, "var/log/caddy.log") || formula.Service.ErrorLog != formula.Service.Log {
		return nil, errors.New("unsupported Homebrew Caddy service command, environment, or layout")
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return nil, err
	}
	app := filepath.Join(account.HomeDir, "Library/Application Support/sandbar")
	return &installation{ID: "homebrew-launchd-v1", Binary: binary, Unit: "sh.brew.caddy", Fragment: filepath.Join(account.HomeDir, "Library/LaunchAgents/sh.brew.caddy.plist"), Config: configPath, Globals: filepath.Join(app, "state/global.Caddyfile"), Source: filepath.Join(app, "config.json"), State: filepath.Join(app, "state"), Storage: filepath.Join(storageHome, "caddy"), Account: account.Username, UID: uid, GID: gid, GroupID: gid, Log: formula.Service.Log}, nil
}

type homebrewService struct {
	brew         string
	installation *installation
}
type homebrewServiceInfo struct {
	Name        string  `json:"name"`
	ServiceName string  `json:"service_name"`
	Running     bool    `json:"running"`
	Loaded      bool    `json:"loaded"`
	Registered  bool    `json:"registered"`
	User        *string `json:"user"`
	LoadedFile  *string `json:"loaded_file"`
	Status      string  `json:"status"`
	ExitCode    *int    `json:"exit_code"`
}

func (s *homebrewService) Inspect() (serviceState, error) {
	fail := func(err error) (serviceState, error) {
		return serviceState{State: "inaccessible", Boot: "unknown", Diagnostic: err.Error()}, err
	}
	data, err := brewOutput(s.brew, "services", "info", "caddy", "--json")
	if err != nil {
		return fail(err)
	}
	var entries []homebrewServiceInfo
	if err := json.Unmarshal(data, &entries); err != nil {
		return fail(err)
	}
	if len(entries) != 1 || entries[0].Name != "caddy" || entries[0].ServiceName != s.installation.Unit {
		return fail(errors.New("unsupported Homebrew Caddy service identity"))
	}
	entry := entries[0]
	i := s.installation
	if _, err := os.Lstat(filepath.Join("/Library/LaunchDaemons", i.Unit+".plist")); err == nil {
		return fail(errors.New("root-managed Caddy is unsupported; use the Homebrew user service"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if entry.User != nil && *entry.User != i.Account {
		return fail(errors.New("the Caddy service belongs to another user"))
	}
	if entry.LoadedFile != nil && *entry.LoadedFile != i.Fragment {
		return fail(errors.New("custom Caddy service file is unsupported"))
	}
	if _, err := os.Stat(i.Fragment); err == nil {
		if err := checkHomebrewJob(i); err != nil {
			return fail(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	domain := "gui/" + strconv.Itoa(i.UID)
	output, jobErr := brewOutput("/bin/launchctl", "print", domain+"/"+i.Unit)
	if jobErr != nil {
		if !launchdJobMissing(jobErr, i.Unit) {
			return fail(jobErr)
		}
		if _, err := brewOutput("/bin/launchctl", "print", domain); err != nil {
			return fail(fmt.Errorf("inspect user launchd domain: %w", err))
		}
		output = nil
	}
	state, err := homebrewServiceState(i, entry, output)
	if err != nil {
		return fail(err)
	}
	return state, nil
}
func checkHomebrewJob(i *installation) error {
	data, err := brewOutput("/usr/bin/plutil", "-convert", "json", "-o", "-", i.Fragment)
	if err != nil {
		return err
	}
	var job struct {
		Label                string
		ProgramArguments     []string
		EnvironmentVariables map[string]string
		StandardOutPath      string
		StandardErrorPath    string
		UserName             string
	}
	if err := json.Unmarshal(data, &job); err != nil {
		return err
	}
	if job.Label != i.Unit || !reflect.DeepEqual(job.ProgramArguments, []string{i.Binary, "run", "--config", i.Config}) || !reflect.DeepEqual(job.EnvironmentVariables, map[string]string{"HOME": filepath.Dir(i.Storage), "XDG_DATA_HOME": filepath.Dir(i.Storage)}) || job.StandardOutPath != i.Log || job.StandardErrorPath != i.Log || job.UserName != "" {
		return errors.New("custom Caddy launchd job is unsupported; restore the Homebrew user service before setup")
	}
	return nil
}
func (s *homebrewService) Control(action string, out, errOut io.Writer) error {
	switch action {
	case "start", "stop", "run", "kill":
		return runBounded(s.brew, os.Environ(), nil, out, errOut, "services", action, "caddy")
	case "reload":
		p := installedPaths(s.installation)
		address, err := p.adminAddress()
		if err != nil {
			return err
		}
		return runBounded(s.installation.Binary, installedCaddyEnv(s.installation), nil, out, errOut, "reload", "--config", s.installation.Config, "--force", "--address", address)
	default:
		return fmt.Errorf("unsupported service action %q", action)
	}
}
func (s *homebrewService) Validate(out, errOut io.Writer) error {
	return runBounded(s.installation.Binary, installedCaddyEnv(s.installation), nil, out, errOut, "validate", "--config", filepath.Join(s.installation.State, "validation/Caddyfile"), "--adapter", "caddyfile")
}

func installedRootCertificate(i *installation) string {
	return filepath.Join(i.Storage, "pki/authorities/sandbar/root.crt")
}

// launchctl print separates effective arguments and environment from inherited defaults.
func checkLoadedHomebrewJob(i *installation, data []byte) error {
	var arguments []string
	environment := map[string]string{}
	section, program := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "program = ") {
			program = strings.TrimPrefix(line, "program = ")
		}
		if line == "arguments = {" {
			section = "arguments"
			continue
		}
		if line == "environment = {" {
			section = "environment"
			continue
		}
		if line == "}" {
			section = ""
			continue
		}
		if section == "arguments" {
			arguments = append(arguments, line)
		}
		if section == "environment" {
			key, value, ok := strings.Cut(line, " => ")
			if !ok {
				return errors.New("cannot inspect Caddy launchd environment")
			}
			environment[key] = value
		}
	}
	if program != i.Binary || !reflect.DeepEqual(arguments, []string{i.Binary, "run", "--config", i.Config}) {
		return errors.New("custom loaded Caddy command is unsupported")
	}
	if environment["HOME"] != filepath.Dir(i.Storage) || environment["XDG_DATA_HOME"] != filepath.Dir(i.Storage) {
		return errors.New("custom loaded Caddy storage environment is unsupported")
	}
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CADDY_ADMIN"} {
		if _, ok := environment[key]; ok {
			return fmt.Errorf("custom loaded Caddy environment %s is unsupported", key)
		}
	}
	return nil
}

func homebrewServiceState(i *installation, entry homebrewServiceInfo, job []byte) (serviceState, error) {
	state := serviceState{State: "inactive", Boot: "disabled"}
	if entry.Registered {
		state.Boot = "enabled"
	}
	if job == nil {
		if entry.Loaded || entry.Running {
			return state, errors.New("the Homebrew and launchd inspections disagree about Caddy")
		}
		if entry.Registered || (entry.ExitCode != nil && *entry.ExitCode != 0) {
			state.State = "failed"
		}
		return state, nil
	}
	if err := checkLoadedHomebrewJob(i, job); err != nil {
		return state, err
	}
	if entry.Running && strings.Contains(string(job), "state = running") {
		state.State = "active"
	} else {
		state.State = "failed"
	}
	return state, nil
}

func launchdJobMissing(err error, unit string) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 113 && strings.Contains(err.Error(), "Could not find service \""+unit+"\" in domain for user gui:")
}

const registerLoginStartup = true

func checkHomebrewEnvironmentOverride() error {
	// Homebrew bin/brew selects this root before service.rb reads services/caddy.env.
	configHome := filepath.Join(os.Getenv("HOME"), ".homebrew")
	if path := os.Getenv("XDG_CONFIG_HOME"); path != "" {
		configHome = filepath.Join(path, "homebrew")
	} else if path := os.Getenv("HOMEBREW_XDG_CONFIG_HOME"); path != "" {
		configHome = filepath.Join(path, "homebrew")
	}
	path := filepath.Join(configHome, "services/caddy.env")
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Caddy service environment override %s: %w", path, err)
	}
	if info.Mode().IsRegular() {
		return fmt.Errorf("custom Caddy service environment is unsupported: %s; review and remove the override before setup", path)
	}
	return nil
}

// Homebrew registers launchd before Caddy has opened its listeners.
func waitForInstalledStartup(p paths, c config) error {
	roots, err := selectedStatusRoots(p.rootCertificate())
	if err != nil {
		return err
	}
	err = waitForDarwinStartup(func() error {
		code, err := checkHTTPSRoute(c, route{Hostname: "sandbar.localhost"}, roots)
		if err != nil {
			return err
		}
		if code >= 500 {
			return fmt.Errorf("the Caddy welcome route returned HTTP %d", code)
		}
		return verifySetupRedirect(c, "sandbar.localhost")
	}, 3*time.Second)
	if err != nil {
		return fmt.Errorf("wait for Caddy startup: %w; see %s", err, installedLogGuidance(p.installed))
	}
	return nil
}

func waitForDarwinStartup(check func() error, limit time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	for {
		err := check()
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !initialCertificatePending(err) {
			return err
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("the Caddy service did not become ready within %s: %w", limit, err)
		case <-timer.C:
		}
	}
}

func validateInstalledPorts(c config) error { return c.validate() }

const customInstalledPorts = true

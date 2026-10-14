package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"
)

const sandbarLaunchdID = "sandbar-launchd-v1"
const sandbarLaunchdLabel = "local.sandbar.caddy"

// Allow the observed launchd five-second exit timeout before job replacement.
const launchdShutdownLimit = 10 * time.Second

var launchdOutput = brewOutput
var launchdControl = func(args ...string) error { _, err := launchdOutput("/bin/launchctl", args...); return err }

func launchdTemplate(i *installation) string { return filepath.Join(i.State, "launchd/caddy.plist") }
func launchdDomain(i *installation) string   { return "gui/" + strconv.Itoa(i.UID) }
func launchdTarget(i *installation) string   { return launchdDomain(i) + "/" + i.Unit }
func bridgeArguments(i *installation) []string {
	return []string{i.CLI, "_launchd-caddy", "--caddy", i.Binary, "--config", i.Config, "--setup-record", filepath.Join(i.State, "setup.json")}
}
func newLaunchdInstallation(old *installation, cli string) *installation {
	i := *old
	i.ID = sandbarLaunchdID
	i.Unit = sandbarLaunchdLabel
	i.CLI = cli
	i.Fragment = filepath.Join(filepath.Dir(old.Fragment), sandbarLaunchdLabel+".plist")
	return &i
}
func renderLaunchdJob(i *installation, plan socketPlan) ([]byte, error) {
	if err := plan.validate(); err != nil {
		return nil, err
	}
	for _, path := range []string{i.CLI, i.Binary, i.Config, i.Fragment, i.State, i.Storage, i.Log} {
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("launchd requires an absolute path: %s", path)
		}
	}
	var b bytes.Buffer
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>")
	str := func(s string) {
		b.WriteString("<string>")
		_ = xml.EscapeText(&b, []byte(s))
		b.WriteString("</string>")
	}
	key := func(s string) { b.WriteString("<key>"); _ = xml.EscapeText(&b, []byte(s)); b.WriteString("</key>") }
	key("Label")
	str(i.Unit)
	key("ProgramArguments")
	b.WriteString("<array>")
	for _, arg := range bridgeArguments(i) {
		str(arg)
	}
	b.WriteString("</array>")
	key("EnvironmentVariables")
	b.WriteString("<dict>")
	key("HOME")
	str(filepath.Dir(i.Storage))
	key("XDG_DATA_HOME")
	str(filepath.Dir(i.Storage))
	b.WriteString("</dict>")
	key("StandardOutPath")
	str(i.Log)
	key("StandardErrorPath")
	str(i.Log)
	key("RunAtLoad")
	b.WriteString("<true/>")
	key("KeepAlive")
	b.WriteString("<true/>")
	key("Sockets")
	b.WriteString("<dict>")
	for _, group := range []struct {
		name, kind string
		port       int
	}{{"HTTP", "stream", plan.HTTPPort}, {"HTTPS", "stream", plan.HTTPSPort}, {"QUIC", "dgram", plan.HTTPSPort}} {
		key(group.name)
		b.WriteString("<array>")
		addresses := []string{"127.0.0.1"}
		if plan.IPv6 {
			addresses = append(addresses, "::1")
		}
		for _, address := range addresses {
			b.WriteString("<dict>")
			key("SockType")
			str(group.kind)
			key("SockNodeName")
			str(address)
			key("SockServiceName")
			str(strconv.Itoa(group.port))
			key("SockFamily")
			if address == "::1" {
				str("IPv6")
			} else {
				str("IPv4")
			}
			b.WriteString("</dict>")
		}
		b.WriteString("</array>")
	}
	b.WriteString("</dict></dict></plist>\n")
	return b.Bytes(), nil
}

type launchdService struct {
	installation *installation
	old          *homebrewService
}

func (s *launchdService) Inspect() (serviceState, error) {
	state := serviceState{State: "inactive", Boot: "disabled", Sockets: "released"}
	fail := func(err error) (serviceState, error) {
		state.State = "inaccessible"
		state.Diagnostic = err.Error()
		return state, err
	}
	if s.old != nil {
		if err := checkCompetingHomebrewJob(s.old.installation); err != nil {
			return fail(err)
		}
	}
	i := s.installation
	record, err := readSetupRecord(installedPaths(i))
	if err != nil {
		return fail(err)
	}
	if record.Identity != i.identity() || record.SocketPlan == nil {
		return fail(errors.New("the launchd installation differs from setup; review sandbar setup --check"))
	}
	expected, err := renderLaunchdJob(i, *record.SocketPlan)
	if err != nil {
		return fail(err)
	}
	template, err := readConfigInput(launchdTemplate(i))
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(expected, template) {
		return fail(errors.New("the private Sandbar launchd job changed; review sandbar setup --check"))
	}
	login, err := readOptional(i.Fragment)
	if err != nil {
		return fail(err)
	}
	if login != nil {
		if !bytes.Equal(expected, login) {
			return fail(errors.New("the registered Sandbar launchd job changed; review sandbar setup --check"))
		}
		state.Boot = "enabled"
	}
	output, err := launchdOutput("/bin/launchctl", "print", launchdTarget(i))
	if err != nil {
		if !launchdJobMissing(err, i.Unit) {
			return fail(err)
		}
		if _, err := launchdOutput("/bin/launchctl", "print", launchdDomain(i)); err != nil {
			return fail(err)
		}
		return state, nil
	}
	if err := checkLoadedLaunchdJob(i, output); err != nil {
		return fail(err)
	}
	if err := checkLoadedSocketPlan(output, *record.SocketPlan); err != nil {
		return fail(err)
	}
	state.Sockets = "owned by launchd"
	if strings.Contains(string(output), "state = running") {
		state.State = "active"
	} else {
		state.State = "failed"
	}
	return state, nil
}
func checkLoadedLaunchdJob(i *installation, data []byte) error {
	var arguments []string
	section := ""
	program := ""
	environment := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "program = "):
			program = strings.TrimPrefix(line, "program = ")
		case line == "arguments = {":
			section = "arguments"
		case line == "environment = {":
			section = "environment"
		case line == "}":
			section = ""
		case section == "arguments":
			arguments = append(arguments, line)
		case section == "environment":
			key, value, ok := strings.Cut(line, " => ")
			if ok {
				environment[key] = value
			}
		}
	}
	if program != i.CLI || !reflect.DeepEqual(arguments, bridgeArguments(i)) {
		return errors.New("custom loaded Sandbar launchd command is unsupported")
	}
	if environment["HOME"] != filepath.Dir(i.Storage) || environment["XDG_DATA_HOME"] != filepath.Dir(i.Storage) {
		return errors.New("custom loaded Sandbar storage environment is unsupported")
	}
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "CADDY_ADMIN", "SANDBAR_HOME"} {
		if _, ok := environment[key]; ok {
			return fmt.Errorf("custom loaded Sandbar environment %s is unsupported", key)
		}
	}
	return nil
}
func (s *launchdService) Control(action string, out, errOut io.Writer) error {
	i := s.installation
	state, err := s.Inspect()
	if err != nil {
		return err
	}
	switch action {
	case "stop":
		if state.Sockets != "released" {
			pid := loadedLaunchdPID(i)
			if err := launchdControl("bootout", launchdTarget(i)); err != nil {
				return err
			}
			if err := waitLaunchdRemoval(i, launchdShutdownLimit, pid); err != nil {
				return err
			}
		}
		if err := os.Remove(i.Fragment); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	case "start":
		if state.Boot != "enabled" {
			data, err := readConfigInput(launchdTemplate(i))
			if err != nil {
				return err
			}
			if err := atomicWriteMode(i.Fragment, data, 0600, -1, -1); err != nil {
				return err
			}
		}
		if state.Sockets == "released" {
			return launchdControl("bootstrap", launchdDomain(i), i.Fragment)
		}
		return nil
	case "reload":
		record, err := readSetupRecord(installedPaths(i))
		if err != nil {
			return err
		}
		data, err := loadLaunchdRuntime(i, record, errOut)
		if err != nil {
			return err
		}
		address, err := installedPaths(i).adminAddress()
		if err != nil {
			return err
		}
		return runBounded(i.Binary, installedCaddyEnv(i), bytes.NewReader(data), out, errOut, "reload", "--config", "-", "--force", "--address", address)
	default:
		return fmt.Errorf("unsupported Sandbar launchd action %q", action)
	}
}
func (s *launchdService) Validate(out, errOut io.Writer) error {
	p := installedPaths(s.installation)
	record, err := readSetupRecord(p)
	if err != nil {
		return err
	}
	data, err := adaptCaddyfile(p, p.file("validation/Caddyfile"), errOut)
	if err != nil {
		return err
	}
	if record.SocketPlan == nil {
		return errors.New("missing launchd socket plan")
	}
	data, err = convertSocketRuntime(data, *record.SocketPlan)
	if err != nil {
		return err
	}
	return validateLaunchdRuntime(p, data, out, errOut)
}
func validateLaunchdRuntime(p paths, data []byte, out, errOut io.Writer) error {
	return invokeSelectedCaddy(p, caddyEnv(p), bytes.NewReader(data), out, errOut, "validate", "--config", "-")
}
func loadLaunchdRuntime(i *installation, record setupRecord, errOut io.Writer) ([]byte, error) {
	if record.SocketPlan == nil {
		return nil, errors.New("missing launchd socket plan")
	}
	p := installedPaths(i)
	data, err := adaptCaddyfile(p, i.Config, errOut)
	if err != nil {
		return nil, err
	}
	if record.Identity != i.identity() {
		return nil, errors.New("the launchd installation differs from setup")
	}
	if err := verifyInputManifest(record.Manifest); err != nil {
		return nil, err
	}
	cfg := config{Version: 2, HTTPPort: record.SocketPlan.HTTPPort, HTTPSPort: record.SocketPlan.HTTPSPort}
	hosts := map[string]bool{"sandbar.localhost": true}
	var doc struct {
		Apps struct {
			TLS struct {
				Automation struct {
					Policies []struct {
						Subjects []string `json:"subjects"`
						Issuers  []struct {
							Module string `json:"module"`
							CA     string `json:"ca"`
						} `json:"issuers"`
					} `json:"policies"`
				} `json:"automation"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for _, policy := range doc.Apps.TLS.Automation.Policies {
		if len(policy.Issuers) == 1 && policy.Issuers[0].Module == "internal" && policy.Issuers[0].CA == "sandbar" {
			for _, host := range policy.Subjects {
				if host != "sandbar.localhost" {
					hosts[host] = true
				}
			}
		}
	}
	address, err := p.adminAddress()
	if err != nil {
		return nil, err
	}
	if err := checkInstalledAdaptedHosts(data, cfg, address, hosts); err != nil {
		return nil, err
	}
	return convertSocketRuntime(data, *record.SocketPlan)
}
func waitLaunchdRemoval(i *installation, limit time.Duration, observedPID ...string) error {
	deadline := time.Now().Add(limit)
	for {
		_, err := launchdOutput("/bin/launchctl", "print", launchdTarget(i))
		if err != nil {
			if launchdJobMissing(err, i.Unit) {
				gone := true
				if len(observedPID) > 0 && observedPID[0] != "" {
					output, probeErr := launchdOutput("/bin/ps", "-p", observedPID[0], "-o", "pid=")
					gone = probeErr != nil && strings.TrimSpace(string(output)) == ""
				}
				if gone {
					return nil
				}
			} else {
				return err
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the Caddy job %s did not finish shutdown within %s", i.Unit, limit)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Setup records use JSON identities so binary installation does not migrate services.
func recordedDarwinInstallation(old *installation, brew string) (*installation, error) {
	record, err := readSetupRecord(installedPaths(old))
	if errors.Is(err, os.ErrNotExist) {
		return old, nil
	}
	if err != nil {
		return nil, err
	}
	var saved installation
	if err := json.Unmarshal([]byte(record.Identity), &saved); err != nil {
		return nil, err
	}
	if saved.ID != sandbarLaunchdID {
		return old, nil
	}
	candidate := newLaunchdInstallation(old, saved.CLI)
	if candidate.identity() != record.Identity {
		return nil, errors.New("the Caddy installation differs from setup; review sandbar setup --check")
	}
	candidate.Service = &launchdService{installation: candidate, old: &homebrewService{brew: brew, installation: old}}
	return candidate, nil
}

func checkCompetingHomebrewJob(old *installation) error {
	for _, path := range []string{old.Fragment, filepath.Join("/Library/LaunchDaemons", old.Unit+".plist"), filepath.Join("/Library/LaunchDaemons", sandbarLaunchdLabel+".plist")} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("conflicting Caddy service owner: %s; review sandbar setup --check", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_, err := launchdOutput("/bin/launchctl", "print", launchdTarget(old))
	if err == nil {
		return errors.New("the Homebrew Caddy job conflicts with Sandbar service ownership")
	}
	if !launchdJobMissing(err, old.Unit) {
		return err
	}
	return nil
}

func checkNewLaunchdTarget(i *installation) error {
	for _, path := range []string{i.Fragment, launchdTemplate(i), filepath.Join("/Library/LaunchDaemons", i.Unit+".plist")} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("refuse existing Sandbar launchd job before migration: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_, err := launchdOutput("/bin/launchctl", "print", launchdTarget(i))
	if err == nil {
		return errors.New("refuse an existing local.sandbar.caddy job before migration")
	}
	if !launchdJobMissing(err, i.Unit) {
		return err
	}
	return nil
}

// launchctl prints each array entry as a separate named socket block.
// Verify each IPv4/IPv6 entry, including repeated HTTP, HTTPS and QUIC names.
func checkLoadedSocketPlan(data []byte, plan socketPlan) error {
	ports := map[string]int{"HTTP": plan.HTTPPort, "HTTPS": plan.HTTPSPort, "QUIC": plan.HTTPSPort}
	seen := map[string]bool{}
	var group struct {
		name, kind, node, service, family string
		count                             int
	}
	depth := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if depth == 0 {
			if line == "sockets = {" {
				depth = 1
			}
			continue
		}
		if line == "}" {
			if depth == 2 {
				port, ok := ports[group.name]
				if !ok {
					return fmt.Errorf("loaded launchd job has unexpected socket group %s", group.name)
				}
				kind := "stream"
				if group.name == "QUIC" {
					kind = "datagram"
				}
				node := "127.0.0.1"
				switch group.family {
				case "ipv4":
				case "ipv6":
					if !plan.IPv6 {
						return errors.New("loaded launchd job has unexpected IPv6 sockets")
					}
					node = "::1"
				default:
					return fmt.Errorf("loaded launchd socket group %s has unsupported family %s", group.name, group.family)
				}
				if group.kind != kind || group.node != node || group.service != strconv.Itoa(port) || group.count != 1 {
					return fmt.Errorf("loaded launchd socket group %s (%s) differs from setup", group.name, group.family)
				}
				key := group.name + "/" + group.family
				if seen[key] {
					return fmt.Errorf("loaded launchd job repeats socket %s", key)
				}
				seen[key] = true
			}
			depth--
			if depth == 0 {
				break
			}
			continue
		}
		if strings.HasSuffix(line, " = {") {
			if depth == 1 {
				name, err := strconv.Unquote(strings.TrimSuffix(line, " = {"))
				if err != nil {
					return fmt.Errorf("invalid launchd socket group: %s", line)
				}
				group.name = name
				group.kind = ""
				group.node = ""
				group.service = ""
				group.family = ""
				group.count = 0
			} else if depth != 2 || line != "sockets = {" {
				return fmt.Errorf("unexpected launchd socket block: %s", line)
			}
			depth++
			continue
		}
		if depth == 3 && line != "" {
			descriptor, _, _ := strings.Cut(line, " ")
			value, err := strconv.Atoi(descriptor)
			if err != nil || value < 0 {
				return fmt.Errorf("invalid launchd socket descriptor: %s", line)
			}
			group.count++
		} else if depth == 2 {
			key, value, ok := strings.Cut(line, " = ")
			if !ok {
				continue
			}
			switch key {
			case "type":
				group.kind = value
			case "node name":
				group.node = value
			case "service name":
				group.service = value
			case "family":
				group.family = value
			}
		}
	}
	if depth != 0 {
		return errors.New("incomplete launchd socket definitions")
	}
	families := []string{"ipv4"}
	if plan.IPv6 {
		families = append(families, "ipv6")
	}
	for _, name := range []string{"HTTP", "HTTPS", "QUIC"} {
		for _, family := range families {
			if !seen[name+"/"+family] {
				return fmt.Errorf("loaded launchd job is missing socket %s/%s", name, family)
			}
		}
	}
	return nil
}

func loadedLaunchdPID(i *installation) string {
	output, err := launchdOutput("/bin/launchctl", "print", launchdTarget(i))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid = ") {
			pid := strings.TrimPrefix(line, "pid = ")
			if value, err := strconv.Atoi(pid); err == nil && value > 0 {
				return pid
			}
		}
	}
	return ""
}

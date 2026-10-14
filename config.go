package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type route struct {
	Hostname string `json:"hostname"`
	Upstream string `json:"upstream"`
}

type teleportDestination struct {
	Machine    string `json:"machine"`
	Host       string `json:"host"`
	User       string `json:"user"`
	Port       int    `json:"port"`
	HTTPSPort  int    `json:"https_port"`
	LocalPort  int    `json:"local_port"`
	RemoteBin  string `json:"remote_bin,omitempty"`
	RemoteHome string `json:"remote_home,omitempty"`
	RootPEM    string `json:"root_pem"`
}

type config struct {
	Version      int                   `json:"version"`
	Machine      string                `json:"machine,omitempty"`
	Teleports    []teleportDestination `json:"teleports,omitempty"`
	Hostname     string                `json:"hostname,omitempty"`
	UpstreamPort int                   `json:"upstream_port,omitempty"`
	HTTPPort     int                   `json:"http_port"`
	HTTPSPort    int                   `json:"https_port"`
	Routes       []route               `json:"routes,omitempty"`
}

func (c config) MarshalJSON() ([]byte, error) {
	if c.Version == 1 {
		return json.Marshal(struct {
			Version      int    `json:"version"`
			Hostname     string `json:"hostname"`
			UpstreamPort int    `json:"upstream_port"`
			HTTPPort     int    `json:"http_port"`
			HTTPSPort    int    `json:"https_port"`
		}{c.Version, c.Hostname, c.UpstreamPort, c.HTTPPort, c.HTTPSPort})
	}
	routes := c.Routes
	if routes == nil {
		routes = []route{}
	}
	if c.Version == 3 {
		destinations := c.Teleports
		if destinations == nil {
			destinations = []teleportDestination{}
		}
		return json.Marshal(struct {
			Version   int                   `json:"version"`
			Machine   string                `json:"machine"`
			HTTPPort  int                   `json:"http_port"`
			HTTPSPort int                   `json:"https_port"`
			Routes    []route               `json:"routes"`
			Teleports []teleportDestination `json:"teleports"`
		}{c.Version, c.Machine, c.HTTPPort, c.HTTPSPort, routes, destinations})
	}
	return json.Marshal(struct {
		Version   int     `json:"version"`
		HTTPPort  int     `json:"http_port"`
		HTTPSPort int     `json:"https_port"`
		Routes    []route `json:"routes"`
	}{c.Version, c.HTTPPort, c.HTTPSPort, routes})
}

func normalizeHostname(hostname string) (string, error) {
	for _, ch := range hostname {
		if ch > 127 {
			return "", errors.New("hostname must contain only ASCII characters")
		}
	}
	hostname = strings.ToLower(hostname)
	if len(hostname) > 253 || !strings.HasSuffix(hostname, ".sandbar.localhost") {
		return "", errors.New("hostname must be an ASCII name below sandbar.localhost")
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("hostname has an invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("hostname may contain only ASCII letters, digits, hyphens, and label separators")
			}
		}
	}
	return hostname, nil
}

func normalizeUpstream(input string, httpPort, httpsPort int) (string, error) {
	value := input
	if _, err := strconv.Atoi(value); err == nil {
		value = "http://127.0.0.1:" + value
	} else if !strings.Contains(value, "://") {
		if _, _, err := net.SplitHostPort(value); err != nil {
			return "", errors.New("upstream must be a port, a host-and-port pair, or an HTTP(S) URL")
		}
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid upstream: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("upstream scheme must be http or https")
	}
	if u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(value, "#") || u.Opaque != "" {
		return "", errors.New("upstream must be an origin without credentials, paths, queries, or fragments")
	}
	if strings.Count(u.Host, ":") > 1 && !strings.HasPrefix(u.Host, "[") {
		return "", errors.New("IPv6 upstream addresses must use brackets")
	}
	host := strings.ToLower(u.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("upstream host must be localhost or a loopback IP address")
	}
	if ip != nil {
		host = ip.String()
	}
	portText := u.Port()
	if portText == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", errors.New("upstream port must be from 1 through 65535")
		}
		portText = "80"
		if u.Scheme == "https" {
			portText = "443"
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("upstream port must be from 1 through 65535")
	}
	if port == httpPort || port == httpsPort {
		return "", errors.New("upstream port must differ from http_port and https_port")
	}
	return u.Scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func (c *config) validate() error {
	if c.Version != 1 && c.Version != 2 && c.Version != 3 {
		return fmt.Errorf("unsupported configuration version %d (want 1, 2, or 3)", c.Version)
	}
	for _, p := range []struct {
		name  string
		value int
	}{{"http_port", c.HTTPPort}, {"https_port", c.HTTPSPort}} {
		if p.value < 1 || p.value > 65535 {
			return fmt.Errorf("%s must be from 1 through 65535", p.name)
		}
	}
	if c.HTTPPort == c.HTTPSPort {
		return errors.New("http_port and https_port must differ")
	}
	if c.Version == 1 {
		hostname, err := normalizeHostname(c.Hostname)
		if err != nil {
			return err
		}
		c.Hostname = hostname
		c.Routes = []route{{hostname, strconv.Itoa(c.UpstreamPort)}}
	}
	if c.Version == 3 {
		machine, err := normalizeMachine(c.Machine)
		if err != nil {
			return err
		}
		c.Machine = machine
		if err := c.validateTeleports(); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		hostname, err := normalizeHostname(r.Hostname)
		if err != nil {
			return err
		}
		if seen[hostname] {
			return fmt.Errorf("duplicate hostname %q", hostname)
		}
		seen[hostname] = true
		upstream, err := normalizeUpstream(r.Upstream, c.HTTPPort, c.HTTPSPort)
		if err != nil {
			return fmt.Errorf("%s: %w", hostname, err)
		}
		if c.Version == 3 && len(ownMachineHostname(hostname, c.Machine)) > 253 {
			return fmt.Errorf("machine alias for %s exceeds 253 characters", hostname)
		}
		r.Hostname, r.Upstream = hostname, upstream
	}
	sort.Slice(c.Routes, func(i, j int) bool { return c.Routes[i].Hostname < c.Routes[j].Hostname })
	return nil
}

func (c config) routeURL(hostname string) string {
	if c.HTTPSPort == 443 {
		return "https://" + hostname
	}
	return fmt.Sprintf("https://%s:%d", hostname, c.HTTPSPort)
}

func (c config) httpsURL() string {
	hostname := c.Hostname
	if hostname == "" && len(c.Routes) > 0 {
		hostname = c.Routes[0].Hostname
	}
	return c.routeURL(hostname)
}

func readConfig(path string) (config, error) {
	file, err := os.Open(path)
	if err != nil {
		return config{}, fmt.Errorf("read configuration: %w", err)
	}
	defer file.Close()
	return decodeConfig(file)
}

func decodeConfig(input io.Reader) (config, error) {
	var raw json.RawMessage
	decoder := json.NewDecoder(input)
	if err := decoder.Decode(&raw); err != nil {
		return config{}, fmt.Errorf("read configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return config{}, errors.New("configuration must contain exactly one JSON object")
	}
	var header struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return config{}, err
	}
	c := config{Version: header.Version}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	switch header.Version {
	case 1:
		var legacy struct {
			Version      int    `json:"version"`
			Hostname     string `json:"hostname"`
			UpstreamPort int    `json:"upstream_port"`
			HTTPPort     int    `json:"http_port"`
			HTTPSPort    int    `json:"https_port"`
		}
		if err := decoder.Decode(&legacy); err != nil {
			return c, fmt.Errorf("read configuration: %w", err)
		}
		c.Hostname, c.UpstreamPort, c.HTTPPort, c.HTTPSPort = legacy.Hostname, legacy.UpstreamPort, legacy.HTTPPort, legacy.HTTPSPort
	case 2:
		var current struct {
			Version   int      `json:"version"`
			HTTPPort  int      `json:"http_port"`
			HTTPSPort int      `json:"https_port"`
			Routes    *[]route `json:"routes"`
		}
		if err := decoder.Decode(&current); err != nil {
			return c, fmt.Errorf("read configuration: %w", err)
		}
		if current.Routes == nil {
			return c, errors.New("version 2 configuration requires a routes array")
		}
		c.HTTPPort, c.HTTPSPort, c.Routes = current.HTTPPort, current.HTTPSPort, *current.Routes
	case 3:
		var current struct {
			Version   int                    `json:"version"`
			Machine   string                 `json:"machine"`
			HTTPPort  int                    `json:"http_port"`
			HTTPSPort int                    `json:"https_port"`
			Routes    *[]route               `json:"routes"`
			Teleports *[]teleportDestination `json:"teleports"`
		}
		if err := decoder.Decode(&current); err != nil {
			return c, fmt.Errorf("read configuration: %w", err)
		}
		if current.Routes == nil || current.Teleports == nil {
			return c, errors.New("version 3 configuration requires routes and teleports arrays")
		}
		c.Machine, c.HTTPPort, c.HTTPSPort, c.Routes, c.Teleports = current.Machine, current.HTTPPort, current.HTTPSPort, *current.Routes, *current.Teleports
	default:
		return c, fmt.Errorf("unsupported configuration version %d (want 1, 2, or 3)", c.Version)
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

func configBytes(c config) ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	return append(data, '\n'), err
}

func writeConfig(path string, c config) error {
	data, err := configBytes(c)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create configuration: %w", err)
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	return errors.Join(writeErr, syncErr, file.Close())
}

func normalizeMachine(name string) (string, error) {
	if len(name) == 0 || len(name) > 55 {
		return "", errors.New("machine must be one ASCII DNS label of 1 through 55 characters")
	}
	for _, ch := range name {
		if ch > 127 {
			return "", errors.New("machine must contain only ASCII letters, digits, and hyphens")
		}
	}
	name = strings.ToLower(name)
	if name[0] == '-' || name[len(name)-1] == '-' {
		return "", errors.New("machine must not start or end with a hyphen")
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
			return "", errors.New("machine must be one ASCII DNS label")
		}
	}
	return name, nil
}

func machineHostname(machine string) string { return "sandbar-" + machine + ".localhost" }
func ownMachineHostname(hostname, machine string) string {
	return strings.TrimSuffix(hostname, "sandbar.localhost") + machineHostname(machine)
}

func selectMachine(saved, requested, hostname string) (string, error) {
	if requested != "" {
		name, err := normalizeMachine(requested)
		if err != nil {
			return "", fmt.Errorf("--machine: %w", err)
		}
		if saved != "" && name != saved {
			return "", fmt.Errorf("machine identity is already %s; changing it is not supported", saved)
		}
		return name, nil
	}
	if saved != "" {
		return saved, nil
	}
	label, _, _ := strings.Cut(hostname, ".")
	name, err := normalizeMachine(label)
	if err != nil {
		return "", fmt.Errorf("OS hostname has no valid machine name; supply --machine <name>: %w", err)
	}
	return name, nil
}

func upgradeMachineConfig(c config, requested string) (config, error) {
	hostname := ""
	if c.Machine == "" && requested == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			return c, fmt.Errorf("read OS hostname; supply --machine <name>: %w", err)
		}
	}
	machine, err := selectMachine(c.Machine, requested, hostname)
	if err != nil {
		return c, err
	}
	c.Version, c.Machine, c.Hostname, c.UpstreamPort = 3, machine, "", 0
	if c.Routes == nil {
		c.Routes = []route{}
	}
	if c.Teleports == nil {
		c.Teleports = []teleportDestination{}
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

func validateTeleportRoot(root string) error {
	data := []byte(strings.TrimSpace(root))
	if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return errors.New("destination root must be a public PEM CA certificate")
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("destination root must contain exactly one public PEM CA certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse destination root: %w", err)
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		return errors.New("destination root must be a CA certificate")
	}
	return nil
}

func (c *config) validateTeleports() error {
	seen := map[string]bool{}
	ports := map[int]bool{}
	for i := range c.Teleports {
		d := &c.Teleports[i]
		machine, err := normalizeMachine(d.Machine)
		if err != nil {
			return fmt.Errorf("destination: %w", err)
		}
		d.Machine = machine
		if machine == c.Machine || seen[machine] {
			return fmt.Errorf("destination machine %s conflicts with an existing identity", machine)
		}
		seen[machine] = true
		if err := validateSSHEndpoint(d.Host); err != nil {
			return err
		}
		if err := validateSSHEndpoint(d.User); err != nil {
			return err
		}
		for _, port := range []int{d.Port, d.HTTPSPort, d.LocalPort} {
			if port < 1 || port > 65535 {
				return errors.New("destination ports must be from 1 through 65535")
			}
		}
		if d.LocalPort == c.HTTPPort || d.LocalPort == c.HTTPSPort || ports[d.LocalPort] {
			return errors.New("destination local port conflicts with another listener")
		}
		ports[d.LocalPort] = true
		for _, path := range []string{d.RemoteBin, d.RemoteHome} {
			if path != "" && (!filepath.IsAbs(path) || strings.ContainsAny(path, "\r\n\x00")) {
				return errors.New("destination remote paths must be absolute and contain no control characters")
			}
		}
		if err := validateTeleportRoot(d.RootPEM); err != nil {
			return fmt.Errorf("destination %s: %w", machine, err)
		}
	}
	sort.Slice(c.Teleports, func(i, j int) bool { return c.Teleports[i].Machine < c.Teleports[j].Machine })
	return nil
}

// localSites derives aliases without adding editable duplicate app records.
func (c config) localSites(installed bool) []route {
	sites := []route{}
	if installed {
		sites = append(sites, route{Hostname: "sandbar.localhost"})
	}
	if c.Version == 3 {
		sites = append(sites, route{Hostname: machineHostname(c.Machine)})
	}
	for _, r := range c.Routes {
		sites = append(sites, r)
		if c.Version == 3 {
			sites = append(sites, route{Hostname: ownMachineHostname(r.Hostname, c.Machine), Upstream: r.Upstream})
		}
	}
	return sites
}

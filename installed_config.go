package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const globalMarkerStart = "# BEGIN SANDBAR GLOBAL\n"
const globalMarkerEnd = "# END SANDBAR GLOBAL\n"
const routesMarkerStart = "# BEGIN SANDBAR ROUTES\n"
const routesMarkerEnd = "# END SANDBAR ROUTES\n"

func renderInstalledGlobals(c config, adminAddress, rootCert, rootKey string) string {
	var b strings.Builder
	if c.HTTPPort != 80 || c.HTTPSPort != 443 {
		fmt.Fprintf(&b, "http_port %d\nhttps_port %d\n", c.HTTPPort, c.HTTPSPort)
	}
	fmt.Fprintf(&b, "admin %s\nskip_install_trust\npki {\n\tca sandbar {\n\t\tname \"sandbar local CA\"\n", strconv.Quote(adminAddress+"|"+installedSocketMode))
	if rootCert != "" && rootKey != "" {
		fmt.Fprintf(&b, "\t\troot {\n\t\t\tcert %s\n\t\t\tkey %s\n\t\t}\n", strconv.Quote(rootCert), strconv.Quote(rootKey))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

const welcomeHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Sandbar</title><h1>Sandbar is running</h1><p>Add your first app:</p><pre>sandbar add netbox.sandbar.localhost 8000</pre></html>`

func renderInstalledRoutes(c config, ipv6 bool) (string, error) {
	if err := validateInstalledPorts(c); err != nil {
		return "", err
	}
	if err := c.validate(); err != nil {
		return "", err
	}
	bind := "127.0.0.1"
	if ipv6 {
		bind += " [::1]"
	}
	var b strings.Builder
	sites := append([]route{{Hostname: "sandbar.localhost"}}, c.Routes...)
	for _, r := range sites {
		fmt.Fprintf(&b, "https://%s:%d {\n\tbind %s\n\ttls {\n\t\tissuer internal {\n\t\t\tca sandbar\n\t\t}\n\t}\n", r.Hostname, c.HTTPSPort, bind)
		if r.Hostname == "sandbar.localhost" {
			fmt.Fprintf(&b, "\theader Content-Type \"text/html; charset=utf-8\"\n\trespond %s 200\n", strconv.Quote(welcomeHTML))
		} else {
			fmt.Fprintf(&b, "\treverse_proxy %s\n", r.Upstream)
		}
		fmt.Fprintf(&b, "}\n\nhttp://%s:%d {\n\tbind %s\n\tredir %s{uri} 308\n}\n\n", r.Hostname, c.HTTPPort, bind, c.routeURL(r.Hostname))
	}
	// An explicit fallback prevents Caddy's automatic redirect fallback from
	// redirecting names that Sandbar does not serve. Exact custom sites retain priority.
	fmt.Fprintf(&b, "http://:%d {\n\tbind %s\n\trespond 404\n}\n", c.HTTPPort, bind)
	return strings.TrimRight(b.String(), "\n") + "\n", nil
}

type inputFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type inputGlob struct {
	Pattern string   `json:"pattern"`
	Matches []string `json:"matches"`
}
type inputManifest struct {
	Files []inputFile `json:"files"`
	Globs []inputGlob `json:"globs,omitempty"`
}
type installedComposition struct {
	Top           []byte
	Candidate     []byte
	Manifest      inputManifest
	StockReplaced bool
}
type caddyToken struct {
	text                    string
	start, end, line, depth int
}

// scanCaddyfile locates blocks and static imports. Caddy owns syntax validation.
// Unsupported token forms fail rather than guessing where to insert imports.
func scanCaddyfile(data []byte) ([]caddyToken, error) {
	var tokens []caddyToken
	line, depth := 1, 0
	for i := 0; i < len(data); {
		switch data[i] {
		case ' ', '\t', '\r':
			i++
			continue
		case '\n':
			line++
			i++
			continue
		case '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			continue
		}
		start, tokenLine := i, line
		var value string
		if data[i] == '"' || data[i] == '`' {
			quote := data[i]
			i++
			for i < len(data) && data[i] != quote {
				if data[i] == '\n' {
					line++
				}
				if quote == '"' && data[i] == '\\' {
					i++
				}
				i++
			}
			if i >= len(data) {
				return nil, errors.New("unterminated Caddyfile quote")
			}
			i++
			var err error
			value, err = strconv.Unquote(string(data[start:i]))
			if err != nil {
				return nil, err
			}
		} else {
			for i < len(data) && !strings.ContainsRune(" \t\r\n", rune(data[i])) {
				i++
			}
			value = string(data[start:i])
		}
		if strings.Contains(value, "<<") || strings.Contains(value, "{$") {
			return nil, errors.New("environment substitutions and heredocs need manual Caddy integration")
		}
		if value == "}" {
			depth--
			if depth < 0 {
				return nil, errors.New("unbalanced Caddyfile braces")
			}
		}
		tokens = append(tokens, caddyToken{value, start, i, tokenLine, depth})
		if value == "{" {
			depth++
		}
	}
	if depth != 0 {
		return nil, errors.New("unbalanced Caddyfile braces")
	}
	return tokens, nil
}

func stripOwnedMarker(data []byte, start, end string) ([]byte, error) {
	a, b := bytes.Count(data, []byte(start)), bytes.Count(data, []byte(end))
	if a == 0 && b == 0 {
		return data, nil
	}
	if a != 1 || b != 1 {
		return nil, errors.New("conflicting Sandbar integration markers; review the service Caddyfile")
	}
	i, j := bytes.Index(data, []byte(start)), bytes.Index(data, []byte(end))
	if j < i {
		return nil, errors.New("conflicting Sandbar integration markers")
	}
	return append(append([]byte{}, data[:i]...), data[j+len(end):]...), nil
}

func stockSiteRange(data []byte, tokens []caddyToken) (int, int, bool) {
	for i, t := range tokens {
		if t.depth != 0 || t.text != ":80" || i+6 >= len(tokens) || (i > 0 && tokens[i-1].text != "}") {
			continue
		}
		want := []string{":80", "{", "root", "*", "/usr/share/caddy", "file_server", "}"}
		if i+len(want) > len(tokens) {
			continue
		}
		equal := true
		for j, w := range want {
			if tokens[i+j].text != w {
				equal = false
				break
			}
		}
		if equal && tokens[i+6].depth == 0 {
			return t.start, tokens[i+6].end, true
		}
	}
	return 0, 0, false
}

func composeInstalledConfig(topPath string, topBytes []byte, globalPath, routePath string, globals, routes []byte, replaceStock bool) (installedComposition, error) {
	var result installedComposition
	top, err := stripOwnedMarker(topBytes, globalMarkerStart, globalMarkerEnd)
	if err != nil {
		return result, err
	}
	top, err = stripOwnedMarker(top, routesMarkerStart, routesMarkerEnd)
	if err != nil {
		return result, err
	}
	tokens, err := scanCaddyfile(top)
	if err != nil {
		return result, fmt.Errorf("%s: %w", topPath, err)
	}
	if a, b, stock := stockSiteRange(top, tokens); stock {
		if !replaceStock {
			return result, fmt.Errorf("%s contains Caddy's stock welcome site; review setup --check and use --replace-default-site", topPath)
		}
		top = append(append([]byte{}, top[:a]...), top[b:]...)
		result.StockReplaced = true
		tokens, err = scanCaddyfile(top)
		if err != nil {
			return result, err
		}
	}
	for n, token := range tokens {
		if token.depth == 1 && token.text == "admin" {
			return result, fmt.Errorf("%s defines an admin endpoint outside Sandbar markers; review it before setup", topPath)
		}
		if token.text == "ca" && n+1 < len(tokens) && tokens[n+1].text == "sandbar" {
			return result, fmt.Errorf("%s already defines CA sandbar outside Sandbar markers", topPath)
		}
	}
	globalImport := globalMarkerStart + "import " + strconv.Quote(globalPath) + "\n" + globalMarkerEnd
	if len(tokens) > 0 && tokens[0].text == "{" {
		at := tokens[0].end
		prefix := "\n"
		if at < len(top) && top[at] == '\n' {
			at++
			prefix = ""
		}
		top = append(append(append([]byte{}, top[:at]...), []byte(prefix+globalImport)...), top[at:]...)
	} else {
		top = append([]byte("{\n"+globalImport+"}\n"), top...)
	}
	if len(top) > 0 && top[len(top)-1] != '\n' {
		top = append(top, '\n')
	}
	top = append(top, []byte(routesMarkerStart+"import "+strconv.Quote(routePath)+"\n"+routesMarkerEnd)...)
	result.Top = top
	result.Candidate, result.Manifest, err = composeCandidate(topPath, top, map[string][]byte{filepath.Clean(topPath): top, filepath.Clean(globalPath): globals, filepath.Clean(routePath): routes}, routePath)
	return result, err
}

func stageInstalledCandidate(topPath, globalPath, routePath string, routeBytes []byte) ([]byte, inputManifest, error) {
	if _, err := readConfigInput(routePath); err != nil {
		return nil, inputManifest{}, err
	}
	top, err := readConfigInput(topPath)
	if err != nil {
		return nil, inputManifest{}, err
	}
	globals, err := readConfigInput(globalPath)
	if err != nil {
		return nil, inputManifest{}, err
	}
	return composeCandidate(topPath, top, map[string][]byte{filepath.Clean(globalPath): globals, filepath.Clean(routePath): routeBytes}, routePath)
}

func readConfigInput(path string) ([]byte, error) {
	clean, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var missing error
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			missing = fmt.Errorf("read Caddy input %s: %w", path, err)
		} else if err != nil {
			return nil, fmt.Errorf("read Caddy input %s: %w", path, err)
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("the Caddy input %s uses a symlink; use regular configuration files", path)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	if missing != nil {
		return nil, missing
	}
	info, err := os.Stat(clean)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("the Caddy input %s is not a regular file", path)
	}
	return os.ReadFile(clean)
}

func inputRecord(path string, data []byte) (inputFile, error) {
	if _, err := readConfigInput(path); err != nil {
		return inputFile{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return inputFile{}, err
	}
	if !info.Mode().IsRegular() {
		return inputFile{}, fmt.Errorf("the Caddy input %s is not a regular file", path)
	}
	digest := sha256.Sum256(data)
	return inputFile{path, hex.EncodeToString(digest[:]), uint32(info.Mode().Perm())}, nil
}

func importMatches(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	if !strings.ContainsAny(pattern, "*?[") {
		if len(matches) == 0 {
			return nil, fmt.Errorf("the Caddy import %s does not exist", pattern)
		}
	}
	result := []string{}
	for _, match := range matches {
		if strings.HasPrefix(filepath.Base(match), ".") && strings.HasPrefix(filepath.Base(pattern), "*") {
			continue
		}
		result = append(result, match)
	}
	return result, nil
}

func composeCandidate(topPath string, top []byte, overrides map[string][]byte, routePath string) ([]byte, inputManifest, error) {
	manifest := inputManifest{}
	visiting := map[string]bool{}
	seen := map[string]bool{}
	var expand func(string, []byte) ([]byte, error)
	expand = func(path string, data []byte) ([]byte, error) {
		path = filepath.Clean(path)
		if visiting[path] {
			return nil, fmt.Errorf("cyclic Caddy import at %s", path)
		}
		visiting[path] = true
		defer delete(visiting, path)
		if path != filepath.Clean(routePath) && !seen[path] {
			record, err := inputRecord(path, data)
			if err != nil {
				// Setup can compose a not-yet-created global fragment.
				if _, owned := overrides[path]; !owned || !errors.Is(err, os.ErrNotExist) {
					return nil, err
				}
				digest := sha256.Sum256(data)
				record = inputFile{path, hex.EncodeToString(digest[:]), 0644}
			}
			manifest.Files = append(manifest.Files, record)
			seen[path] = true
		}
		tokens, err := scanCaddyfile(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := checkCaddyInputPaths(path, tokens); err != nil {
			return nil, err
		}
		var out bytes.Buffer
		cursor := 0
		for i, t := range tokens {
			if t.text != "import" {
				continue
			}
			if i > 0 && tokens[i-1].line == t.line && tokens[i-1].text != "{" {
				continue
			}
			if i+1 >= len(tokens) || tokens[i+1].line != t.line {
				return nil, fmt.Errorf("unsupported Caddy import in %s", path)
			}
			arg := tokens[i+1]
			if i+2 < len(tokens) && tokens[i+2].line == t.line {
				return nil, fmt.Errorf("the Caddy import arguments require manual integration: %s", path)
			}
			if strings.ContainsAny(arg.text, "{}") {
				return nil, fmt.Errorf("the Caddy snippet or dynamic import requires manual integration: %s", path)
			}
			pattern := arg.text
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(path), pattern)
			}
			pattern = filepath.Clean(pattern)
			var matches []string
			if _, ok := overrides[pattern]; ok {
				matches = []string{pattern}
			} else {
				matches, err = importMatches(pattern)
				if err != nil {
					return nil, err
				}
			}
			if strings.ContainsAny(pattern, "*?[") {
				manifest.Globs = append(manifest.Globs, inputGlob{pattern, matches})
			}
			out.Write(data[cursor:t.start])
			for _, match := range matches {
				imported, owned := overrides[match]
				if !owned {
					imported, err = readConfigInput(match)
					if err != nil {
						return nil, err
					}
				}
				expanded, err := expand(match, imported)
				if err != nil {
					return nil, err
				}
				out.Write(expanded)
				out.WriteByte('\n')
			}
			cursor = arg.end
		}
		out.Write(data[cursor:])
		return out.Bytes(), nil
	}
	candidate, err := expand(topPath, top)
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	return candidate, manifest, err
}

func verifyInputManifest(manifest inputManifest) error {
	for _, record := range manifest.Files {
		data, err := readConfigInput(record.Path)
		if err != nil {
			return err
		}
		current, err := inputRecord(record.Path, data)
		if err != nil {
			return err
		}
		if current != record {
			return fmt.Errorf("the Caddy input changed: %s; review and reconcile with setup before changing routes", record.Path)
		}
	}
	for _, glob := range manifest.Globs {
		current, err := importMatches(glob.Pattern)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, glob.Matches) {
			return fmt.Errorf("the Caddy import membership changed: %s; reconcile with setup", glob.Pattern)
		}
	}
	return nil
}

func checkInstalledAdapted(data []byte, c config, admin string) error {
	if err := validateInstalledPorts(c); err != nil {
		return err
	}
	if err := c.validate(); err != nil {
		return err
	}
	var doc struct {
		Admin struct {
			Listen   string `json:"listen"`
			Disabled bool   `json:"disabled"`
		} `json:"admin"`
		Storage json.RawMessage `json:"storage"`
		Apps    struct {
			HTTP struct {
				HTTPPort  int `json:"http_port"`
				HTTPSPort int `json:"https_port"`
				Servers   map[string]struct {
					Listen    []string        `json:"listen"`
					Routes    json.RawMessage `json:"routes"`
					AutoHTTPS struct {
						Disabled            bool `json:"disable"`
						DisableCertificates bool `json:"disable_certificates"`
					} `json:"automatic_https"`
				} `json:"servers"`
			} `json:"http"`
			PKI struct {
				CAs map[string]struct {
					Name string `json:"name"`
				} `json:"certificate_authorities"`
			} `json:"pki"`
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
		return fmt.Errorf("decode adapted Caddy configuration: %w", err)
	}
	if doc.Admin.Disabled || doc.Admin.Listen != admin+"|"+installedSocketMode {
		return errors.New("the Caddy admin conflicts with Sandbar's private endpoint")
	}
	if len(doc.Storage) > 0 && string(doc.Storage) != "null" {
		return errors.New("custom Caddy storage requires manual integration")
	}
	httpPort, httpsPort := doc.Apps.HTTP.HTTPPort, doc.Apps.HTTP.HTTPSPort
	if httpPort == 0 {
		httpPort = 80
	}
	if httpsPort == 0 {
		httpsPort = 443
	}
	if httpPort != c.HTTPPort || httpsPort != c.HTTPSPort {
		return fmt.Errorf("the Caddy global HTTP/HTTPS ports conflict with installed Sandbar ports %d/%d; review the shared Caddy configuration", c.HTTPPort, c.HTTPSPort)
	}
	ca, ok := doc.Apps.PKI.CAs["sandbar"]
	if !ok || ca.Name != "sandbar local CA" {
		return errors.New("the Caddy CA sandbar conflicts with Sandbar's dedicated CA")
	}
	hosts := map[string]bool{"sandbar.localhost": true}
	for _, r := range c.Routes {
		hosts[r.Hostname] = true
	}
	hostCounts := map[string]int{}
	for name, server := range doc.Apps.HTTP.Servers {
		var names []string
		if err := collectCaddyHosts(server.Routes, &names); err != nil {
			return err
		}
		relevant := false
		for _, listen := range server.Listen {
			host, port, err := net.SplitHostPort(listen)
			if err != nil {
				return fmt.Errorf("unsupported Caddy listener %q", listen)
			}
			if port != strconv.Itoa(c.HTTPPort) && port != strconv.Itoa(c.HTTPSPort) {
				continue
			}
			relevant = true
			ip := net.ParseIP(host)
			if host == "" || ip != nil && ip.IsUnspecified() {
				return fmt.Errorf("the Caddy server %s has a wildcard listener %s conflicting with Sandbar loopback sites", name, listen)
			}
		}
		for _, host := range names {
			if hosts[host] {
				for _, listen := range server.Listen {
					_, port, _ := net.SplitHostPort(listen)
					if port == strconv.Itoa(c.HTTPSPort) && (server.AutoHTTPS.Disabled || server.AutoHTTPS.DisableCertificates) {
						return fmt.Errorf("the Caddy automatic certificate settings prevent Sandbar HTTPS for %s", host)
					}
				}
				hostCounts[host]++
				for _, listen := range server.Listen {
					h, _, err := net.SplitHostPort(listen)
					ip := net.ParseIP(h)
					if err != nil || ip == nil || !ip.IsLoopback() {
						return fmt.Errorf("the Sandbar hostname %s is exposed on %s", host, listen)
					}
				}
			} else if relevant {
				for owned := range hosts {
					if caddyHostMatches(host, owned) {
						return fmt.Errorf("the Caddy hostname %s overlaps Sandbar hostname %s", host, owned)
					}
				}
			}
		}
	}
	for host := range hosts {
		if hostCounts[host] != 2 {
			return fmt.Errorf("the Caddy hostname %s has conflicting or missing HTTP/HTTPS routes", host)
		}
		found := false
		for _, policy := range doc.Apps.TLS.Automation.Policies {
			for _, subject := range policy.Subjects {
				if subject == host {
					found = true
					if len(policy.Issuers) != 1 || policy.Issuers[0].Module != "internal" || policy.Issuers[0].CA != "sandbar" {
						return fmt.Errorf("the Caddy hostname %s does not use the Sandbar CA", host)
					}
				}
			}
		}
		if !found {
			return fmt.Errorf("the Caddy hostname %s has no Sandbar certificate policy", host)
		}
	}
	return nil
}

func collectCaddyHosts(raw json.RawMessage, hosts *[]string) error {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for key, item := range v {
				if key == "host" {
					if list, ok := item.([]any); ok {
						for _, h := range list {
							if h, ok := h.(string); ok {
								*hosts = append(*hosts, h)
							}
						}
					}
				} else {
					walk(item)
				}
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(value)
	return nil
}

func caddyHostMatches(pattern, host string) bool {
	if pattern == "*" || pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return false
}

// Service and validation processes can have different working directories.
// Require absolute resource paths so both processes read the same resources.
func checkCaddyInputPaths(path string, tokens []caddyToken) error {
	for n, token := range tokens {
		if n > 0 && tokens[n-1].line == token.line && tokens[n-1].text != "{" {
			continue
		}
		if token.depth == 0 && strings.HasPrefix(token.text, "(") {
			return fmt.Errorf("the Caddy snippets require manual integration: %s", path)
		}
		var args []string
		for j := n + 1; j < len(tokens) && tokens[j].line == token.line; j++ {
			if tokens[j].text == "{" || tokens[j].text == "}" {
				break
			}
			args = append(args, tokens[j].text)
		}
		var resources []string
		switch token.text {
		case "root":
			if len(args) > 0 {
				resources = args[len(args)-1:]
			}
		case "tls":
			if len(args) == 2 {
				resources = args
			}
		case "cert", "key", "load", "ca_root", "acme_ca_root":
			resources = args
		case "output":
			if len(args) > 1 && args[0] == "file" {
				resources = args[1:2]
			}
		}
		for _, resource := range resources {
			if !filepath.IsAbs(resource) {
				return fmt.Errorf("the Caddy input %s uses relative resource path %q; use an absolute path before setup", path, resource)
			}
		}
	}
	return nil
}

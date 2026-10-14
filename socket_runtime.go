package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type socketPlan struct {
	HTTPPort  int  `json:"http_port"`
	HTTPSPort int  `json:"https_port"`
	IPv6      bool `json:"ipv6"`
}

func (p socketPlan) validate() error {
	c := config{Version: 2, HTTPPort: p.HTTPPort, HTTPSPort: p.HTTPSPort}
	return c.validate()
}

// Convert only the selected physical sockets. All route handlers remain intact.
func convertSocketRuntime(data []byte, plan socketPlan) ([]byte, error) {
	if err := plan.validate(); err != nil {
		return nil, err
	}
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	apps, _ := doc["apps"].(map[string]any)
	http, _ := apps["http"].(map[string]any)
	servers, _ := http["servers"].(map[string]any)
	ownedHosts := map[string]bool{"sandbar.localhost": true}
	tls, _ := apps["tls"].(map[string]any)
	automation, _ := tls["automation"].(map[string]any)
	policies, _ := automation["policies"].([]any)
	for _, value := range policies {
		policy, _ := value.(map[string]any)
		issuers, _ := policy["issuers"].([]any)
		if len(issuers) != 1 {
			continue
		}
		issuer, _ := issuers[0].(map[string]any)
		if issuer["module"] != "internal" || issuer["ca"] != "sandbar" {
			continue
		}
		subjects, _ := policy["subjects"].([]any)
		for _, value := range subjects {
			host, _ := value.(string)
			ownedHosts[host] = true
		}
	}
	for name, value := range servers {
		server, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid Caddy server %s", name)
		}
		listeners, _ := server["listen"].([]any)
		byListener, _ := server["listen_protocols"].([]any)
		if len(byListener) > 0 && len(byListener) != len(listeners) {
			return nil, fmt.Errorf("server %s has mismatched listener protocols", name)
		}
		var converted []any
		var selections []any
		touched := false
		for n, value := range listeners {
			address, ok := value.(string)
			if !ok {
				return nil, errors.New("invalid Caddy listener")
			}
			if strings.HasPrefix(address, "fd/") || strings.HasPrefix(address, "fdgram/") {
				return nil, fmt.Errorf("unowned Caddy descriptor listener %s", address)
			}
			host, portText, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("unsupported Caddy listener %s", address)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				return nil, err
			}
			selected, err := socketListenerProtocols(server, n)
			if err != nil {
				return nil, err
			}
			if port != plan.HTTPPort && port != plan.HTTPSPort {
				converted = append(converted, address)
				selections = append(selections, selected)
				continue
			}
			ip := net.ParseIP(host)
			if host == "" || ip != nil && ip.IsUnspecified() {
				return nil, fmt.Errorf("the Caddy listener %s conflicts with launchd loopback sockets", address)
			}
			if ip == nil {
				return nil, fmt.Errorf("unsupported Caddy listener %s", address)
			}
			if !ip.Equal(net.ParseIP("127.0.0.1")) && !ip.Equal(net.IPv6loopback) {
				converted = append(converted, address)
				selections = append(selections, selected)
				continue
			}
			slot := 100
			if port == plan.HTTPSPort {
				slot = 102
			}
			if ip.To4() == nil {
				if !plan.IPv6 {
					return nil, fmt.Errorf("the Caddy listener %s is absent from the saved IPv4-only socket plan", address)
				}
				slot++
			}
			var tcp []string
			h3 := false
			for _, protocol := range selected {
				if protocol == "h3" {
					h3 = true
				} else {
					tcp = append(tcp, protocol)
				}
			}
			if len(tcp) > 0 {
				converted = append(converted, fmt.Sprintf("fd/%d", slot))
				selections = append(selections, tcp)
			}
			if h3 && port == plan.HTTPSPort {
				converted = append(converted, fmt.Sprintf("fdgram/%d", slot+2))
				selections = append(selections, []string{"h3"})
			}
			if len(tcp) == 0 && !(h3 && port == plan.HTTPSPort) {
				return nil, fmt.Errorf("the Caddy listener %s has no supported protocol", address)
			}
			touched = true
		}
		// Automatic redirects create numeric HTTP listeners during provisioning.
		// Every TLS hostname on an inherited socket needs an explicit redirect.
		auto, _ := server["automatic_https"].(map[string]any)
		redirectsDisabled := auto["disable_redirects"] == true || auto["disable"] == true
		httpOnly := len(listeners) > 0
		for _, value := range listeners {
			address, _ := value.(string)
			_, port, err := net.SplitHostPort(address)
			if err != nil || port != strconv.Itoa(plan.HTTPPort) {
				httpOnly = false
			}
		}
		tlsEnabled := server["tls_connection_policies"] != nil || !httpOnly
		redirectConflict := false
		for _, value := range listeners {
			address, _ := value.(string)
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				continue
			}
			ip := net.ParseIP(host)
			if host == "" || (ip != nil && (ip.IsUnspecified() || ip.Equal(net.ParseIP("127.0.0.1")) || plan.IPv6 && ip.Equal(net.IPv6loopback))) {
				redirectConflict = true
			}
		}
		if tlsEnabled && !redirectsDisabled && redirectConflict {
			var hosts []string
			raw, _ := json.Marshal(server["routes"])
			if err := collectCaddyHosts(raw, &hosts); err != nil {
				return nil, err
			}
			skipped := map[string]bool{}
			if list, ok := auto["skip"].([]any); ok {
				for _, value := range list {
					host, _ := value.(string)
					skipped[host] = true
				}
			}
			for _, host := range hosts {
				if !ownedHosts[host] && !skipped[host] {
					return nil, fmt.Errorf("the Caddy site %s needs automatic redirects conflicting with launchd sockets; configure explicit compatible redirects", host)
				}
			}
		}
		if touched {
			server["listen"] = converted
			server["listen_protocols"] = selections
			if auto == nil {
				auto = map[string]any{}
			}
			auto["disable_redirects"] = true
			if httpOnly {
				// Caddy derives this from numeric HTTP listeners. FDs lose the port.
				auto["disable"] = true
			}
			server["automatic_https"] = auto
		}
	}
	return json.Marshal(doc)
}

func installedSocketRuntime(p paths, data []byte, c config) ([]byte, error) {
	if p.installed == nil || p.installed.ID != "sandbar-launchd-v1" {
		return data, nil
	}
	record, err := readSetupRecord(p)
	if err != nil {
		return nil, err
	}
	if record.SocketPlan == nil {
		return nil, errors.New("missing launchd socket plan; run sandbar setup")
	}
	if c.HTTPPort != record.SocketPlan.HTTPPort || c.HTTPSPort != record.SocketPlan.HTTPSPort {
		return nil, errors.New("source ports differ from launchd sockets; run sandbar setup to change ports")
	}
	return convertSocketRuntime(data, *record.SocketPlan)
}

// Mirror Caddy's server defaults and the empty-string listener default marker.
func socketListenerProtocols(server map[string]any, index int) ([]string, error) {
	defaults := []string{"h1", "h2", "h3"}
	if list, ok := server["protocols"].([]any); ok && len(list) > 0 {
		defaults = nil
		for _, value := range list {
			protocol, ok := value.(string)
			if !ok {
				return nil, errors.New("invalid Caddy protocol")
			}
			defaults = append(defaults, protocol)
		}
	}
	listeners, _ := server["listen_protocols"].([]any)
	if len(listeners) == 0 || listeners[index] == nil {
		return defaults, nil
	}
	list, ok := listeners[index].([]any)
	if !ok {
		return nil, errors.New("invalid listener protocols")
	}
	if len(list) == 0 {
		return defaults, nil
	}
	var selected []string
	includeDefaults := false
	for _, value := range list {
		protocol, ok := value.(string)
		if !ok {
			return nil, errors.New("invalid listener protocol")
		}
		if protocol == "" {
			includeDefaults = true
		} else {
			selected = append(selected, protocol)
		}
	}
	if includeDefaults {
		for _, protocol := range defaults {
			found := false
			for _, explicit := range selected {
				if explicit == protocol {
					found = true
					break
				}
			}
			if !found {
				selected = append(selected, protocol)
			}
		}
	}
	return selected, nil
}

package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

const teleportCertificatePath = "/.sandbar/teleport-certificate"

// Setup configures this fixed endpoint before a destination is added.
// Destination changes then use the existing route-only transaction.
func renderTeleportGlobals(c config) string {
	if c.Version != 3 {
		return ""
	}
	return fmt.Sprintf("on_demand_tls {\n\task %s\n}\n", teleportPermissionEndpoint(c))
}

func teleportNamespacePattern(machine string) string {
	label := `[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?`
	return `(?i)^(` + label + `\.)*sandbar-` + machine + `\.localhost$`
}

func teleportNamespaceExpression(value, machine string) string {
	// CEL string literals escape the pattern before RE2 reads it.
	pattern := strings.ReplaceAll(teleportNamespacePattern(machine), `\`, `\\`)
	return fmt.Sprintf("%s.size() <= 253 && %s.matches('%s')", value, value, pattern)
}

func renderTeleportHTTPHandlers(c config) string {
	if c.Version != 3 {
		return ""
	}
	var b strings.Builder
	var permitted []string
	for _, destination := range c.Teleports {
		permitted = append(permitted, "("+teleportNamespaceExpression("{query.domain}", destination.Machine)+")")
	}
	if len(permitted) > 0 {
		fmt.Fprintf(&b, "\t@teleport_certificate {\n\t\thost 127.0.0.1\n\t\tpath %s\n\t\texpression `%s`\n\t}\n\trespond @teleport_certificate 204\n", teleportCertificatePath, strings.Join(permitted, " || "))
	}
	for i, destination := range c.Teleports {
		fmt.Fprintf(&b, "\t@teleport_redirect_%d expression `%s`\n\tredir @teleport_redirect_%d %s{uri} 308\n", i, teleportNamespaceExpression("{host}", destination.Machine), i, c.routeURL("{host}"))
	}
	return b.String()
}

func renderTeleportHTTPSRoutes(c config, bind, caID string) string {
	if len(c.Teleports) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "https://:%d {\n\tbind %s\n\ttls {\n\t\tissuer internal {\n\t\t\tca %s\n\t\t}\n\t\ton_demand\n\t}\n", c.HTTPSPort, bind, caID)
	for i, destination := range c.Teleports {
		block, _ := pem.Decode([]byte(destination.RootPEM)) // Configuration validation requires a public CA certificate.
		fmt.Fprintf(&b, `	@teleport_%d expression %s
	handle @teleport_%d {
		reverse_proxy https://127.0.0.1:%d {
			header_up Host {hostport}
			transport http {
				tls_server_name %s
				tls_trust_pool inline {
					trust_der %s
				}
			}
		}
	}
`, i, "`"+teleportNamespaceExpression("{host}", destination.Machine)+"`", i, destination.LocalPort, machineHostname(destination.Machine), base64.StdEncoding.EncodeToString(block.Bytes))
	}
	b.WriteString("\thandle {\n\t\trespond 404\n\t}\n}\n\n")
	return b.String()
}

func teleportPermissionEndpoint(c config) string {
	return "http://127.0.0.1:" + strconv.Itoa(c.HTTPPort) + teleportCertificatePath
}

// A shared Caddy configuration must retain the fixed permission endpoint and
// each unrelated site's certificate policy when the fallback policy is added.
func checkTeleportAdapted(data []byte, c config, caID string) error {
	if c.Version != 3 {
		return nil
	}
	var doc struct {
		Apps struct {
			TLS struct {
				Automation struct {
					OnDemand map[string]any `json:"on_demand"`
					Policies []struct {
						Subjects []string `json:"subjects"`
						OnDemand bool     `json:"on_demand"`
						Issuers  []struct {
							Module string `json:"module"`
							CA     string `json:"ca"`
						} `json:"issuers"`
					} `json:"policies"`
				} `json:"automation"`
			} `json:"tls"`
			HTTP struct {
				Servers map[string]struct {
					Routes json.RawMessage `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	expected := map[string]any{"permission": map[string]any{"module": "http", "endpoint": teleportPermissionEndpoint(c)}}
	if !reflect.DeepEqual(doc.Apps.TLS.Automation.OnDemand, expected) {
		return errors.New("the Caddy on-demand TLS settings conflict with Sandbar's certificate permission endpoint")
	}
	count := 0
	for _, policy := range doc.Apps.TLS.Automation.Policies {
		if !policy.OnDemand {
			continue
		}
		if len(c.Teleports) == 0 || len(policy.Subjects) != 0 || len(policy.Issuers) != 1 || policy.Issuers[0].Module != "internal" || policy.Issuers[0].CA != caID {
			return errors.New("the Caddy on-demand certificate policy conflicts with Sandbar Teleport")
		}
		count++
	}
	if len(c.Teleports) > 0 && count != 1 {
		return errors.New("missing Sandbar Teleport certificate policy")
	}
	for _, server := range doc.Apps.HTTP.Servers {
		var hosts []string
		if err := collectCaddyHosts(server.Routes, &hosts); err != nil {
			return err
		}
		for _, destination := range c.Teleports {
			pattern := regexp.MustCompile(teleportNamespacePattern(destination.Machine))
			for _, host := range hosts {
				if pattern.MatchString(host) || caddyHostMatches(host, machineHostname(destination.Machine)) || caddyHostMatches(host, "app."+machineHostname(destination.Machine)) {
					return fmt.Errorf("the Caddy hostname %s overlaps Teleport destination %s", host, destination.Machine)
				}
			}
		}
	}
	return nil
}

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func socketRuntimeDocument(servers map[string]any) []byte {
	data, _ := json.Marshal(map[string]any{"apps": map[string]any{"http": map[string]any{"servers": servers}}})
	return data
}
func TestSocketRuntimeListenersAndProtocols(t *testing.T) {
	for _, test := range []struct {
		name      string
		ipv6      bool
		protocols []string
		want      []string
	}{{"IPv4", false, nil, []string{"fd/102", "fdgram/104"}}, {"IPv6", true, nil, []string{"fd/102", "fdgram/104", "fd/103", "fdgram/105"}}, {"restricted", false, []string{"h2"}, []string{"fd/102"}}, {"HTTP3", false, []string{"h3"}, []string{"fdgram/104"}}} {
		t.Run(test.name, func(t *testing.T) {
			listeners := []string{"127.0.0.1:18443"}
			if test.ipv6 {
				listeners = append(listeners, "[::1]:18443")
			}
			server := map[string]any{"listen": listeners, "tls_connection_policies": []any{map[string]any{}}, "routes": []any{map[string]any{"match": []any{map[string]any{"host": []string{"sandbar.localhost"}}}}}}
			if test.protocols != nil {
				server["protocols"] = test.protocols
			}
			output, err := convertSocketRuntime(socketRuntimeDocument(map[string]any{"https": server}), socketPlan{18080, 18443, test.ipv6})
			if err != nil {
				t.Fatal(err)
			}
			var doc struct {
				Apps struct {
					HTTP struct {
						Servers map[string]struct {
							Listen    []string        `json:"listen"`
							Protocols [][]string      `json:"listen_protocols"`
							Auto      map[string]bool `json:"automatic_https"`
						} `json:"servers"`
					} `json:"http"`
				} `json:"apps"`
			}
			if err := json.Unmarshal(output, &doc); err != nil {
				t.Fatal(err)
			}
			got := doc.Apps.HTTP.Servers["https"]
			if strings.Join(got.Listen, ",") != strings.Join(test.want, ",") {
				t.Fatalf("listeners %v, want %v", got.Listen, test.want)
			}
			if got.Auto["disable"] || !got.Auto["disable_redirects"] {
				t.Fatal(got.Auto)
			}
			for n, address := range got.Listen {
				for _, protocol := range got.Protocols[n] {
					if strings.HasPrefix(address, "fdgram/") != (protocol == "h3") {
						t.Fatalf("mismatched %s %v", address, got.Protocols[n])
					}
				}
			}
		})
	}
}
func TestSocketRuntimePreservesHTTPAndIndependentSites(t *testing.T) {
	http := map[string]any{"listen": []string{"127.0.0.1:18080"}, "routes": []any{map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 308, "headers": map[string]any{"Location": []string{"https://sandbar.localhost:18443{http.request.uri}"}}}}}}}
	independent := map[string]any{"listen": []string{"127.0.0.2:19090"}, "tls_connection_policies": []any{map[string]any{}}, "routes": []any{map[string]any{"match": []any{map[string]any{"host": []string{"independent.localhost"}}}}}}
	data, err := convertSocketRuntime(socketRuntimeDocument(map[string]any{"http": http, "independent": independent}), socketPlan{18080, 18443, false})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	servers := doc["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	actual, _ := json.Marshal(servers["independent"])
	want, _ := json.Marshal(independent)
	if !jsonEqual(actual, want) {
		t.Fatalf("independent changed: %s", actual)
	}
	converted := servers["http"].(map[string]any)
	if converted["automatic_https"].(map[string]any)["disable"] != true {
		t.Fatal("HTTP descriptor must remain cleartext")
	}
	routes, _ := json.Marshal(converted["routes"])
	want, _ = json.Marshal(http["routes"])
	if !jsonEqual(routes, want) {
		t.Fatal("redirect routes changed")
	}
}
func TestSocketRuntimeRejectsOwnershipConflicts(t *testing.T) {
	for _, address := range []string{":18443", "0.0.0.0:18080", "[::1]:18443", "fd/102", "fdgram/104"} {
		_, err := convertSocketRuntime(socketRuntimeDocument(map[string]any{"server": map[string]any{"listen": []string{address}}}), socketPlan{18080, 18443, false})
		if err == nil {
			t.Fatalf("accepted %s", address)
		}
	}
	server := map[string]any{"listen": []string{"127.0.0.1:19090"}, "tls_connection_policies": []any{map[string]any{}}, "routes": []any{map[string]any{"match": []any{map[string]any{"host": []string{"unrelated.localhost"}}}}}}
	_, err := convertSocketRuntime(socketRuntimeDocument(map[string]any{"independent": server}), socketPlan{18080, 18443, false})
	if err == nil || !strings.Contains(err.Error(), "unrelated.localhost") {
		t.Fatal(err)
	}
}
func TestSocketRuntimeListenerProtocolDefaults(t *testing.T) {
	for _, protocols := range []any{nil, []any{}, []any{""}, []any{"h2", ""}} {
		server := map[string]any{"listen": []string{"127.0.0.1:18443"}, "protocols": []string{"h2", "h3"}, "listen_protocols": []any{protocols}}
		output, err := convertSocketRuntime(socketRuntimeDocument(map[string]any{"server": server}), socketPlan{18080, 18443, false})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(output), "fdgram/104") {
			t.Fatalf("lost default HTTP/3: %s", output)
		}
	}
}

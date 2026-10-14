package main

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"
)

func TestDarwinTeleportSetupUpgrade(t *testing.T) {
	p, service := darwinSetupFixture(t)
	var diagnostic bytes.Buffer
	if err := setupDarwin(p, setupOptions{Machine: "saved"}, io.Discard, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	root := readTestFile(t, p.rootCertificate())
	legacy := config{Version: 2, HTTPPort: 80, HTTPSPort: 443, Routes: []route{{"kept.sandbar.localhost", "8000"}}}
	source := mustConfigBytes(t, legacy)
	if err := p.writeFile(p.config, source); err != nil {
		t.Fatal(err)
	}
	generated := readTestFile(t, p.generatedPath())
	if err := setupDarwin(p, setupOptions{Machine: "saved"}, io.Discard, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	c, err := readConfig(p.config)
	if err != nil || c.Version != 3 || c.Machine != "saved" || len(c.Routes) != 1 {
		t.Fatalf("%+v %v", c, err)
	}
	matched := false
	backups, err := filepath.Glob(p.file("backups/setup-*/backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range backups {
		var backup setupUndo
		if err := json.Unmarshal(readTestFile(t, path), &backup); err != nil {
			t.Fatal(err)
		}
		hasSource, hasGenerated := false, false
		for _, file := range backup.Files {
			if file.Path == p.config && bytes.Equal(file.Data, source) {
				hasSource = true
			}
			if file.Path == p.generatedPath() && bytes.Equal(file.Data, generated) {
				hasGenerated = true
			}
		}
		matched = matched || hasSource && hasGenerated
	}
	if !matched {
		t.Fatal("setup backup lacks matched pre-upgrade source and generated files")
	}
	accepted := readTestFile(t, p.config)
	actions := len(service.Actions)
	if err := setupDarwin(p, setupOptions{Machine: "renamed"}, io.Discard, &diagnostic, setupFixtureVerified); err == nil {
		t.Fatal("changed established identity")
	}
	if len(service.Actions) != actions || !bytes.Equal(accepted, readTestFile(t, p.config)) || !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("identity conflict changed setup or CA")
	}
	if err := setupDarwin(p, setupOptions{}, io.Discard, &diagnostic, setupFixtureVerified); err != nil {
		t.Fatal(err, diagnostic.String())
	}
	c, err = readConfig(p.config)
	if err != nil || c.Machine != "saved" {
		t.Fatal(c, err)
	}
	if !bytes.Equal(root, readTestFile(t, p.rootCertificate())) {
		t.Fatal("repeat rotated CA")
	}
}

//go:build linux

package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestLinuxSetupApplyRefusesPendingRecoveryBeforePrivileges(t *testing.T) {
	for _, kind := range []string{"valid", "malformed", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			p, service := testInstalledPaths(t)
			tx := testTransaction(t, p, "prepared", false)
			if err := prepareTransaction(p, &tx); err != nil {
				t.Fatal(err)
			}
			tx.Phase = "loading"
			if err := saveTransaction(p, tx); err != nil {
				t.Fatal(err)
			}
			if err := checkTransactionFiles(p, tx); err != nil {
				t.Fatal("fixture must have valid installed recovery", err)
			}
			if kind == "malformed" {
				if err := os.WriteFile(p.file("transaction/journal.json"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			journal := readTestFile(t, p.file("transaction/journal.json"))
			source := readTestFile(t, p.config)
			routes := readTestFile(t, p.generatedPath())
			state := service.State
			if kind == "unreadable" {
				if err := os.Chmod(p.file("transaction"), 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p.file("transaction"), 0700) })
			}
			// A nil account also makes any accidental continuation into privileged setup fail this test.
			err := applySetup(p, setupOptions{}, nil, nil, nil, nil, installedComposition{}, nil, state, nil, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), p.file("transaction")) {
				t.Fatal("setup did not refuse before privileged changes", err)
			}
			if kind == "unreadable" {
				info, err := os.Lstat(p.file("transaction"))
				if err != nil || info.Mode().Perm() != 0 {
					t.Fatal("setup changed transaction permissions", info, err)
				}
				if err := os.Chmod(p.file("transaction"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(journal, readTestFile(t, p.file("transaction/journal.json"))) || !bytes.Equal(source, readTestFile(t, p.config)) || !bytes.Equal(routes, readTestFile(t, p.generatedPath())) || len(service.Actions) != 0 || service.State != state {
				t.Fatal("setup changed pending installation", service.Actions)
			}
		})
	}
}

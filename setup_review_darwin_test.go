package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDarwinSetupPreservesPendingRecovery(t *testing.T) {
	for _, kind := range []string{"valid", "malformed", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			p, service := darwinSetupFixture(t)
			if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, io.Discard, setupFixtureVerified); err != nil {
				t.Fatal(err)
			}
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
			before := setupReviewFiles(t, p)
			backups, err := filepath.Glob(p.file("backups/setup-*"))
			if err != nil {
				t.Fatal(err)
			}
			actions := len(service.Actions)
			state := service.State
			if kind == "unreadable" {
				if err := os.Chmod(p.file("transaction"), 0000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p.file("transaction"), 0700) })
			}
			port := 8443
			for _, check := range []bool{true, false} {
				err := setupDarwin(p, setupOptions{Check: check, HTTPSPort: &port}, io.Discard, io.Discard, setupFixtureVerified)
				if err == nil || !strings.Contains(err.Error(), p.file("transaction")) {
					t.Fatal("setup accepted pending recovery", check, err)
				}
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
			afterBackups, err := filepath.Glob(p.file("backups/setup-*"))
			if err != nil || !reflect.DeepEqual(backups, afterBackups) || !reflect.DeepEqual(before, setupReviewFiles(t, p)) || len(service.Actions) != actions || service.State != state {
				t.Fatal("setup changed pending installation", service.Actions, err)
			}
		})
	}
}

func TestDarwinSetupRechecksRecoveryUnderLock(t *testing.T) {
	p, service := darwinSetupFixture(t)
	if err := setupDarwin(p, setupOptions{Machine: "fixture"}, io.Discard, io.Discard, setupFixtureVerified); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(p.file("router.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	beforeBackups, err := filepath.Glob(p.file("backups/setup-*/backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	before := setupReviewFiles(t, p)
	actions := len(service.Actions)
	state := service.State
	done := make(chan error, 1)
	port := 8443
	go func() {
		done <- setupDarwin(p, setupOptions{HTTPSPort: &port}, io.Discard, io.Discard, setupFixtureVerified)
	}()
	deadline := time.After(5 * time.Second)
	for {
		backups, err := filepath.Glob(p.file("backups/setup-*/backup.json"))
		if err != nil {
			t.Fatal(err)
		}
		if len(backups) > len(beforeBackups) {
			break
		}
		select {
		case err := <-done:
			t.Fatal("setup finished before acquiring lock", err)
		case <-deadline:
			t.Fatal("setup did not reach apply")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := os.Mkdir(p.file("transaction"), 0700); err != nil {
		t.Fatal(err)
	}
	journal := []byte("pending transaction created while setup waits")
	if err := os.WriteFile(p.file("transaction/journal.json"), journal, 0600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), p.file("transaction")) {
			t.Fatal("setup did not recheck pending recovery", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("setup did not leave lock")
	}
	delete(before, p.file("transaction/journal.json"))
	after := setupReviewFiles(t, p)
	delete(after, p.file("transaction/journal.json"))
	if !reflect.DeepEqual(before, after) || len(service.Actions) != actions || service.State != state || !bytes.Equal(readTestFile(t, p.file("transaction/journal.json")), journal) {
		t.Fatal("setup changed files or service after pending recovery appeared", service.Actions)
	}
}

type setupReviewSnapshot struct {
	Data     []byte
	Metadata *fileMetadata
}

func setupReviewFiles(t *testing.T, p paths) map[string]setupReviewSnapshot {
	t.Helper()
	result := map[string]setupReviewSnapshot{}
	for _, path := range []string{p.config, p.installed.Config, p.installed.Globals, p.generatedPath(), p.file("setup.json"), p.file("validation/Caddyfile"), p.rootCertificate(), p.file("transaction/journal.json")} {
		data, metadata, err := readSetupFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = setupReviewSnapshot{Data: data, Metadata: metadata}
	}
	return result
}

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func storedRoot(t *testing.T, p paths) string {
	t.Helper()
	root := p.file("caddy/pki/authorities/local/root.crt")
	if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sandbar local CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestTrustDelegation(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		t.Run(command, func(t *testing.T) {
			p := initialized(t)
			root := storedRoot(t, p)
			callsPath := fakeCaddy(t)
			for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
				t.Setenv(key, "/caller/"+key)
			}
			if err := os.WriteFile(p.config, []byte("invalid route JSON"), 0600); err != nil {
				t.Fatal(err)
			}
			keyPath := p.file("caddy/pki/authorities/local/root.key")
			if err := os.WriteFile(keyPath, []byte("test key placeholder"), 0600); err != nil {
				t.Fatal(err)
			}
			before := readTestFile(t, root)
			for range 2 {
				code, out, errOut := cli(t, "--home", filepath.Dir(p.config), command)
				if code != 0 || !strings.Contains(out, command+" output") || !strings.Contains(errOut, command+" diagnostic") {
					t.Fatalf("%d %s %s", code, out, errOut)
				}
				for _, text := range []string{root, "command completed", "Chrome", "browser guide"} {
					if !strings.Contains(out, text) {
						t.Fatal(out)
					}
				}
				if !strings.Contains(errOut, "elevated access") || !strings.Contains(errOut, root) || strings.Contains(out, "Chrome trusts") {
					t.Fatalf("%s %s", out, errOut)
				}
			}
			expected := []string{"untrust", "--cert", root}
			if command == "trust" {
				address, err := p.adminAddress()
				if err != nil {
					t.Fatal(err)
				}
				expected = []string{"trust", "--ca", "local", "--address", address}
			}
			if got := readCalls(t, callsPath); !reflect.DeepEqual(got, [][]string{{"version"}, expected, {"version"}, expected}) {
				t.Fatal(got)
			}
			wantEnv := "/caller/HOME\n/caller/XDG_CONFIG_HOME\n/caller/XDG_DATA_HOME\n/caller/XDG_STATE_HOME\n/caller/XDG_CACHE_HOME\n"
			if got := string(readTestFile(t, os.Getenv("FAKE_ENV"))); got != wantEnv {
				t.Fatalf("trust environment: %q", got)
			}
			if !bytes.Equal(before, readTestFile(t, root)) || string(readTestFile(t, keyPath)) != "test key placeholder" || string(readTestFile(t, p.config)) != "invalid route JSON" {
				t.Fatal("changed retained CA material or route configuration")
			}
			if _, err := os.Stat(p.file("Caddyfile")); !os.IsNotExist(err) {
				t.Fatal("generated a Caddyfile")
			}
		})
	}
}

func TestTrustForwardsInputAndFailures(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		t.Run(command, func(t *testing.T) {
			p := initialized(t)
			storedRoot(t, p)
			callsPath := fakeCaddy(t)
			t.Setenv("FAKE_READ_INPUT", "1")
			t.Setenv("FAKE_TRUST_EXIT", "29")
			t.Setenv("FAKE_DIAGNOSTIC", "permission denied after a store changed")
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			if _, err := writer.WriteString("confirmation\n"); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			original := os.Stdin
			os.Stdin = input
			t.Cleanup(func() { os.Stdin = original })
			code, out, errOut := cli(t, "--home", filepath.Dir(p.config), command)
			if code != 29 || !strings.Contains(out, "input: confirmation") || strings.Contains(out, "command completed") {
				t.Fatalf("%d %s %s", code, out, errOut)
			}
			for _, text := range []string{"permission denied after a store changed", "might already have changed", "documented removal steps", "exit status 29"} {
				if !strings.Contains(errOut, text) {
					t.Fatal(errOut)
				}
			}
			if command == "trust" && !strings.Contains(errOut, "selected Sandbar router to be running") {
				t.Fatal(errOut)
			}
			if len(readCalls(t, callsPath)) != 2 {
				t.Fatal("retried or started Caddy")
			}
		})
	}
}

func TestTrustHomeSelection(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		t.Run(command, func(t *testing.T) {
			envHome, flagHome := shortHome(t), shortHome(t)
			pEnv, pFlag := testPaths(t, envHome), testPaths(t, flagHome)
			rootEnv, rootFlag := storedRoot(t, pEnv), storedRoot(t, pFlag)
			beforeEnv, beforeFlag := readTestFile(t, rootEnv), readTestFile(t, rootFlag)
			if bytes.Equal(beforeEnv, beforeFlag) {
				t.Fatal("test roots must differ")
			}
			callsPath := fakeCaddy(t)
			t.Setenv("SANDBAR_HOME", envHome)
			for _, args := range [][]string{{command}, {"--home", flagHome, command}} {
				if code, _, errOut := cli(t, args...); code != 0 {
					t.Fatal(errOut)
				}
			}
			calls := readCalls(t, callsPath)
			for i, p := range []paths{pEnv, pFlag} {
				target := p.file("caddy/pki/authorities/local/root.crt")
				if command == "trust" {
					target = "unix/" + p.file("admin.sock")
				}
				if call := calls[2*i+1]; call[len(call)-1] != target {
					t.Fatal(call)
				}
			}
			if !bytes.Equal(beforeEnv, readTestFile(t, rootEnv)) || !bytes.Equal(beforeFlag, readTestFile(t, rootFlag)) {
				t.Fatal("changed another root with the same display name")
			}
		})
	}
}

func TestUnavailableRoot(t *testing.T) {
	for _, kind := range []string{"missing", "directory", "symlink loop"} {
		t.Run(kind, func(t *testing.T) {
			p := initialized(t)
			root := p.file("caddy/pki/authorities/local/root.crt")
			if kind != "missing" {
				if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "directory" {
					err = os.Mkdir(root, 0700)
				} else {
					err = os.Symlink("root.crt", root)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			callsPath := fakeCaddy(t)
			code, _, errOut := cli(t, "--home", filepath.Dir(p.config), "untrust")
			if code == 0 || !strings.Contains(errOut, "read selected root certificate "+root) {
				t.Fatalf("%d %s", code, errOut)
			}
			if _, err := os.Stat(callsPath); !os.IsNotExist(err) {
				t.Fatal("invoked Caddy for an unavailable root")
			}
		})
	}
}

func TestTrustRejectsExtraArguments(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		for _, argument := range []string{"extra", "--help", "--ca"} {
			callsPath := fakeCaddy(t)
			home := filepath.Join(shortHome(t), "absent")
			code, _, errOut := cli(t, "--home", home, command, argument)
			if code == 0 || !strings.Contains(errOut, command+" accepts no arguments") {
				t.Fatalf("%d %s", code, errOut)
			}
			for _, path := range []string{home, callsPath} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("extra argument caused work", path)
				}
			}
		}
	}
}

func TestTrustRequiresSupportedCaddy(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		for _, version := range []string{"v2.11.6", "v3.0.0", "missing", "exit"} {
			t.Run(command+"/"+version, func(t *testing.T) {
				p := initialized(t)
				storedRoot(t, p)
				callsPath := fakeCaddy(t)
				t.Setenv("FAKE_VERSION", version)
				if version == "missing" {
					t.Setenv("PATH", t.TempDir())
				}
				if version == "exit" {
					t.Setenv("FAKE_VERSION_EXIT", "17")
				}
				code, _, errOut := cli(t, "--home", filepath.Dir(p.config), command)
				if code == 0 || version == "exit" && code != 17 {
					t.Fatalf("%d %s", code, errOut)
				}
				if version != "missing" && !reflect.DeepEqual(readCalls(t, callsPath), [][]string{{"version"}}) {
					t.Fatal("attempted trust with unusable Caddy")
				}
			})
		}
	}
}

func TestTrustCommandsUseLock(t *testing.T) {
	for _, command := range []string{"trust", "untrust"} {
		t.Run(command, func(t *testing.T) {
			p := initialized(t)
			storedRoot(t, p)
			callsPath := fakeCaddy(t)
			err := withLock(p, func() error {
				done := make(chan int, 1)
				go func() {
					done <- run([]string{"--home", filepath.Dir(p.config), command}, &bytes.Buffer{}, &bytes.Buffer{})
				}()
				t.Cleanup(func() {
					select {
					case code := <-done:
						if code != 0 {
							t.Error("trust operation failed after lock released", code)
						}
					case <-time.After(time.Second):
						t.Error("trust operation did not finish after lock released")
					}
				})
				select {
				case code := <-done:
					return fmt.Errorf("operation ran while locked: %d", code)
				case <-time.After(40 * time.Millisecond):
				}
				if _, err := os.Stat(callsPath); !os.IsNotExist(err) {
					return fmt.Errorf("invoked Caddy while locked: %v", err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTrustHelp(t *testing.T) {
	_, out, _ := cli(t, "--help")
	for _, text := range []string{"[--home <directory>] trust", "[--home <directory>] untrust", "caller's trust stores", "elevated access", "does not verify browser trust", "complete removal"} {
		if !strings.Contains(out, text) {
			t.Fatal(out)
		}
	}
}

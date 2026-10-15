//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestUninstallLinuxCallerStages(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("caller stages require a non-root test user")
	}
	for _, stage := range []string{"preview", "preflight failure", "untrust failure", "apply failure", "success"} {
		t.Run(stage, func(t *testing.T) {
			p, _ := testInstalledPaths(t)
			calls := fakeCaddy(t)
			binary, err := exec.LookPath("caddy")
			if err != nil {
				t.Fatal(err)
			}
			p.installed.Binary = binary
			root := storedRoot(t, p)
			if err := os.WriteFile(p.rootCertificate(), readTestFile(t, root), 0600); err != nil {
				t.Fatal(err)
			}
			_, fingerprint, err := doctorRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			plan := uninstallPlan{Paths: p, Installation: *p.installed, OwnerUID: os.Getuid(), Fingerprint: fingerprint, Config: config{Version: 3, Machine: "fixture", HTTPPort: 80, HTTPSPort: 443}}
			t.Setenv("HOME", "/caller-home")
			for _, key := range []string{"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"} {
				t.Setenv(key, "")
			}
			t.Setenv("SSH_AUTH_SOCK", "")
			if stage == "untrust failure" {
				t.Setenv("FAKE_TRUST_EXIT", "29")
			}
			before := readTestFile(t, p.config)
			old := uninstallLinuxSudo
			t.Cleanup(func() { uninstallLinuxSudo = old })
			var sudoCalls [][]string
			uninstallLinuxSudo = func(executable string, out, errOut io.Writer, args ...string) error {
				if !filepath.IsAbs(executable) {
					t.Fatalf("relative elevation executable: %s", executable)
				}
				sudoCalls = append(sudoCalls, append([]string{}, args...))
				if err := checkUninstallSystemArgs(args); err != nil {
					t.Fatal(err)
				}
				if args[0] == "--preflight" {
					if stage == "preflight failure" {
						return errors.New("administrator declined")
					}
					return json.NewEncoder(out).Encode(&plan)
				}
				if args[1] != fingerprint || args[2] != uninstallPlanDigest(&plan) {
					t.Fatalf("changed identities: %v", args)
				}
				if string(readTestFile(t, os.Getenv("FAKE_ENV"))) != "/caller-home\n\n\n\n\n" {
					t.Fatal("untrust did not retain caller environment")
				}
				if stage == "apply failure" {
					return errors.New("cleanup authorization declined")
				}
				return nil
			}
			var out, errOut bytes.Buffer
			err = uninstallInstalled(stage == "preview", &out, &errOut)
			wantErr := strings.Contains(stage, "failure")
			if (err != nil) != wantErr {
				t.Fatalf("error=%v output=%s %s", err, out.String(), errOut.String())
			}
			wantSudo := 1
			if stage == "apply failure" || stage == "success" {
				wantSudo = 2
			}
			if len(sudoCalls) != wantSudo {
				t.Fatalf("sudo calls: %v", sudoCalls)
			}
			if stage == "preview" || stage == "preflight failure" {
				if _, err := os.Stat(calls); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("read-only stage invoked Caddy trust")
				}
			} else if got := readCalls(t, calls); !reflect.DeepEqual(got, [][]string{{"version"}, {"untrust", "--cert", p.rootCertificate()}}) {
				t.Fatal(got)
			}
			if !bytes.Equal(before, readTestFile(t, p.config)) || !bytes.Equal(readTestFile(t, root), readTestFile(t, p.rootCertificate())) {
				t.Fatal("caller stage changed configuration or CA files")
			}
		})
	}
}

func TestUninstallLinuxInternalArguments(t *testing.T) {
	for _, args := range [][]string{{"--preflight"}, {"--apply", strings.Repeat("AB", 32), strings.Repeat("ab", 32)}} {
		if err := checkUninstallSystemArgs(args); err != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{nil, {"--preflight", "/tmp/delete"}, {"--apply", "/etc", "/var"}, {"--apply", strings.Repeat("a", 64), strings.Repeat("z", 64)}, {"--apply", strings.Repeat("a", 64), strings.Repeat("b", 64), "/tmp"}} {
		if err := checkUninstallSystemArgs(args); err == nil {
			t.Fatal("accepted arbitrary internal targets", args)
		}
	}
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if _, err := uninstallSudoOwner(account.Uid, account.Username); err != nil {
			t.Fatal(err)
		}
		if err := uninstallSystem([]string{"--preflight"}, io.Discard, io.Discard); err == nil {
			t.Fatal("unprivileged internal preflight accepted")
		}
	}
	for _, uid := range []string{"", "0", "-1", "001", "not-a-uid"} {
		if _, err := uninstallSudoOwner(uid, account.Username); err == nil {
			t.Fatal("accepted ambiguous caller", uid)
		}
	}
	if _, err := uninstallSudoOwner(account.Uid, account.Username+"-other"); err == nil {
		t.Fatal("accepted another caller identity")
	}
}

func TestUninstallLinuxPoliciesPreserveConflicts(t *testing.T) {
	for _, conflict := range []string{"none", "contents", "mode", "owner", "symlink", "missing"} {
		t.Run(conflict, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sandbar-policy")
			policy := setupPolicy{path, []byte("owned policy\n"), 0644}
			if err := os.WriteFile(path, policy.data, policy.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, policy.mode); err != nil {
				t.Fatal(err)
			}
			owner := os.Getuid()
			switch conflict {
			case "contents":
				if err := os.WriteFile(path, []byte("external edits\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0666); err != nil {
					t.Fatal(err)
				}
			case "owner":
				owner++
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			err := checkUninstallLinuxPolicies([]setupPolicy{policy}, owner)
			if (err == nil) != (conflict == "none") {
				t.Fatalf("conflict=%s err=%v", conflict, err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("policy inspection changed files")
			}
		})
	}
}

func TestUninstallLinuxGroupBoundaries(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/sh\nmarkj:x:1001:1001:Mark:/home/markj:/bin/sh\ncaddy:x:999:999:Caddy:/var/lib/caddy:/bin/sh\n")
	good := []byte("sandbar:x:2000:markj,caddy\n")
	if err := checkUninstallLinuxGroup(good, passwd, 2000, "markj", "caddy"); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"sandbar:x:2001:markj,caddy\n", "sandbar:x:2000:markj,caddy,other\n", "sandbar:x:2000:caddy\n", "sandbar:x:2000:markj,caddy,caddy\n", "sandbar:x:2000:markj,caddy\nsandbar:x:2000:other\n"} {
		if err := checkUninstallLinuxGroup([]byte(group), passwd, 2000, "markj", "caddy"); err == nil {
			t.Fatal("accepted unrelated or ambiguous grants", group)
		}
	}
	for _, accounts := range []string{string(passwd) + "other:x:2001:2000:Other:/home/other:/bin/sh\n", strings.ReplaceAll(string(passwd), "caddy:x:999:999:", "caddy:x:999:2000:"), "markj:x:1001:1001:Mark:/home/markj:/bin/sh\n", "invalid passwd\n"} {
		if err := checkUninstallLinuxGroup(good, []byte(accounts), 2000, "markj", "caddy"); err == nil {
			t.Fatal("accepted primary or unknown group use", accounts)
		}
	}
}

func TestUninstallLinuxShutdownPreservesEvidence(t *testing.T) {
	for _, failure := range []string{"none", "stop", "disable", "show", "active", "enabled"} {
		t.Run(failure, func(t *testing.T) {
			p, _ := testInstalledPaths(t)
			root := storedRoot(t, p)
			before := readTestFile(t, p.config)
			rootBefore := readTestFile(t, root)
			plan := &uninstallPlan{Paths: p, Installation: *p.installed, OwnerUID: os.Getuid()}
			oldInspect := uninstallLinuxInspect
			t.Cleanup(func() { uninstallLinuxInspect = oldInspect })
			uninstallLinuxInspect = func() (*installation, error) { return p.installed, nil }
			old := uninstallLinuxOutput
			t.Cleanup(func() { uninstallLinuxOutput = old })
			var actions []string
			uninstallLinuxOutput = func(binary string, args ...string) ([]byte, error) {
				if binary != "/usr/bin/systemctl" {
					t.Fatalf("unexpected command %s", binary)
				}
				actions = append(actions, args[0])
				if args[0] == failure {
					return nil, errors.New("simulated service failure")
				}
				active, boot := "inactive", "disabled"
				if failure == "active" {
					active = "active"
				}
				if failure == "enabled" {
					boot = "enabled"
				}
				return []byte("LoadState=loaded\nActiveState=" + active + "\nUnitFileState=" + boot + "\n"), nil
			}
			err := uninstallPlatformStop(plan, io.Discard, io.Discard)
			if (err == nil) != (failure == "none") {
				t.Fatal(failure, err)
			}
			if !bytes.Equal(before, readTestFile(t, p.config)) || !bytes.Equal(rootBefore, readTestFile(t, root)) {
				t.Fatal("shutdown removed recovery evidence")
			}
			if failure == "stop" && fmt.Sprint(actions) != "[stop]" || failure == "disable" && fmt.Sprint(actions) != "[stop disable]" {
				t.Fatal(actions)
			}
		})
	}
}

func TestUninstallLinuxFinishGrantBoundaries(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"none", "daemon-reload", "extra member", "gpasswd", "groupdel"} {
		t.Run(failure, func(t *testing.T) {
			plan := &uninstallPlan{OwnerUID: os.Getuid(), Installation: installation{GroupID: 2000, Account: "caddy"}}
			old := uninstallLinuxOutput
			t.Cleanup(func() { uninstallLinuxOutput = old })
			var actions []string
			uninstallLinuxOutput = func(binary string, args ...string) ([]byte, error) {
				name := filepath.Base(binary)
				actions = append(actions, name+" "+strings.Join(args, " "))
				if failure == name || len(args) > 0 && failure == args[0] {
					return nil, errors.New("simulated grant failure")
				}
				if name == "getent" && args[0] == "group" {
					members := account.Username + ",caddy"
					if failure == "extra member" {
						members += ",other"
					}
					return []byte("sandbar:x:2000:" + members + "\n"), nil
				}
				if name == "getent" && args[0] == "passwd" {
					return []byte(account.Username + ":x:" + account.Uid + ":1001:Caller:/home/caller:/bin/sh\ncaddy:x:999:999:Caddy:/var/lib/caddy:/bin/sh\n"), nil
				}
				return nil, nil
			}
			err := uninstallPlatformFinish(plan, io.Discard, io.Discard)
			if (err == nil) != (failure == "none") {
				t.Fatal(failure, err, actions)
			}
			if failure == "none" {
				want := []string{"systemctl daemon-reload", "getent group sandbar", "getent passwd", "gpasswd -d " + account.Username + " sandbar", "gpasswd -d caddy sandbar", "groupdel sandbar"}
				if !reflect.DeepEqual(actions, want) {
					t.Fatal(actions)
				}
			}
			if failure == "extra member" && strings.Contains(strings.Join(actions, "\n"), "gpasswd") {
				t.Fatal("removed another user's access", actions)
			}
		})
	}
}

func TestUninstallLinuxBackupIdentity(t *testing.T) {
	p, _ := testInstalledPaths(t)
	root := t.TempDir()
	path := filepath.Join(root, "sandbar-setup-fixture")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	backup := setupUndo{Dir: path, Files: []setupBackup{{Path: p.config, Published: []byte("source")}}}
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "backup.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := findUninstallLinuxBackups(p, root, os.Getuid()); err != nil || !reflect.DeepEqual(got, []string{path}) {
		t.Fatal(got, err)
	}
	backup.Dir = filepath.Join(root, "another-installation")
	data, err = json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "backup.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := findUninstallLinuxBackups(p, root, os.Getuid()); err == nil {
		t.Fatal("accepted unverified backup identity")
	}
	if !bytes.Equal(data, readTestFile(t, filepath.Join(path, "backup.json"))) {
		t.Fatal("backup inspection changed evidence")
	}
}

func TestUninstallLinuxRepeatPreservesOrphanGrants(t *testing.T) {
	p, _ := testInstalledPaths(t)
	p.installed.ID = "apt-systemd-v1"
	p.installed.GroupID = 2000
	plan := &uninstallPlan{Paths: p, Installation: *p.installed, AlreadyRemoved: true}
	if err := uninstallPlatformPreflight(plan, os.Getuid()); err == nil || !strings.Contains(err.Error(), "group remains") {
		t.Fatal(err)
	}
	p.installed.GroupID = -1
	old := uninstallLinuxPolicies
	t.Cleanup(func() { uninstallLinuxPolicies = old })
	policy := filepath.Join(t.TempDir(), "policy")
	uninstallLinuxPolicies = func(paths) ([]setupPolicy, int) { return []setupPolicy{{policy, []byte("owned"), 0644}}, os.Getuid() }
	if err := uninstallPlatformPreflight(plan, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, []byte("external"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := uninstallPlatformPreflight(plan, os.Getuid()); err == nil {
		t.Fatal("orphan policy accepted as complete")
	}
	if string(readTestFile(t, policy)) != "external" {
		t.Fatal("orphan policy removed")
	}
}

// Privileged production inputs stay fixed. This fixture replaces only their
// inspection boundaries, then exercises the actual temporary-file cleanup.
func linuxUninstallFixture(t *testing.T) (paths, string, []setupPolicy, *[]string) {
	t.Helper()
	p, _ := testInstalledPaths(t)
	fakeCaddy(t)
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal(err)
	}
	p.installed.ID = "apt-systemd-v1"
	p.installed.Binary = binary
	p.installed.Account = "caddy"
	oldInspect := uninstallLinuxInspect
	t.Cleanup(func() { uninstallLinuxInspect = oldInspect })
	uninstallLinuxInspect = func() (*installation, error) { return p.installed, nil }
	cfg := config{Version: 3, Machine: "linux-fixture", HTTPPort: 80, HTTPSPort: 443, Routes: []route{}}
	source, err := configBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.writeFile(p.config, source); err != nil {
		t.Fatal(err)
	}
	address, err := p.adminAddress()
	if err != nil {
		t.Fatal(err)
	}
	globals := []byte(renderInstalledGlobals(cfg, address, "", ""))
	routes, err := renderInstalledRoutes(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	top := []byte("# retained header\n{\n}\n# retained footer\n")
	composition, err := composeInstalledConfig(p.installed.Config, top, p.installed.Globals, p.generatedPath(), globals, []byte(routes), false)
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{p.installed.Config: composition.Top, p.installed.Globals: globals, p.generatedPath(): []byte(routes), p.file("router.lock"): nil} {
		if err := os.WriteFile(path, data, 0660); err != nil {
			t.Fatal(err)
		}
	}
	_, manifest, err := stageInstalledCandidate(p.installed.Config, p.installed.Globals, p.generatedPath(), []byte(routes))
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(setupRecord{Identity: p.installed.identity(), Manifest: manifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("setup.json"), record, 0640); err != nil {
		t.Fatal(err)
	}
	publicRoot := storedRoot(t, testPaths(t, t.TempDir()))
	authority := filepath.Join(p.installed.Storage, "pki/authorities/sandbar")
	if err := os.MkdirAll(authority, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root.crt", "root.key", "intermediate.crt", "intermediate.key"} {
		data := []byte("fixture private material")
		if name == "root.crt" {
			data = readTestFile(t, publicRoot)
		}
		if err := os.WriteFile(filepath.Join(authority, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p.rootCertificate(), readTestFile(t, publicRoot), 0644); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(p.installed.Storage, "certificates/sandbar/obsolete.sandbar.localhost")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{"crt", "key", "json"} {
		if err := os.WriteFile(filepath.Join(leaf, "obsolete.sandbar.localhost."+ext), []byte("fixture leaf"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := filepath.Join(p.installed.Storage, "pki/authorities/other/keep")
	if err := os.MkdirAll(filepath.Dir(unrelated), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte("unrelated authority"), 0600); err != nil {
		t.Fatal(err)
	}
	backupRoot := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(backupRoot, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(backupRoot, "sandbar-setup-fixture")
	if err := os.Mkdir(backup, 0700); err != nil {
		t.Fatal(err)
	}
	undo := setupUndo{Dir: backup, Files: []setupBackup{{Path: p.config, Published: source}}}
	if err := undo.save(); err != nil {
		t.Fatal(err)
	}
	oldBackups := uninstallLinuxBackups
	t.Cleanup(func() { uninstallLinuxBackups = oldBackups })
	uninstallLinuxBackups = func(p paths) ([]string, error) { return findUninstallLinuxBackups(p, backupRoot, os.Getuid()) }
	policies := setupPolicies(address)
	policyDir := t.TempDir()
	for n := range policies {
		policies[n].path = filepath.Join(policyDir, fmt.Sprintf("policy-%d", n))
		if err := os.WriteFile(policies[n].path, policies[n].data, policies[n].mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(policies[n].path, policies[n].mode); err != nil {
			t.Fatal(err)
		}
	}
	oldPolicies := uninstallLinuxPolicies
	t.Cleanup(func() { uninstallLinuxPolicies = oldPolicies })
	uninstallLinuxPolicies = func(paths) ([]setupPolicy, int) { return policies, os.Getuid() }
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	oldOutput := uninstallLinuxOutput
	t.Cleanup(func() { uninstallLinuxOutput = oldOutput })
	var actions []string
	uninstallLinuxOutput = func(binary string, args ...string) ([]byte, error) {
		actions = append(actions, filepath.Base(binary)+" "+strings.Join(args, " "))
		if filepath.Base(binary) == "getent" && args[0] == "group" {
			return []byte(fmt.Sprintf("sandbar:x:%d:%s,caddy\n", p.installed.GroupID, account.Username)), nil
		}
		if filepath.Base(binary) == "getent" && args[0] == "passwd" {
			return []byte(fmt.Sprintf("%s:x:%s:99991:Caller:/home/caller:/bin/sh\ncaddy:x:999:99992:Caddy:/var/lib/caddy:/bin/sh\n", account.Username, account.Uid)), nil
		}
		if args[0] == "show" {
			return []byte("LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n"), nil
		}
		return nil, nil
	}
	return p, backup, policies, &actions
}

func TestUninstallLinuxFullCleanup(t *testing.T) {
	p, backup, policies, actions := linuxUninstallFixture(t)
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	before := readTestFile(t, p.installed.Config)
	if err := runUninstallUser(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.state, filepath.Dir(p.config), backup, filepath.Join(p.installed.Storage, "pki/authorities/sandbar"), filepath.Join(p.installed.Storage, "certificates/sandbar")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cleanup retained %s: %v", path, err)
		}
	}
	for _, policy := range policies {
		if _, err := os.Lstat(policy.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("retained policy", policy.path, err)
		}
	}
	stripped, err := stripUninstallMarkers(before, p.installed.Globals, p.generatedPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stripped, readTestFile(t, p.installed.Config)) {
		t.Fatal("changed bytes outside owned markers")
	}
	if string(readTestFile(t, filepath.Join(p.installed.Storage, "pki/authorities/other/keep"))) != "unrelated authority" {
		t.Fatal("changed another authority")
	}
	if !strings.Contains(strings.Join(*actions, "\n"), "systemctl stop fixture.service\nsystemctl disable fixture.service") {
		t.Fatal(*actions)
	}
	p.installed.GroupID = -1
	repeat, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil || !repeat.AlreadyRemoved {
		t.Fatal("repeat did not recognize complete removal", repeat, err)
	}
	if _, err := os.Lstat(p.state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("repeat recreated state", err)
	}
}

func TestUninstallLinuxFullFailureRetention(t *testing.T) {
	for _, failure := range []string{"untrust", "stop", "policy change", "new unknown file", "identity change", "reload", "groupdel"} {
		t.Run(failure, func(t *testing.T) {
			p, backup, policies, actions := linuxUninstallFixture(t)
			plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(p.installed.Storage, "pki/authorities/sandbar/root.crt")
			key := filepath.Join(filepath.Dir(root), "root.key")
			before := map[string][]byte{}
			for _, path := range []string{p.config, p.installed.Config, p.rootCertificate(), root, key, filepath.Join(backup, "backup.json"), p.file("setup.json")} {
				before[path] = readTestFile(t, path)
			}
			if failure == "untrust" {
				t.Setenv("FAKE_TRUST_EXIT", "29")
			}
			err = runUninstallUser(plan, io.Discard, io.Discard)
			if failure != "untrust" && err != nil {
				t.Fatal(err)
			}
			if failure == "untrust" && err == nil {
				t.Fatal("expected untrust failure")
			}
			if failure == "policy change" {
				if err := os.WriteFile(policies[0].path, []byte("external policy"), policies[0].mode); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "new unknown file" {
				if err := os.WriteFile(p.file("external-note"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "identity change" {
				inspect := uninstallLinuxInspect
				uninstallLinuxInspect = func() (*installation, error) {
					current, err := inspect()
					if err != nil {
						return nil, err
					}
					changed := *current
					changed.Unit = "unrelated.service"
					return &changed, nil
				}
			}
			command := uninstallLinuxOutput
			uninstallLinuxOutput = func(binary string, args ...string) ([]byte, error) {
				if args[0] == failure || filepath.Base(binary) == failure || failure == "reload" && args[0] == "daemon-reload" {
					return nil, errors.New("simulated cleanup failure")
				}
				return command(binary, args...)
			}
			if failure != "untrust" {
				err = finishUninstall(plan, io.Discard, io.Discard)
				if err == nil {
					t.Fatal("expected cleanup failure")
				}
			}
			for path, data := range before {
				if (failure == "reload" || failure == "groupdel") && path != p.file("setup.json") && path != filepath.Join(backup, "backup.json") {
					continue
				}
				if !bytes.Equal(data, readTestFile(t, path)) {
					t.Fatal("failure deleted or changed required evidence", path)
				}
			}
			if failure == "untrust" || failure == "policy change" || failure == "new unknown file" || failure == "identity change" {
				if strings.Contains(strings.Join(*actions, "\n"), "systemctl stop") {
					t.Fatal("conflict reached service mutation", *actions)
				}
			}
		})
	}
}

func TestIntegrationUninstallLinuxComposition(t *testing.T) {
	requireIntegration(t)
	binary, err := exec.LookPath("caddy")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	p, backup, _, _ := linuxUninstallFixture(t)
	shim := filepath.Join(t.TempDir(), "caddy")
	guard := filepath.Join(t.TempDir(), "simulated-untrust")
	// Parse with native Caddy. Trust remains a simulated caller operation.
	script := `#!/bin/sh
case "$1" in
  version|adapt) exec "$SANDBAR_UNINSTALL_REAL_CADDY" "$@" ;;
  untrust) printf '%s\n' "$@" > "$SANDBAR_UNINSTALL_TRUST_GUARD" ;;
  *) exit 99 ;;
esac
`
	if err := os.WriteFile(shim, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SANDBAR_UNINSTALL_REAL_CADDY", binary)
	t.Setenv("SANDBAR_UNINSTALL_TRUST_GUARD", guard)
	p.installed.Binary = shim
	record, err := readSetupRecord(p)
	if err != nil {
		t.Fatal(err)
	}
	record.Identity = p.installed.identity()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.file("setup.json"), data, 0640); err != nil {
		t.Fatal(err)
	}
	plan, err := buildUninstallPlan(p, os.Getuid(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := runUninstallUser(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if string(readTestFile(t, guard)) != "untrust\n--cert\n"+p.rootCertificate()+"\n" {
		t.Fatal("trust simulation did not target selected root")
	}
	if err := finishUninstall(plan, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native composition cleanup retained backup", err)
	}
	if _, err := os.Stat(p.state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native composition cleanup retained runtime", err)
	}
}

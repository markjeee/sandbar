package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUninstallArgumentsAndHelp(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("SANDBAR_HOME", "")
	for _, args := range [][]string{{"uninstall"}, {"uninstall", "--check", "--yes"}, {"uninstall", "--yes", "extra"}, {"uninstall", "--unknown"}, {"--home", shortHome(t), "uninstall", "--yes"}, {"uninstall", "--home", "/tmp/private", "--check"}} {
		code, _, diagnostic := cli(t, args...)
		if code == 0 || diagnostic == "" {
			t.Fatalf("accepted %v", args)
		}
	}
	t.Setenv("SANDBAR_HOME", shortHome(t))
	if code, _, diagnostic := cli(t, "uninstall", "--yes"); code == 0 || !strings.Contains(diagnostic, "SANDBAR_HOME") {
		t.Fatal(code, diagnostic)
	}
	for _, args := range [][]string{{"uninstall", "--help"}, {"--help"}} {
		code, out, diagnostic := cli(t, args...)
		if code != 0 || !strings.Contains(out, "uninstall") || diagnostic != "" {
			t.Fatal(code, out, diagnostic)
		}
	}
}
func TestUninstallOwnedTreeAndSnapshots(t *testing.T) {
	for _, conflict := range []string{"unknown", "symlink", "edit", "mode"} {
		t.Run(conflict, func(t *testing.T) {
			root := shortHome(t)
			path := filepath.Join(root, "owned")
			if err := os.WriteFile(path, []byte("owned evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			plan := &uninstallPlan{}
			if conflict == "unknown" {
				if err := os.WriteFile(filepath.Join(root, "unknown"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if conflict == "symlink" {
				if err := os.Symlink(path, filepath.Join(root, "link")); err != nil {
					t.Fatal(err)
				}
			}
			err := plan.addTree(root, func(rel string, _ os.FileInfo) bool { return rel == "." || rel == "owned" }, os.Getuid())
			if conflict == "unknown" || conflict == "symlink" {
				if err == nil {
					t.Fatal("accepted unknown content")
				}
				if string(readTestFile(t, path)) != "owned evidence" {
					t.Fatal("changed evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if conflict == "edit" {
				if err := os.WriteFile(path, []byte("external edit"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := removeUninstallEntry(plan.Entries[0]); err == nil {
				t.Fatal("removed changed file")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestUninstallMarkersPreserveOutsideBytes(t *testing.T) {
	top := []byte("# before\n{\n" + globalMarkerStart + "import \"/globals\"\n" + globalMarkerEnd + " email test@example.com\n}\n# middle\n" + routesMarkerStart + "import \"/routes\"\n" + routesMarkerEnd + "# tail\n")
	stripped, err := stripUninstallMarkers(top, "/globals", "/routes")
	if err != nil || string(stripped) != "# before\n{\n email test@example.com\n}\n# middle\n# tail\n" {
		t.Fatal(string(stripped), err)
	}
	for _, changed := range [][]byte{bytes.Replace(top, []byte("import \"/routes\""), []byte("import \"/other\""), 1), append(top, []byte(routesMarkerStart)...), bytes.Replace(top, []byte(globalMarkerEnd), nil, 1)} {
		if _, err := stripUninstallMarkers(changed, "/globals", "/routes"); err == nil {
			t.Fatal("accepted changed markers")
		}
	}
}
func TestUninstallPlanDigestPreservesEvidence(t *testing.T) {
	plan := &uninstallPlan{SourceSHA256: "source", SetupSHA256: "setup", Entries: []uninstallEntry{{Path: "backup.json", SHA256: "original"}, {Path: "ssh.log"}}}
	before := uninstallPlanDigest(plan)
	plan.SetupSHA256 = "changed"
	if before == uninstallPlanDigest(plan) {
		t.Fatal("missed setup change")
	}
	plan.SetupSHA256 = "setup"
	plan.Entries[0].SHA256 = "changed"
	if before == uninstallPlanDigest(plan) {
		t.Fatal("missed backup change")
	}
}
func TestUninstallOSAliasAndTreeSymlink(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "sandbar-uninstall-alias-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "owned")
	if err := os.WriteFile(path, []byte("owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkUninstallParents(path); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := checkUninstallParents(filepath.Join(link, "owned")); err == nil {
		t.Fatal("followed cleanup-tree symlink")
	}
}
func TestUninstallUnknownTeleportBlocksUserChanges(t *testing.T) {
	p, _ := testInstalledPaths(t)
	cfg := config{Teleports: []teleportDestination{{Machine: "peer"}}}
	socket, _, err := teleportControlPaths(p, cfg.Teleports[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(socket, []byte("not a control socket"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := &uninstallPlan{Paths: p, Config: cfg}
	if err := observeUninstallTeleports(plan); err == nil {
		t.Fatal("accepted unknown owner/control state")
	}
	if err := runUninstallUser(plan, io.Discard, io.Discard); err == nil {
		t.Fatal("changed user state")
	}
	if string(readTestFile(t, socket)) != "not a control socket" {
		t.Fatal("deleted unknown control file")
	}
}
func TestUninstallLeafOwnershipBoundary(t *testing.T) {
	root := shortHome(t)
	for _, path := range []string{"obsolete.localhost/obsolete.localhost.crt", "obsolete.localhost/obsolete.localhost.key", "obsolete.localhost/obsolete.localhost.json"} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	plan := &uninstallPlan{}
	if err := plan.addTree(root, uninstallLeafPath, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if len(plan.Entries) != 3 {
		t.Fatal(plan.Entries)
	}
	if err := os.WriteFile(filepath.Join(root, "obsolete.localhost", "foreign.key"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := plan.addTree(root, uninstallLeafPath, os.Getuid()); err == nil {
		t.Fatal("accepted foreign certificate file")
	}
}
func TestUninstallRetainsSelectedExecutable(t *testing.T) {
	for _, name := range []string{"default/sandbar", "custom/sandbar"} {
		root := shortHome(t)
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("executable fixture"), 0755); err != nil {
			t.Fatal(err)
		}
		plan := &uninstallPlan{Installation: installation{CLI: path}}
		if err := plan.addFile(path, os.Getuid()); err == nil {
			t.Fatal("scheduled selected executable deletion")
		}
		if string(readTestFile(t, path)) != "executable fixture" {
			t.Fatal("changed executable")
		}
	}
}
func TestUninstallRefusesLateControlSocket(t *testing.T) {
	p, _ := testInstalledPaths(t)
	d := teleportDestination{Machine: "peer"}
	socket, _, _ := teleportControlPaths(p, d)
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	plan := &uninstallPlan{Paths: p, Config: config{Teleports: []teleportDestination{d}}, OwnerUID: os.Getuid()}
	if err := checkUninstallDisconnected(plan); err == nil {
		t.Fatal("accepted new connection")
	}
}
func TestInstalledLockWaiterRechecksSetup(t *testing.T) {
	p, _ := testInstalledPaths(t)
	file, err := os.OpenFile(p.file("router.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	entered := false
	done := make(chan error, 1)
	go func() { done <- withLock(p, func() error { entered = true; return nil }) }()
	// Wait until the goroutine opened the existing inode, after its first setup check.
	lockInfo, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		descriptors, err := os.ReadDir("/dev/fd")
		if err != nil {
			t.Fatal(err)
		}
		matches := 0
		for _, descriptor := range descriptors {
			// macOS fdesc stat reports a synthetic device. Fstat the duplicate.
			duplicate, err := os.Open(filepath.Join("/dev/fd", descriptor.Name()))
			if err != nil {
				continue
			}
			info, err := duplicate.Stat()
			_ = duplicate.Close()
			if err == nil && os.SameFile(lockInfo, info) {
				matches++
			}
		}
		if matches >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("waiter did not open the router lock")
		}
		time.Sleep(time.Millisecond)
	}
	// Retirement while the held lock excludes mutations. Even an already-waiting
	// command must reject missing setup when it obtains this same inode.
	if err := os.Remove(p.file("setup.json")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err == nil || entered {
		t.Fatal("waiter entered retired installation", err)
	}
}
func TestUninstallMissingEvidenceIsNotRegenerated(t *testing.T) {
	p, _ := testInstalledPaths(t)
	if err := os.Remove(p.file("setup.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := buildUninstallPlan(p, os.Getuid(), io.Discard); err == nil {
		t.Fatal("accepted partial setup")
	}
	if _, err := os.Stat(p.file("setup.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("regenerated evidence", err)
	}
}

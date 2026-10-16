package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Plans contain public configuration and hashes, never CA keys or backup contents.
type uninstallPlan struct {
	Paths            paths `json:"-"`
	Installation     installation
	OwnerUID         int
	Config           config
	Top, Stripped    []byte
	Fingerprint      string
	Entries          []uninstallEntry
	Directories      []string
	DirectoryEntries []uninstallEntry
	Manifest         inputManifest
	SourceSHA256     string
	SetupSHA256      string
	AlreadyRemoved   bool
}
type uninstallEntry struct {
	Path     string
	Mode     os.FileMode
	UID, GID int
	SHA256   string
}

func uninstall(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(errOut)
	check := flags.Bool("check", false, "preview installed removal")
	yes := flags.Bool("yes", false, "confirm installed removal")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *check == *yes {
		return errors.New("use uninstall --check to preview or uninstall --yes to confirm removal")
	}
	return uninstallInstalled(*check, out, errOut)
}

func buildUninstallPlan(p paths, ownerUID int, errOut io.Writer) (*uninstallPlan, error) {
	if p.installed == nil {
		return nil, errors.New("uninstall requires the installed integration")
	}
	plan := &uninstallPlan{Paths: p, Installation: *p.installed, OwnerUID: ownerUID}
	i := p.installed
	absent := true
	for _, path := range []string{filepath.Dir(p.config), p.state, i.Globals, filepath.Join(i.Storage, "pki/authorities/sandbar"), filepath.Join(i.Storage, "certificates/sandbar")} {
		if _, err := os.Lstat(path); err == nil {
			absent = false
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	backups, err := uninstallBackupRoots(p)
	if err != nil {
		return nil, err
	}
	if absent && len(backups) == 0 {
		top, err := readOptional(i.Config)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(top, []byte("SANDBAR GLOBAL")) || bytes.Contains(top, []byte("SANDBAR ROUTES")) {
			return nil, fmt.Errorf("the Sandbar markers remain in %s; retain partial state for manual recovery", i.Config)
		}
		controlDir := teleportShortControlDir(p, ownerUID)
		if _, err := os.Lstat(controlDir); err == nil {
			return nil, fmt.Errorf("the Sandbar SSH control directory remains at %s; review it manually", controlDir)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		plan.AlreadyRemoved = true
		if err := uninstallPlatformPreflight(plan, ownerUID); err != nil {
			return nil, err
		}
		return plan, nil
	}
	if err := p.requireSetup(); err != nil {
		return nil, fmt.Errorf("uninstall needs intact setup evidence; retain remnants for manual recovery: %w", err)
	}
	if _, err := os.Lstat(p.file("transaction")); err == nil {
		return nil, fmt.Errorf("resolve pending route recovery at %s before uninstall", p.file("transaction"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	setupData, err := os.ReadFile(p.file("setup.json"))
	if err != nil {
		return nil, err
	}
	plan.SetupSHA256 = fmt.Sprintf("%x", sha256.Sum256(setupData))
	sourceData, err := os.ReadFile(p.config)
	if err != nil {
		return nil, err
	}
	plan.SourceSHA256 = fmt.Sprintf("%x", sha256.Sum256(sourceData))
	plan.Config, err = readConfig(p.config)
	if err != nil {
		return nil, err
	}
	if err := checkUninstallOwnedFragments(p); err != nil {
		return nil, err
	}
	generated, err := os.ReadFile(p.generatedPath())
	if err != nil {
		return nil, err
	}
	matchingRoutes := false
	for _, ipv6 := range []bool{false, true} {
		expected, err := renderInstalledRoutes(plan.Config, ipv6)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(generated, []byte(expected)) {
			matchingRoutes = true
		}
	}
	if !matchingRoutes {
		return nil, fmt.Errorf("retain modified generated routes: %s; review reload before uninstall", p.generatedPath())
	}
	state, err := i.Service.Inspect()
	if err != nil {
		return nil, err
	}
	if state.State != "active" && state.State != "inactive" && state.State != "failed" {
		return nil, fmt.Errorf("cannot uninstall service in state %s", state.State)
	}
	plan.Top, err = readConfigInput(i.Config)
	if err != nil {
		return nil, err
	}
	plan.Stripped, err = stripUninstallMarkers(plan.Top, i.Globals, p.generatedPath())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i.Config, err)
	}
	candidate, manifest, err := composeCandidate(i.Config, plan.Stripped, map[string][]byte{i.Config: plan.Stripped}, p.generatedPath())
	if err != nil {
		return nil, err
	}
	// The manifest describes the current on-disk inputs, not the stripped candidate.
	for n := range manifest.Files {
		if manifest.Files[n].Path == i.Config {
			manifest.Files[n], err = inputRecord(i.Config, plan.Top)
			if err != nil {
				return nil, err
			}
		}
	}
	plan.Manifest = manifest
	if err := checkUninstallCandidate(p, candidate, errOut); err != nil {
		return nil, err
	}
	authority := filepath.Join(i.Storage, "pki/authorities/sandbar")
	original := filepath.Join(authority, "root.crt")
	_, plan.Fingerprint, err = doctorRoot(original)
	if err != nil {
		return nil, fmt.Errorf("retain CA identity evidence at %s: %w", original, err)
	}
	copies := []string{p.rootCertificate(), p.file("root.crt")}
	for _, copyPath := range copies {
		if copyPath == original {
			continue
		}
		if _, err := os.Lstat(copyPath); errors.Is(err, os.ErrNotExist) && copyPath != p.rootCertificate() {
			continue
		} else if err != nil {
			return nil, err
		}
		_, fingerprint, err := doctorRoot(copyPath)
		if err != nil {
			return nil, err
		}
		if fingerprint != plan.Fingerprint {
			return nil, fmt.Errorf("public root differs at %s; retain it for separate trust removal", copyPath)
		}
	}
	sshPath := filepath.Join(filepath.Dir(p.config), "ssh/config")
	if sshData, err := readOptional(sshPath); err != nil {
		return nil, err
	} else if sshData != nil {
		expected, err := renderTeleportSSH(filepath.Dir(sshPath), plan.Config.Teleports)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(sshData, expected) {
			return nil, fmt.Errorf("retain modified Sandbar SSH configuration: %s", sshPath)
		}
	}
	owners := []int{0, i.UID, ownerUID}
	if err := plan.addTree(filepath.Dir(p.config), func(rel string, info os.FileInfo) bool {
		if filepath.Clean(filepath.Dir(p.config)) == filepath.Clean(filepath.Dir(p.state)) && (rel == "state" || strings.HasPrefix(rel, "state/")) {
			return true
		}
		return rel == "." || rel == "config.json" || rel == "ssh" || rel == "ssh/config" || rel == "ssh/known_hosts"
	}, owners...); err != nil {
		return nil, err
	}
	// The macOS source directory contains state. Inspect it using its own allowlist.
	if err := plan.addTree(p.state, func(rel string, info os.FileInfo) bool { return uninstallStatePath(p, plan.Config, rel, info) }, owners...); err != nil {
		return nil, err
	}
	if err := plan.addTree(authority, func(rel string, info os.FileInfo) bool {
		return rel == "." || rel == "root.crt" || rel == "root.key" || rel == "intermediate.crt" || rel == "intermediate.key"
	}, owners...); err != nil {
		return nil, err
	}
	if err := plan.addTree(filepath.Join(i.Storage, "certificates/sandbar"), uninstallLeafPath, owners...); err != nil {
		return nil, err
	}
	if err := plan.addFile(i.Globals, owners...); err != nil {
		return nil, err
	}
	for _, backup := range backups {
		data, err := readConfigInput(filepath.Join(backup, "backup.json"))
		if err != nil {
			return nil, err
		}
		var undo setupUndo
		if err := json.Unmarshal(data, &undo); err != nil {
			return nil, fmt.Errorf("retain unrecognized setup backup %s: %w", backup, err)
		}
		if undo.Dir != backup {
			return nil, fmt.Errorf("retain setup backup with changed identity: %s", backup)
		}
		if err := plan.addTree(backup, uninstallBackupPath, owners...); err != nil {
			return nil, err
		}
	}
	if err := plan.addTeleportControlDirectory(); err != nil {
		return nil, err
	}
	if err := uninstallPlatformPreflight(plan, ownerUID); err != nil {
		return nil, err
	}
	sort.Slice(plan.Entries, func(a, b int) bool { return plan.Entries[a].Path < plan.Entries[b].Path })
	return plan, nil
}

func (plan *uninstallPlan) addTeleportControlDirectory() error {
	root := teleportShortControlDir(plan.Paths, plan.OwnerUID)
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || int(stat.Uid) != plan.OwnerUID {
		return fmt.Errorf("SSH directory must be owned by user %d with mode 0700: %s", plan.OwnerUID, root)
	}
	return plan.addTree(root, func(rel string, info os.FileInfo) bool {
		if rel == "." {
			return true
		}
		for _, d := range plan.Config.Teleports {
			socket, _, _ := teleportControlPathsForOwner(plan.Paths, d, plan.OwnerUID)
			if socket == filepath.Join(root, rel) {
				return info.Mode()&os.ModeSocket != 0
			}
		}
		return false
	}, plan.OwnerUID)
}

func stripUninstallMarkers(top []byte, globals, routes string) ([]byte, error) {
	result := append([]byte{}, top...)
	for _, marker := range []struct{ start, end, path string }{{globalMarkerStart, globalMarkerEnd, globals}, {routesMarkerStart, routesMarkerEnd, routes}} {
		expected := marker.start + "import " + strconv.Quote(marker.path) + "\n" + marker.end
		if bytes.Count(result, []byte(expected)) != 1 || bytes.Count(result, []byte(marker.start)) != 1 || bytes.Count(result, []byte(marker.end)) != 1 {
			return nil, errors.New("the Sandbar markers changed or are missing; review the Caddyfile before uninstall")
		}
		var err error
		result, err = stripOwnedMarker(result, marker.start, marker.end)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func checkUninstallCandidate(p paths, candidate []byte, errOut io.Writer) error {
	dir, err := os.MkdirTemp("", "sandbar-uninstall-preview-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, candidate, 0600); err != nil {
		return err
	}
	// Adaptation parses only. It does not provision a CA or bind listeners.
	data, err := adaptCaddyfile(p, path, errOut)
	if err != nil {
		return fmt.Errorf("inspect configuration after Sandbar removal: %w", err)
	}
	var document struct {
		Apps  map[string]json.RawMessage `json:"apps"`
		Admin struct {
			Listen string `json:"listen"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return err
	}
	for name, raw := range document.Apps {
		if string(raw) != "{}" && string(raw) != "null" {
			return fmt.Errorf("selected Caddy service still has unrelated %s configuration; separate unrelated sites before uninstall", name)
		}
	}
	if document.Admin.Listen != "" {
		return errors.New("selected Caddy configuration retains an unrelated admin listener; separate it before uninstall")
	}
	return nil
}

func uninstallStatePath(p paths, c config, rel string, info os.FileInfo) bool {
	switch rel {
	case ".", "routes", "routes/Caddyfile", "work", "work/router.lock", "admin", "admin/admin.sock", "validation", "validation/Caddyfile", "global.Caddyfile", "root.crt", "setup.json", "launchd", "launchd/caddy.plist", "backups", "teleport", "work/teleport":
		return true
	}
	if strings.HasPrefix(rel, "backups/setup-") {
		parts := strings.Split(rel, "/")
		return len(parts) == 2 && info.IsDir() || len(parts) == 3 && parts[2] == "backup.json" && !info.IsDir()
	}
	if strings.HasPrefix(rel, "work/transaction-complete") {
		tail := strings.TrimPrefix(rel, "work/transaction-complete")
		return tail == "" && info.IsDir() || strings.HasPrefix(tail, "/") && uninstallTransactionFile(strings.TrimPrefix(tail, "/"))
	}
	for _, d := range c.Teleports {
		socket, log, _ := teleportControlPathsForOwner(p, d, os.Getuid())
		for _, path := range []string{filepath.Dir(log), log, socket} {
			relative, err := filepath.Rel(p.state, path)
			if err == nil && relative == rel {
				return true
			}
		}
	}
	return false
}
func uninstallTransactionFile(name string) bool {
	switch name {
	case "journal.json", "previous.config.json", "candidate.config.json", "previous.Caddyfile", "candidate.Caddyfile", "previous.active.json", "candidate.active.json":
		return true
	}
	return false
}
func uninstallLeafPath(rel string, info os.FileInfo) bool {
	if rel == "." {
		return true
	}
	parts := strings.Split(rel, string(os.PathSeparator))
	if len(parts) == 1 {
		return info.IsDir()
	}
	if len(parts) != 2 || info.IsDir() {
		return false
	}
	base := strings.TrimSuffix(parts[1], filepath.Ext(parts[1]))
	extension := filepath.Ext(parts[1])
	return base == parts[0] && (extension == ".crt" || extension == ".key" || extension == ".json")
}
func uninstallBackupPath(rel string, info os.FileInfo) bool {
	switch rel {
	case ".", "backup.json", "sudoers.candidate", "legacy", "legacy/root.crt", "legacy/root.key", "legacy/intermediate.crt", "legacy/intermediate.key", "legacy/config.json", "legacy/Caddyfile":
		return true
	}
	return false
}

func (plan *uninstallPlan) addFile(path string, owners ...int) error {
	for _, entry := range plan.Entries {
		if entry.Path == path {
			return nil
		}
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := checkUninstallParents(path); err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	allowed := false
	if ok {
		for _, owner := range owners {
			if int(st.Uid) == owner {
				allowed = true
			}
		}
	}
	if !allowed || info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && info.Mode()&os.ModeSocket == 0) {
		return fmt.Errorf("retain unowned or unsupported file: %s", path)
	}
	cli, _ := os.Executable()
	cli, _ = filepath.EvalSymlinks(cli)
	if path == cli || path == plan.Installation.CLI {
		return fmt.Errorf("retained executable is inside cleanup targets: %s; move it before uninstall", path)
	}
	entry := uninstallEntry{Path: path, Mode: info.Mode(), UID: int(st.Uid), GID: int(st.Gid)}
	if info.Mode().IsRegular() && !strings.HasSuffix(path, "/ssh.log") {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entry.SHA256 = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	plan.Entries = append(plan.Entries, entry)
	return nil
}
func (plan *uninstallPlan) addTree(root string, allowed func(string, os.FileInfo) bool, owners ...int) error {
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := checkUninstallParents(root); err != nil {
		return err
	}
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !allowed(rel, info) {
			return fmt.Errorf("retain unknown file or directory: %s; review it before uninstall", path)
		}
		if info.IsDir() {
			st, ok := info.Sys().(*syscall.Stat_t)
			owned := false
			if ok {
				for _, uid := range owners {
					if int(st.Uid) == uid {
						owned = true
					}
				}
			}
			if !owned {
				return fmt.Errorf("retain unowned directory: %s", path)
			}
			for _, dir := range plan.Directories {
				if dir == path {
					return nil
				}
			}
			plan.DirectoryEntries = append(plan.DirectoryEntries, uninstallEntry{Path: path, Mode: info.Mode(), UID: int(st.Uid), GID: int(st.Gid)})
			plan.Directories = append(plan.Directories, path)
			return nil
		}
		return plan.addFile(path, owners...)
	})
}
func checkUninstallParents(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 && (parent == "/tmp" || parent == "/var") {
			target, err := os.Readlink(parent)
			if err == nil && (target == "private"+parent || target == "/private"+parent) {
				continue
			}
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("retain path with non-directory or symlink parent: %s", parent)
		}
		if parent == filepath.Dir(parent) {
			return nil
		}
	}
}

func uninstallPlanDigest(plan *uninstallPlan) string {
	type stable struct {
		Identity, Fingerprint, SetupSHA256, SourceSHA256 string
		Top                                              []byte
		Entries, Directories                             []uninstallEntry
	}
	var entries []uninstallEntry
	for _, entry := range plan.Entries {
		if entry.Mode&os.ModeSocket != 0 || strings.HasSuffix(entry.Path, "/ssh.log") {
			continue
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Path < entries[b].Path })
	directories := append([]uninstallEntry{}, plan.DirectoryEntries...)
	sort.Slice(directories, func(a, b int) bool { return directories[a].Path < directories[b].Path })
	data, _ := json.Marshal(stable{plan.Installation.identity(), plan.Fingerprint, plan.SetupSHA256, plan.SourceSHA256, plan.Top, entries, directories})
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
func printUninstallPlan(plan *uninstallPlan, out io.Writer) {
	if plan.AlreadyRemoved {
		fmt.Fprintln(out, "Sandbar cleanup is already complete. The CLI remains installed.")
		return
	}
	fmt.Fprintln(out, "Selected service:", plan.Installation.Unit)
	fmt.Fprintln(out, "Public root SHA-256:", plan.Fingerprint)
	for _, d := range plan.Config.Teleports {
		fmt.Fprintln(out, "Disconnect owned Teleport if connected:", d.Machine)
	}
	fmt.Fprintln(out, "Remove current-user certificate trust through Caddy before file cleanup.")
	fmt.Fprintln(out, "Remove Sandbar markers from:", plan.Installation.Config)
	for _, entry := range plan.Entries {
		fmt.Fprintln(out, "Remove:", entry.Path)
	}
	for _, dir := range plan.Directories {
		fmt.Fprintln(out, "Remove when empty:", dir)
	}
	cli := plan.Installation.CLI
	if cli == "" {
		cli, _ = os.Executable()
	}
	fmt.Fprintln(out, "Keep executable:", cli)
	fmt.Fprintln(out, "Keep Caddy packages, shared storage and logs, unrelated services, user SSH keys, and remote machines.")
	fmt.Fprintln(out, "Manual browser imports and other users' trust stores need separate review.")
}

func runUninstallUser(plan *uninstallPlan, out, errOut io.Writer) error {
	if plan.AlreadyRemoved {
		return nil
	}
	p := plan.Paths
	if err := observeUninstallTeleports(plan); err != nil {
		return err
	}
	configPath := filepath.Join(filepath.Dir(p.config), "ssh/config")
	for _, d := range plan.Config.Teleports {
		state, err := observeTeleport(p, d)
		if err != nil {
			return err
		}
		if state == "disconnected" {
			continue
		}
		socket, _, err := teleportControlPaths(p, d)
		if err != nil {
			return err
		}
		if err := exitTeleportMaster(configPath, socket, d, errOut); err != nil {
			return fmt.Errorf("disconnect %s; remaining files retained: %w", d.Machine, err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			state, err = observeTeleport(p, d)
			if err != nil {
				return err
			}
			if state == "disconnected" {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("the Teleport %s did not disconnect; retain its control files", d.Machine)
			}
			time.Sleep(25 * time.Millisecond)
		}
		fmt.Fprintln(out, "Disconnected Teleport:", d.Machine)
	}
	if err := changeTrust(p, "untrust", out, errOut); err != nil {
		return fmt.Errorf("untrust failed; retain CA files, configuration, and setup backups; completed disconnects remain in effect: %w", err)
	}
	fmt.Fprintln(out, "Completed current-user untrust for root SHA-256:", plan.Fingerprint)
	for _, d := range plan.Config.Teleports {
		state, err := observeTeleport(p, d)
		if err != nil {
			return err
		}
		if state != "disconnected" {
			return fmt.Errorf("the Teleport %s connected during uninstall; retain its state and retry", d.Machine)
		}
		socket, _, err := teleportControlPaths(p, d)
		if err != nil {
			return err
		}
		info, err := os.Lstat(socket)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || int(stat.Uid) != os.Getuid() || info.Mode().Perm() != 0600 {
			return fmt.Errorf("retain changed SSH socket: %s", socket)
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed disconnected SSH control socket:", socket)
	}
	return nil
}

// Linux preflight must derive the caller's short control path while running as root.
func teleportControlPathsForOwner(p paths, d teleportDestination, uid int) (string, string, error) {
	socket, log, err := teleportControlPaths(p, d)
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(socket, "/tmp/sandbar-") {
		socket = filepath.Join(teleportShortControlDir(p, uid), teleportID(d.Machine)+".sock")
	}
	return socket, log, nil
}

func finishUninstall(plan *uninstallPlan, out, errOut io.Writer) (result error) {
	if plan.AlreadyRemoved {
		return nil
	}
	p := plan.Paths
	// Do not create a lock or prepare directories during uninstall.
	lock, err := os.OpenFile(p.file("router.lock"), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("retain installed files; open existing router lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	defer func() {
		if result != nil {
			fmt.Fprintln(errOut, "Uninstall incomplete. Earlier disconnect and untrust actions are not reversed.")
			fmt.Fprintln(errOut, "Retain remaining evidence under:", filepath.Dir(p.config), p.state, plan.Installation.Storage)
			fmt.Fprintln(errOut, "Review the failed path and docs/install.md before retry or fresh setup.")
		}
	}()
	fresh, err := buildUninstallPlan(p, plan.OwnerUID, errOut)
	if err != nil {
		return err
	}
	if uninstallPlanDigest(fresh) != uninstallPlanDigest(plan) {
		return errors.New("installation changed after preflight; retain files and repeat uninstall --check")
	}
	if err := checkUninstallDisconnected(fresh); err != nil {
		return err
	}
	if err := verifyInputManifest(fresh.Manifest); err != nil {
		return err
	}
	if err := uninstallPlatformStop(fresh, out, errOut); err != nil {
		return fmt.Errorf("service shutdown failed; retain configuration, CA, and backups: %w", err)
	}
	fmt.Fprintln(out, "Stopped and disabled startup:", fresh.Installation.Unit)
	if err := verifyInputManifest(fresh.Manifest); err != nil {
		return err
	}
	if err := checkUninstallDisconnected(fresh); err != nil {
		return err
	}
	meta, err := readFileMetadata(fresh.Installation.Config)
	if err != nil {
		return err
	}
	if meta == nil {
		return errors.New("shared Caddyfile disappeared during uninstall")
	}
	if err := atomicWriteMode(fresh.Installation.Config, fresh.Stripped, meta.Mode, meta.UID, meta.GID); err != nil {
		return fmt.Errorf("publish stripped Caddyfile: %w", err)
	}
	fmt.Fprintln(out, "Removed Sandbar Caddyfile markers:", fresh.Installation.Config)
	// Setup retirement precedes lock-path removal. Waiters recheck setup under lock.
	sort.SliceStable(fresh.Entries, func(a, b int) bool {
		return uninstallDeleteOrder(fresh.Entries[a].Path, p) < uninstallDeleteOrder(fresh.Entries[b].Path, p)
	})
	finishedPlatform := false
	for _, entry := range fresh.Entries {
		if !finishedPlatform && uninstallDeleteOrder(entry.Path, p) > 1 {
			if err := uninstallPlatformFinish(fresh, out, errOut); err != nil {
				return err
			}
			finishedPlatform = true
		}
		if err := removeUninstallEntry(entry); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed:", entry.Path)
	}
	if !finishedPlatform {
		if err := uninstallPlatformFinish(fresh, out, errOut); err != nil {
			return err
		}
	}
	sort.Slice(fresh.Directories, func(a, b int) bool { return len(fresh.Directories[a]) > len(fresh.Directories[b]) })
	for _, dir := range fresh.Directories {
		info, err := os.Lstat(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		matching := false
		stat, ok := info.Sys().(*syscall.Stat_t)
		for _, entry := range fresh.DirectoryEntries {
			if ok && entry.Path == dir && entry.Mode == info.Mode() && entry.UID == int(stat.Uid) && entry.GID == int(stat.Gid) {
				matching = true
				break
			}
		}
		if !info.IsDir() || !matching {
			return fmt.Errorf("retain changed directory: %s", dir)
		}
		if err := checkUninstallParents(dir); err != nil {
			return err
		}
		if err := os.Remove(dir); err != nil {
			return fmt.Errorf("retain nonempty or changed directory %s: %w", dir, err)
		}
	}
	fmt.Fprintln(out, "Uninstall complete. The Sandbar executable remains installed.")
	fmt.Fprintln(out, "Fresh setup creates new configuration and CA material. Request trust and register Teleport peers again.")
	return nil
}
func uninstallDeleteOrder(path string, p paths) int {
	if path == p.file("router.lock") {
		return 4
	}
	if strings.Contains(path, "/backups/") || strings.HasPrefix(path, "/var/backups/sandbar-setup-") {
		return 2
	}
	if path == p.file("setup.json") {
		return 3
	}
	return 1
}
func checkUninstallDisconnected(plan *uninstallPlan) error {
	for _, d := range plan.Config.Teleports {
		socket, _, err := teleportControlPathsForOwner(plan.Paths, d, plan.OwnerUID)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(socket); err == nil {
			return fmt.Errorf("the Teleport control socket remains at %s; disconnect it and repeat uninstall", socket)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func removeUninstallEntry(entry uninstallEntry) error {
	if err := checkUninstallParents(entry.Path); err != nil {
		return err
	}
	info, err := os.Lstat(entry.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != entry.Mode || int(st.Uid) != entry.UID || int(st.Gid) != entry.GID {
		return fmt.Errorf("retain changed file: %s", entry.Path)
	}
	if entry.SHA256 != "" {
		data, err := os.ReadFile(entry.Path)
		if err != nil {
			return err
		}
		if fmt.Sprintf("%x", sha256.Sum256(data)) != entry.SHA256 {
			return fmt.Errorf("retain externally edited file: %s", entry.Path)
		}
	}
	if err := os.Remove(entry.Path); err != nil {
		return fmt.Errorf("remove %s: %w", entry.Path, err)
	}
	return nil
}

func observeUninstallTeleports(plan *uninstallPlan) error {
	for _, d := range plan.Config.Teleports {
		if _, err := observeTeleport(plan.Paths, d); err != nil {
			return fmt.Errorf("retain Teleport state for %s: %w", d.Machine, err)
		}
	}
	return nil
}

func checkUninstallOwnedFragments(p paths) error {
	record, err := readSetupRecord(p)
	if err != nil {
		return err
	}
	for _, file := range record.Manifest.Files {
		if file.Path == p.installed.Globals {
			return verifyInputManifest(inputManifest{Files: []inputFile{file}})
		}
	}
	return fmt.Errorf("setup has no ownership evidence for %s; review setup --check", p.installed.Globals)
}

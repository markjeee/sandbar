//go:build linux

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

var uninstallLinuxOutput = systemOutput
var uninstallLinuxInspect = inspectInstallation
var uninstallLinuxPolicies = func(p paths) ([]setupPolicy, int) {
	address, _ := p.adminAddress()
	return setupPolicies(address), 0
}
var uninstallLinuxSudo = func(executable string, out, errOut io.Writer, args ...string) error {
	return runBounded("/usr/bin/sudo", os.Environ(), os.Stdin, out, errOut,
		append([]string{"--", executable, "_uninstall-system"}, args...)...)
}

func uninstallInstalled(check bool, out, errOut io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("run sandbar uninstall as your normal user; it requests administrator authorization for system inspection and cleanup")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	var output bytes.Buffer
	if err := uninstallLinuxSudo(executable, &output, errOut, "--preflight"); err != nil {
		return fmt.Errorf("administrator inspection failed; no cleanup started: %w", err)
	}
	var plan uninstallPlan
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return fmt.Errorf("read administrator inspection: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("administrator inspection returned more than one result")
	}
	if plan.OwnerUID != os.Getuid() {
		return errors.New("administrator inspection returned a different caller identity")
	}
	plan.Paths = installedPaths(&plan.Installation)
	printUninstallPlan(&plan, out)
	if plan.AlreadyRemoved {
		return nil
	}
	if err := observeUninstallTeleports(&plan); err != nil {
		return err
	}
	if check {
		return nil
	}
	if err := runUninstallUser(&plan, out, errOut); err != nil {
		return err
	}
	if err := uninstallLinuxSudo(executable, out, errOut, "--apply", plan.Fingerprint, uninstallPlanDigest(&plan)); err != nil {
		return fmt.Errorf("system cleanup failed after caller disconnect and untrust; remaining system files require retry or manual review: %w", err)
	}
	return nil
}

// This entry point accepts identities, never caller-selected filesystem paths.
func uninstallSystem(args []string, out, errOut io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("internal uninstall inspection and cleanup require administrator authorization")
	}
	if err := checkUninstallSystemArgs(args); err != nil {
		return err
	}
	ownerUID, err := uninstallSudoOwner(os.Getenv("SUDO_UID"), os.Getenv("SUDO_USER"))
	if err != nil {
		return err
	}
	i, err := inspectInstallation()
	if err != nil {
		return err
	}
	plan, err := buildUninstallPlan(installedPaths(i), ownerUID, errOut)
	if err != nil {
		return err
	}
	if args[0] == "--preflight" {
		return json.NewEncoder(out).Encode(plan)
	}
	if plan.AlreadyRemoved {
		fmt.Fprintln(out, "Sandbar cleanup is already complete. The CLI remains installed.")
		return nil
	}
	if plan.Fingerprint != args[1] || uninstallPlanDigest(plan) != args[2] {
		return errors.New("installed identity or configuration changed after user cleanup; system files retained for manual review")
	}
	return finishUninstall(plan, out, errOut)
}

func checkUninstallSystemArgs(args []string) error {
	if len(args) == 1 && args[0] == "--preflight" {
		return nil
	}
	if len(args) == 3 && args[0] == "--apply" && uninstallSHA256(args[1]) && uninstallSHA256(args[2]) {
		return nil
	}
	return errors.New("internal uninstall accepts --preflight or --apply <root-sha256> <plan-sha256> only")
}

func uninstallSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func uninstallSudoOwner(uid, name string) (int, error) {
	id, err := strconv.Atoi(uid)
	if err != nil || id <= 0 || strconv.Itoa(id) != uid || name == "" {
		return 0, errors.New("internal uninstall requires the original non-root sudo caller")
	}
	account, err := user.LookupId(uid)
	if err != nil || account.Username != name {
		return 0, errors.New("internal uninstall cannot verify the original sudo caller")
	}
	return id, nil
}

func uninstallPlatformPreflight(plan *uninstallPlan, ownerUID int) error {
	p := plan.Paths
	if p.installed.ID != "apt-systemd-v1" {
		return errors.New("uninstall requires the supported apt/systemd installation")
	}
	policies, policyOwner := uninstallLinuxPolicies(p)
	if plan.AlreadyRemoved {
		if p.installed.GroupID >= 0 {
			return errors.New("the Sandbar group remains without setup evidence; manual review required")
		}
		for _, policy := range policies {
			if _, err := os.Lstat(policy.path); !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("retained or inaccessible Sandbar policy requires manual review: %s", policy.path)
			}
		}
		return nil
	}
	if p.installed.GroupID < 0 {
		return errors.New("the Sandbar access group is missing; preserve the partial installation for manual review")
	}
	if err := checkUninstallLinuxPolicies(policies, policyOwner); err != nil {
		return err
	}
	account, err := user.LookupId(strconv.Itoa(ownerUID))
	if err != nil {
		return err
	}
	group, err := uninstallLinuxOutput("/usr/bin/getent", "group", "sandbar")
	if err != nil {
		return err
	}
	accounts, err := uninstallLinuxOutput("/usr/bin/getent", "passwd")
	if err != nil {
		return err
	}
	if err := checkUninstallLinuxGroup(group, accounts, p.installed.GroupID, account.Username, p.installed.Account); err != nil {
		return err
	}
	// Exact setup policies, the accepted setup identity, and group-owned supported
	// directories establish dedicated integration use. They do not prove who
	// originally created the group or scan unrelated filesystem ownership.
	for _, path := range []string{filepath.Dir(p.config), p.state, p.workDir(), p.file("routes"), p.file("validation"), p.file("admin")} {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || int(stat.Gid) != p.installed.GroupID || (stat.Uid != 0 && int(stat.Uid) != p.installed.UID) {
			return fmt.Errorf("the Sandbar group ownership is ambiguous at %s; manual review required", path)
		}
	}
	for _, policy := range policies {
		if err := plan.addFile(policy.path, policyOwner); err != nil {
			return err
		}
	}
	return nil
}

func checkUninstallLinuxPolicies(policies []setupPolicy, ownerUID int) error {
	for _, policy := range policies {
		info, err := os.Lstat(policy.path)
		if err != nil {
			return fmt.Errorf("inspect Sandbar policy %s: %w", policy.path, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || int(stat.Uid) != ownerUID || stat.Gid != 0 && ownerUID == 0 || fileAccessMode(info.Mode()) != policy.mode {
			return fmt.Errorf("the Sandbar policy ownership or permission conflict: %s", policy.path)
		}
		data, err := os.ReadFile(policy.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, policy.data) {
			return fmt.Errorf("modified Sandbar policy requires manual review: %s", policy.path)
		}
	}
	return nil
}

func checkUninstallLinuxGroup(groupData, passwdData []byte, gid int, caller, caddy string) error {
	line := strings.TrimSuffix(string(groupData), "\n")
	fields := strings.Split(line, ":")
	if len(fields) != 4 || fields[0] != "sandbar" || fields[2] != strconv.Itoa(gid) || strings.ContainsAny(line, "\r\n") {
		return errors.New("the Sandbar group identity is ambiguous; manual review required")
	}
	members := map[string]bool{}
	for _, member := range strings.Split(fields[3], ",") {
		if member != caller && member != caddy || members[member] {
			return fmt.Errorf("the Sandbar group has another or ambiguous member %q; remove its access before uninstall", member)
		}
		members[member] = true
	}
	if !members[caller] || !members[caddy] || caller == caddy {
		return errors.New("the Sandbar group does not have the expected caller and Caddy grants; manual review required")
	}
	found := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(passwdData)), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[0] == "" {
			return errors.New("cannot inspect primary account groups; manual review required")
		}
		if fields[3] == strconv.Itoa(gid) {
			return fmt.Errorf("the Sandbar group is the primary group for %s; manual review required", fields[0])
		}
		if members[fields[0]] {
			found[fields[0]] = true
		}
	}
	if !found[caller] || !found[caddy] {
		return errors.New("cannot verify Sandbar group accounts; manual review required")
	}
	return nil
}

func uninstallPlatformStop(plan *uninstallPlan, out, errOut io.Writer) error {
	checked, err := uninstallLinuxInspect()
	if err != nil {
		return err
	}
	if checked.identity() != plan.Installation.identity() {
		return errors.New("the Caddy service identity changed before shutdown; files retained")
	}
	if err := checkUninstallDisconnected(plan); err != nil {
		return err
	}
	if _, err := uninstallLinuxOutput("/usr/bin/systemctl", "stop", plan.Installation.Unit); err != nil {
		return err
	}
	if _, err := uninstallLinuxOutput("/usr/bin/systemctl", "disable", plan.Installation.Unit); err != nil {
		return err
	}
	data, err := uninstallLinuxOutput("/usr/bin/systemctl", "show", plan.Installation.Unit, "--property=LoadState,ActiveState,UnitFileState")
	if err != nil {
		return err
	}
	fields, err := parseProperties(data)
	if err != nil {
		return err
	}
	if fields["LoadState"] != "loaded" || (fields["ActiveState"] != "inactive" && fields["ActiveState"] != "failed") || fields["UnitFileState"] != "disabled" {
		return errors.New("the Caddy shutdown or boot disable could not be verified; configuration and CA material retained")
	}
	return nil
}

func uninstallPlatformFinish(plan *uninstallPlan, out, errOut io.Writer) error {
	if _, err := uninstallLinuxOutput("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	account, err := user.LookupId(strconv.Itoa(plan.OwnerUID))
	if err != nil {
		return err
	}
	// Recheck group users immediately before removing their dedicated grants.
	group, err := uninstallLinuxOutput("/usr/bin/getent", "group", "sandbar")
	if err != nil {
		return err
	}
	accounts, err := uninstallLinuxOutput("/usr/bin/getent", "passwd")
	if err != nil {
		return err
	}
	if err := checkUninstallLinuxGroup(group, accounts, plan.Installation.GroupID, account.Username, plan.Installation.Account); err != nil {
		return err
	}
	for _, member := range []string{account.Username, plan.Installation.Account} {
		if _, err := uninstallLinuxOutput("/usr/bin/gpasswd", "-d", member, "sandbar"); err != nil {
			return err
		}
		fmt.Fprintln(out, "Removed Sandbar group access:", member)
	}
	if _, err := uninstallLinuxOutput("/usr/sbin/groupdel", "sandbar"); err != nil {
		return err
	}
	fmt.Fprintln(out, "Removed dedicated group: sandbar")
	return nil
}

var uninstallLinuxBackups = func(p paths) ([]string, error) {
	return findUninstallLinuxBackups(p, "/var/backups", 0)
}

func uninstallBackupRoots(p paths) ([]string, error) {
	return uninstallLinuxBackups(p)
}

func findUninstallLinuxBackups(p paths, root string, ownerUID int) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "sandbar-setup-") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || int(stat.Uid) != ownerUID || info.Mode().Perm() != 0700 {
			return nil, fmt.Errorf("setup backup ownership conflict: %s", path)
		}
		file := filepath.Join(path, "backup.json")
		info, err = os.Lstat(file)
		if err != nil {
			return nil, fmt.Errorf("setup backup requires manual review: %s: %w", path, err)
		}
		stat, ok = info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || int(stat.Uid) != ownerUID || info.Mode().Perm() != 0600 {
			return nil, fmt.Errorf("setup backup record ownership conflict: %s", file)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var backup setupUndo
		if err := json.Unmarshal(data, &backup); err != nil {
			return nil, fmt.Errorf("invalid setup backup %s: %w", file, err)
		}
		belongs := false
		for _, saved := range backup.Files {
			if saved.Path == p.config || saved.Path == p.installed.Globals {
				belongs = true
			}
		}
		if backup.Dir != path || !belongs {
			return nil, fmt.Errorf("setup backup identity is ambiguous: %s", path)
		}
		result = append(result, path)
	}
	return result, nil
}

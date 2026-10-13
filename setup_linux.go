//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type setupOptions struct {
	User                        string
	Check, ReplaceDefault       bool
	MigrateConfig, MigrateState string
}

func setup(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	var options setupOptions
	flags.StringVar(&options.User, "user", "", "account to grant Caddy access")
	flags.BoolVar(&options.Check, "check", false, "preview setup")
	flags.BoolVar(&options.ReplaceDefault, "replace-default-site", false, "replace Caddy's stock welcome site")
	flags.StringVar(&options.MigrateConfig, "migrate-config", "", "legacy config.json")
	flags.StringVar(&options.MigrateState, "migrate-state", "", "legacy state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup accepts flags only; use sandbar setup --help")
	}
	if options.User == "" {
		return errors.New("setup requires --user <name>")
	}
	account, err := user.Lookup(options.User)
	if err != nil {
		return fmt.Errorf("find setup user: %w", err)
	}
	if account.Uid == "0" {
		return errors.New("setup requires an existing non-root user")
	}
	if strings.ContainsAny(options.User, "\n\r\t /\\") {
		return errors.New("unsupported account name")
	}
	if (options.MigrateConfig == "") != (options.MigrateState == "") {
		return errors.New("use --migrate-config and --migrate-state together")
	}
	i, err := inspectInstallation()
	if err != nil {
		return err
	}
	for _, path := range []string{"/usr/bin/sudo", "/usr/sbin/visudo", "/usr/sbin/groupadd", "/usr/sbin/groupdel", "/usr/sbin/usermod", "/usr/bin/gpasswd", "/usr/sbin/runuser", "/usr/share/polkit-1/actions/org.freedesktop.systemd1.policy"} {
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("setup prerequisite %s: %w", path, err)
		}
	}
	p := installedPaths(i)
	if err := checkSelectedCaddy(p, caddyEnv(p), errOut); err != nil {
		return err
	}
	top, err := os.ReadFile(i.Config)
	if err != nil {
		return err
	}
	cfg := config{Version: 2, HTTPPort: 80, HTTPSPort: 443, Routes: []route{}}
	source, err := readOptional(p.config)
	if err != nil {
		return err
	}
	originalSource := appendOptional(source)
	originalRoutes, err := readOptional(p.generatedPath())
	if err != nil {
		return err
	}
	originalGlobals, err := readOptional(i.Globals)
	if err != nil {
		return err
	}
	expected := []setupSnapshot{{Path: i.Config, Data: top}, {Path: p.config, Data: originalSource}, {Path: p.generatedPath(), Data: originalRoutes}, {Path: i.Globals, Data: originalGlobals}}
	if source != nil {
		cfg, err = decodeConfig(bytes.NewReader(source))
		if err != nil {
			return err
		}
	}
	var migration *legacyMigration
	if options.MigrateConfig == "" && source == nil {
		for _, legacyPath := range []string{filepath.Join(account.HomeDir, ".config/sandbar/config.json"), filepath.Join(account.HomeDir, ".local/state/sandbar")} {
			if _, err := os.Stat(legacyPath); err == nil {
				return fmt.Errorf("legacy Sandbar state found at %s; use explicit --migrate-config <file> --migrate-state <directory>", legacyPath)
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	if options.MigrateConfig != "" {
		migration, err = inspectLegacyMigration(options, account, i)
		if err != nil {
			return err
		}
		if source != nil && !sameFileBytes(source, migration.Source) {
			return errors.New("installed source conflicts with legacy source; preserve both and review manually")
		}
		cfg = migration.Config
		source = migration.Source
	}
	if source == nil {
		source, err = configBytes(cfg)
		if err != nil {
			return err
		}
	}
	ipv6, err := ipv6Available(probeIPv6, errOut)
	if err != nil {
		return err
	}
	routes, err := renderInstalledRoutes(cfg, ipv6)
	if err != nil {
		return err
	}
	address, err := p.adminAddress()
	if err != nil {
		return err
	}
	if err := checkSetupPolicies(setupPolicies(address)); err != nil {
		return err
	}
	globals := []byte(renderInstalledGlobals(address, "", ""))
	composition, err := composeInstalledConfig(i.Config, top, i.Globals, p.generatedPath(), globals, []byte(routes), options.ReplaceDefault || options.Check)
	if err != nil {
		return err
	}
	state, err := i.Service.Inspect()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Integration:", i.ID)
	fmt.Fprintln(out, "Caddy:", i.Binary, "as", i.Account, "through", i.Unit)
	fmt.Fprintln(out, "Access for:", options.User, "through group sandbar (all Caddy routes and Caddy-readable files)")
	fmt.Fprintln(out, "Configuration:", p.config)
	fmt.Fprintln(out, "Caddy imports:", i.Config, "and", i.Globals)
	fmt.Fprintln(out, "Routes:", p.generatedPath())
	fmt.Fprintln(out, "Admin socket:", p.file("admin.sock"))
	fmt.Fprintln(out, "Policies: /etc/polkit-1/rules.d/50-sandbar.rules and /etc/sudoers.d/sandbar-caddy-validate")
	fmt.Fprintln(out, "Service drop-in: /etc/systemd/system/caddy.service.d/sandbar.conf")
	fmt.Fprintln(out, "Validation: one fixed command as caddy, with a clean environment; caddy also joins sandbar")
	fmt.Fprintln(out, "Service:", state.State, "boot:", state.Boot, "→ enable at boot and start; active service needs one setup restart")
	fmt.Fprintln(out, "Backups: /var/backups/sandbar-setup-<id>/backup.json (root access only)")
	if composition.StockReplaced {
		fmt.Fprintln(out, "Stock welcome site: offer backup and replacement with --replace-default-site")
	}
	if migration != nil {
		migration.describe(out)
	}
	fmt.Fprintln(out, "Welcome:", cfg.routeURL("sandbar.localhost"))
	fmt.Fprintln(out, "Trust is separate: sandbar trust. Start a new login session after setup.")
	if options.Check {
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("setup requires root; use sudo /absolute/path/to/sandbar setup --user <name>; --check previews without changes")
	}
	// Inspect again immediately before the first privileged change.
	checked, err := inspectInstallation()
	if err != nil {
		return err
	}
	if checked.identity() != i.identity() {
		return errors.New("the Caddy installation changed during setup preview")
	}
	return applySetup(p, options, account, source, []byte(routes), globals, composition, expected, state, migration, out, errOut)
}

const polkitRule = `// Sandbar administrators can control only the standard Caddy service.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        subject.isInGroup("sandbar") &&
        action.lookup("unit") == "caddy.service" &&
        ["start", "stop", "reload"].indexOf(action.lookup("verb")) >= 0) {
        return polkit.Result.YES;
    }
});
`
const validationRule = `Defaults:%sandbar env_reset, !setenv
Defaults:%sandbar secure_path=/usr/sbin:/usr/bin:/sbin:/bin
Defaults:%sandbar env_keep -= "HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME XDG_CACHE_HOME CADDY_ADMIN"
%sandbar ALL=(caddy) NOPASSWD: NOSETENV: /usr/bin/caddy validate --config /var/lib/sandbar/validation/Caddyfile --adapter caddyfile
`

func serviceDropIn(address string) []byte {
	return []byte("[Service]\nSupplementaryGroups=sandbar\nExecReload=\nExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force --address " + strconv.Quote(address) + "\n")
}

func applySetup(p paths, options setupOptions, account *user.User, source, routes, globals []byte, composition installedComposition, expected []setupSnapshot, prior serviceState, migration *legacyMigration, out, errOut io.Writer) (result error) {
	i := p.installed
	backupDir, err := os.MkdirTemp("/var/backups", "sandbar-setup-")
	if err != nil {
		return err
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		return err
	}
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	originalInputs, err := captureSetupInputs(composition.Manifest, i)
	if err != nil {
		return err
	}
	undo := setupUndo{Dir: backupDir, Prior: prior, Expected: expected}
	if migration != nil {
		undo.LegacyRestart = migration.RestartCommand
	}
	if err := undo.save(); err != nil {
		return err
	}
	fmt.Fprintln(out, "Setup backup:", backupDir)
	groupCreated := false
	membershipAdded := []string{}
	legacyStopped := false
	serviceChanged := false
	defer func() {
		if result == nil {
			return
		}
		rollbackErr := undo.restore()
		if serviceChanged {
			_, reloadErr := systemOutput("/usr/bin/systemctl", "daemon-reload")
			rollbackErr = errors.Join(rollbackErr, reloadErr)
			if prior.Boot != "enabled" {
				_, err := systemOutput("/usr/bin/systemctl", "disable", i.Unit)
				rollbackErr = errors.Join(rollbackErr, err)
			}
			if prior.State == "active" {
				_, err := systemOutput("/usr/bin/systemctl", "restart", i.Unit)
				rollbackErr = errors.Join(rollbackErr, err)
			} else {
				rollbackErr = errors.Join(rollbackErr, i.Service.Control("stop", out, errOut))
			}
		}
		if legacyStopped {
			rollbackErr = errors.Join(rollbackErr, migration.restart(out, errOut))
		}
		for _, member := range membershipAdded {
			_, err := systemOutput("/usr/bin/gpasswd", "-d", member, "sandbar")
			rollbackErr = errors.Join(rollbackErr, err)
		}
		if groupCreated {
			_, err := systemOutput("/usr/sbin/groupdel", "sandbar")
			rollbackErr = errors.Join(rollbackErr, err)
		}
		result = errors.Join(result, rollbackErr, fmt.Errorf("setup failed; inspect services and restore from %s/backup.json; legacy restart: %s", backupDir, undo.LegacyRestart))
	}()
	if i.GroupID < 0 {
		if _, err := systemOutput("/usr/sbin/groupadd", "--system", "sandbar"); err != nil {
			return err
		}
		groupCreated = true
		group, err := user.LookupGroup("sandbar")
		if err != nil {
			return err
		}
		i.GroupID, err = strconv.Atoi(group.Gid)
		if err != nil {
			return err
		}
	}
	for _, member := range []string{account.Username, i.Account} {
		memberAccount, err := user.Lookup(member)
		if err != nil {
			return err
		}
		groups, err := memberAccount.GroupIds()
		if err != nil {
			return err
		}
		found := false
		for _, group := range groups {
			if group == strconv.Itoa(i.GroupID) {
				found = true
			}
		}
		if !found {
			if _, err := systemOutput("/usr/sbin/usermod", "-a", "-G", "sandbar", member); err != nil {
				return err
			}
			membershipAdded = append(membershipAdded, member)
		}
	}

	for _, dir := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{filepath.Dir(p.config), 0770 | os.ModeSetgid, 0, i.GroupID}, {p.state, 0750 | os.ModeSetgid, 0, i.GroupID},
		{p.file("work"), 0770 | os.ModeSetgid, 0, i.GroupID}, {p.file("routes"), 0770 | os.ModeSetgid, 0, i.GroupID}, {p.file("validation"), 0770 | os.ModeSetgid, 0, i.GroupID},
		{p.file("admin"), 0750 | os.ModeSetgid, i.UID, i.GroupID},
	} {
		if err := undo.directory(dir.path, dir.mode, dir.uid, dir.gid); err != nil {
			return err
		}
	}
	for _, dir := range []string{"/etc/systemd/system/caddy.service.d", "/etc/polkit-1/rules.d", "/etc/sudoers.d", "/etc/caddy"} {
		if err := ensureProtectedDirectory(dir, &undo); err != nil {
			return err
		}
	}
	lock, err := os.OpenFile(p.file("router.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0660)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.Chmod(0660); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	// Refuse policy conflicts rather than overwrite an administrator's changes.
	address, _ := p.adminAddress()
	policies := setupPolicies(address)
	if err := checkSetupPolicies(policies); err != nil {
		return err
	}

	ruleCandidate := filepath.Join(backupDir, "sudoers.candidate")
	if err := atomicWriteMode(ruleCandidate, []byte(validationRule), 0440, 0, 0); err != nil {
		return err
	}
	if _, err := systemOutput("/usr/sbin/visudo", "-c", "-f", ruleCandidate); err != nil {
		return err
	}
	if migration != nil {
		if err := migration.copyAuthority(i, &undo); err != nil {
			return err
		}
	}

	if err := undo.write(p.file("validation/Caddyfile"), composition.Candidate, 0660, 0, i.GroupID); err != nil {
		return err
	}
	cfg, err := decodeConfig(bytes.NewReader(source))
	if err != nil {
		return err
	}
	if err := checkSelectedCaddy(p, caddyEnv(p), errOut); err != nil {
		return err
	}
	adapted, err := adaptCaddyfile(p, p.file("validation/Caddyfile"), errOut)
	if err != nil {
		return err
	}
	if err := checkInstalledAdapted(adapted, cfg, address); err != nil {
		return err
	}
	if err := i.Service.Validate(out, errOut); err != nil {
		return err
	}
	if err := verifyInputManifest(originalInputs); err != nil {
		return err
	}
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	if err := undo.write(i.Globals, globals, 0644, 0, 0); err != nil {
		return err
	}
	if err := undo.write(p.generatedPath(), routes, 0660, 0, i.GroupID); err != nil {
		return err
	}
	if err := verifyInputManifest(originalInputs); err != nil {
		return err
	}
	// Candidate parsing and provisioning finish before the legacy router stops.
	if migration != nil {
		if err := migration.stop(out, errOut); err != nil {
			return err
		}
		legacyStopped = true
	}
	for _, policy := range policies {
		if err := undo.write(policy.path, policy.data, policy.mode, 0, 0); err != nil {
			return err
		}
	}
	if err := undo.write(i.Config, composition.Top, 0644, 0, 0); err != nil {
		return err
	}
	if err := undo.write(p.config, source, 0660, 0, i.GroupID); err != nil {
		return err
	}
	if _, err := systemOutput("/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	serviceChanged = true
	if _, err := systemOutput("/usr/bin/systemctl", "enable", i.Unit); err != nil {
		return err
	}
	if prior.State == "active" {
		if _, err := systemOutput("/usr/bin/systemctl", "restart", i.Unit); err != nil {
			return err
		}
	} else if err := i.Service.Control("start", out, errOut); err != nil {
		return err
	}
	if err := exportServiceRoot(p, &undo); err != nil {
		return err
	}
	if migration != nil {
		if err := migration.verifyRoot(p.rootCertificate()); err != nil {
			return err
		}
	}
	if err := verifySetupRoutes(p, cfg); err != nil {
		return err
	}
	_, manifest, err := stageInstalledCandidate(i.Config, i.Globals, p.generatedPath(), routes)
	if err != nil {
		return err
	}
	record := setupRecord{Identity: i.identity(), Manifest: manifest}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if err := undo.write(p.file("setup.json"), append(data, '\n'), 0640, 0, i.GroupID); err != nil {
		return err
	}
	if migration != nil {
		if err := migration.retire(); err != nil {
			return err
		}
	}
	fmt.Fprintln(out, "Setup complete. Start a new login session, then run sandbar status.")
	fmt.Fprintln(out, "Welcome:", cfg.routeURL("sandbar.localhost"))
	return nil
}
func ensureProtectedDirectory(path string, undo *setupUndo) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return undo.directory(path, 0755, 0, 0)
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&0022 != 0 || stat.Uid != 0 {
		return fmt.Errorf("setup requires root-owned protected directory: %s", path)
	}
	return nil
}

type setupPolicy struct {
	path string
	data []byte
	mode os.FileMode
}

func setupPolicies(address string) []setupPolicy {
	return []setupPolicy{
		{"/etc/polkit-1/rules.d/50-sandbar.rules", []byte(polkitRule), 0644},
		{"/etc/sudoers.d/sandbar-caddy-validate", []byte(validationRule), 0440},
		{"/etc/systemd/system/caddy.service.d/sandbar.conf", serviceDropIn(address), 0644},
	}
}
func checkSetupPolicies(policies []setupPolicy) error {
	for _, policy := range policies {
		info, err := os.Lstat(policy.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || fileAccessMode(info.Mode()) != policy.mode {
			return fmt.Errorf("setup policy ownership or permission conflict: %s", policy.path)
		}
		data, err := os.ReadFile(policy.path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, policy.data) {
			return fmt.Errorf("setup policy conflict: %s", policy.path)
		}
	}
	return nil
}

func appendOptional(data []byte) []byte {
	if data == nil {
		return nil
	}
	return append([]byte{}, data...)
}

func verifySetupRoutes(p paths, c config) error {
	return verifySetupSites(p, c, append([]route{{Hostname: "sandbar.localhost"}}, c.Routes...))
}

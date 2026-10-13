package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type setupOptions struct{ Check, ReplaceDefault bool }

func setup(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	var options setupOptions
	flags.BoolVar(&options.Check, "check", false, "preview setup")
	flags.BoolVar(&options.ReplaceDefault, "replace-default-site", false, "replace Caddy's stock welcome site")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup accepts flags only; use sandbar setup --help")
	}
	i, err := inspectInstallation()
	if err != nil {
		return err
	}
	return setupDarwin(installedPaths(i), options, out, errOut, verifyDarwinSetupRoutes)
}

// The route verifier is replaced only by setup tests whose service commands are simulated.
func setupDarwin(p paths, options setupOptions, out, errOut io.Writer, verify func(paths, config) error) error {
	i := p.installed
	if err := checkSelectedCaddy(p, caddyEnv(p), errOut); err != nil {
		return err
	}
	top, err := readOptional(i.Config)
	if err != nil {
		return err
	}
	source, err := readOptional(p.config)
	if err != nil {
		return err
	}
	cfg := config{Version: 2, HTTPPort: 80, HTTPSPort: 443, Routes: []route{}}
	if source != nil {
		cfg, err = decodeConfig(bytes.NewReader(source))
		if err != nil {
			return err
		}
	} else {
		source, err = configBytes(cfg)
		if err != nil {
			return err
		}
	}
	expected := []setupSnapshot{}
	for _, path := range []string{i.Config, p.config, p.generatedPath(), i.Globals} {
		data, err := readOptional(path)
		if err != nil {
			return err
		}
		expected = append(expected, setupSnapshot{Path: path, Data: data})
	}
	if err := checkSetupSnapshots(expected); err != nil {
		return err
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
	globals := []byte(renderInstalledGlobals(address, "", ""))
	composition, err := composeInstalledConfig(i.Config, top, i.Globals, p.generatedPath(), globals, []byte(routes), options.ReplaceDefault || options.Check)
	if err != nil {
		return err
	}
	prior, err := i.Service.Inspect()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Integration:", i.ID)
	fmt.Fprintln(out, "Caddy:", i.Binary, "as", i.Account, "through", i.Unit)
	fmt.Fprintln(out, "Configuration:", p.config)
	fmt.Fprintln(out, "Caddy imports:", i.Config, "and", i.Globals)
	if top == nil {
		fmt.Fprintln(out, "Create missing Caddyfile:", i.Config)
	}
	fmt.Fprintln(out, "Routes:", p.generatedPath())
	fmt.Fprintln(out, "Admin socket:", p.file("admin.sock"))
	fmt.Fprintln(out, "Login startup:", prior.Boot, "→ register and start the Homebrew user service")
	fmt.Fprintln(out, "Backups:", p.file("backups"))
	if prior.State == "active" {
		fmt.Fprintln(out, "Service action: one setup stop/start to load the private admin endpoint")
	}
	if composition.StockReplaced {
		fmt.Fprintln(out, "Stock welcome site: offer backup and replacement with --replace-default-site")
	}
	fmt.Fprintln(out, "Welcome:", cfg.routeURL("sandbar.localhost"))
	fmt.Fprintln(out, "Trust is separate: sandbar trust. Caddy starts at login, after user login.")
	if options.Check {
		return nil
	}
	return applyDarwinSetup(p, cfg, source, []byte(routes), globals, composition, expected, prior, out, errOut, verify)
}

func applyDarwinSetup(p paths, cfg config, source, routes, globals []byte, composition installedComposition, expected []setupSnapshot, prior serviceState, out, errOut io.Writer, verify func(paths, config) error) (result error) {
	i := p.installed
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	inputs, err := captureSetupInputs(composition.Manifest, i)
	if err != nil {
		return err
	}
	for _, path := range []string{filepath.Dir(p.config), p.state, p.file("backups")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			return err
		}
	}
	backupDir, err := os.MkdirTemp(p.file("backups"), "setup-")
	if err != nil {
		return err
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		return err
	}
	undo := setupUndo{Dir: backupDir, Prior: prior, Expected: expected}
	if err := undo.save(); err != nil {
		return err
	}
	fmt.Fprintln(out, "Setup backup:", backupDir)
	serviceChanged := false
	defer func() {
		if result == nil {
			return
		}
		rollbackErr := undo.restore()
		if serviceChanged {
			rollbackErr = errors.Join(rollbackErr, restoreDarwinService(i.Service, prior, out, errOut))
		}
		result = errors.Join(result, rollbackErr, fmt.Errorf("setup failed; inspect service state and backups at %s/backup.json", backupDir))
	}()
	for _, path := range []string{filepath.Dir(p.config), p.state, p.file("backups"), p.workDir(), p.file("routes"), p.file("admin"), p.file("validation")} {
		if err := undo.directory(path, 0700, i.UID, i.GID); err != nil {
			return err
		}
	}
	lock, err := os.OpenFile(p.file("router.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := lock.Chmod(0600); err != nil {
		return err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	if err := undo.write(p.file("validation/Caddyfile"), composition.Candidate, 0600, -1, -1); err != nil {
		return err
	}
	adapted, err := adaptCaddyfile(p, p.file("validation/Caddyfile"), errOut)
	if err != nil {
		return err
	}
	address, err := p.adminAddress()
	if err != nil {
		return err
	}
	if err := checkInstalledAdapted(adapted, cfg, address); err != nil {
		return err
	}
	if err := i.Service.Validate(out, errOut); err != nil {
		return err
	}
	if err := verifyInputManifest(inputs); err != nil {
		return err
	}
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	for _, file := range []struct {
		path string
		data []byte
	}{{i.Globals, globals}, {p.generatedPath(), routes}, {i.Config, composition.Top}, {p.config, source}} {
		if err := undo.write(file.path, file.data, 0600, -1, -1); err != nil {
			return err
		}
	}
	serviceChanged = true
	if prior.State == "active" {
		if err := i.Service.Control("stop", out, errOut); err != nil {
			return err
		}
	}
	if err := i.Service.Control("start", out, errOut); err != nil {
		return err
	}
	if err := exportServiceRoot(p, &undo); err != nil {
		return err
	}
	if err := verify(p, cfg); err != nil {
		return err
	}
	_, manifest, err := stageInstalledCandidate(i.Config, i.Globals, p.generatedPath(), routes)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(setupRecord{Identity: i.identity(), Manifest: manifest}, "", "  ")
	if err != nil {
		return err
	}
	if err := undo.write(p.file("setup.json"), append(data, '\n'), 0600, -1, -1); err != nil {
		return err
	}
	fmt.Fprintln(out, "Setup complete. Run sandbar status.")
	fmt.Fprintln(out, "Welcome:", cfg.routeURL("sandbar.localhost"))
	return nil
}

func restoreDarwinService(service serviceOperations, prior serviceState, out, errOut io.Writer) error {
	if prior.State == "active" {
		if prior.Boot == "enabled" {
			return errors.Join(service.Control("start", out, errOut), service.Control("reload", out, errOut))
		}
		if err := service.Control("stop", out, errOut); err != nil {
			return err
		}
		return service.Control("run", out, errOut)
	}
	if prior.Boot == "enabled" {
		if err := service.Control("start", out, errOut); err != nil {
			return err
		}
		return service.Control("kill", out, errOut)
	}
	return service.Control("stop", out, errOut)
}

func verifyDarwinSetupRoutes(p paths, c config) error {
	if err := waitForInstalledStartup(p, c); err != nil {
		return err
	}
	return verifySetupSites(p, c, c.Routes)
}

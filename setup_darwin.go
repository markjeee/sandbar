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
	"strconv"
	"strings"
	"syscall"
)

type setupOptions struct {
	Check, ReplaceDefault bool
	HTTPPort, HTTPSPort   *int
}

func setup(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	var options setupOptions
	flags.BoolVar(&options.Check, "check", false, "preview setup")
	flags.BoolVar(&options.ReplaceDefault, "replace-default-site", false, "replace Caddy's stock welcome site")
	httpPort := flags.Int("http-port", 80, "HTTP redirect port")
	httpsPort := flags.Int("https-port", 443, "HTTPS port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("setup accepts flags only; use sandbar setup --help")
	}
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "http-port":
			options.HTTPPort = httpPort
		case "https-port":
			options.HTTPSPort = httpsPort
		}
	})
	i, err := inspectInstallation()
	if err != nil {
		return err
	}
	return setupDarwin(installedPaths(i), options, out, errOut, verifyDarwinSetupRoutes)
}

// The route verifier is replaced only by setup tests whose service commands are simulated.
func setupDarwin(p paths, options setupOptions, out, errOut io.Writer, verify func(paths, config) error) error {
	i := p.installed
	priorService := i.Service
	if i.ID == sandbarLaunchdID {
		cli, err := os.Executable()
		if err != nil {
			return err
		}
		cli, err = filepath.EvalSymlinks(cli)
		if err != nil {
			return err
		}
		selected := *i
		selected.CLI = cli
		if service, ok := priorService.(*launchdService); ok {
			selected.Service = &launchdService{installation: &selected, old: service.old}
			p = installedPaths(&selected)
			i = &selected
		}
	}
	if i.ID == "homebrew-launchd-v1" {
		cli, err := os.Executable()
		if err != nil {
			return err
		}
		cli, err = filepath.EvalSymlinks(cli)
		if err != nil {
			return err
		}
		selected := newLaunchdInstallation(i, cli)
		selected.Service = &launchdService{installation: selected, old: i.Service.(*homebrewService)}
		if err := checkNewLaunchdTarget(selected); err != nil {
			return err
		}
		p = installedPaths(selected)
		i = selected
	}
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
	}
	if options.HTTPPort != nil {
		cfg.HTTPPort = *options.HTTPPort
	}
	if options.HTTPSPort != nil {
		cfg.HTTPSPort = *options.HTTPSPort
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	if source == nil || options.HTTPPort != nil || options.HTTPSPort != nil {
		source, err = configBytes(cfg)
		if err != nil {
			return err
		}
	}
	expected := []setupSnapshot{}
	for _, path := range []string{i.Config, p.config, p.generatedPath(), i.Globals, p.file("setup.json"), launchdTemplate(i), i.Fragment} {
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
	globals, err := renderDarwinGlobals(p, cfg, top, address)
	if err != nil {
		return err
	}
	composition, err := composeInstalledConfig(i.Config, top, i.Globals, p.generatedPath(), globals, []byte(routes), options.ReplaceDefault || options.Check)
	if err != nil {
		return err
	}
	prior, err := priorService.Inspect()
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
	fmt.Fprintln(out, "Ports: HTTP", cfg.HTTPPort, "HTTPS", cfg.HTTPSPort)
	fmt.Fprintln(out, "Routes:", p.generatedPath())
	fmt.Fprintln(out, "Admin socket:", p.file("admin.sock"))
	fmt.Fprintln(out, "Login startup:", prior.Boot, "→ register and start the Sandbar user LaunchAgent")
	if i.ID == sandbarLaunchdID {
		fmt.Fprintln(out, "Service ownership: sh.brew.caddy →", i.Unit)
		fmt.Fprintln(out, "Sandbar executable:", i.CLI)
		fmt.Fprintln(out, "Job template:", launchdTemplate(i))
		fmt.Fprintln(out, "Login copy:", i.Fragment)
		fmt.Fprintln(out, "Sockets: HTTP TCP", cfg.HTTPPort, "HTTPS TCP/UDP", cfg.HTTPSPort, "IPv6", ipv6)
		fmt.Fprintln(out, "Retained Caddy storage:", i.Storage)
	}
	fmt.Fprintln(out, "Backups:", p.file("backups"))
	if prior.State == "active" || prior.State == "failed" {
		fmt.Fprintln(out, "Service action: one setup stop/start to replace the active or failed job")
	}
	if composition.StockReplaced {
		fmt.Fprintln(out, "Stock welcome site: offer backup and replacement with --replace-default-site")
	}
	fmt.Fprintln(out, "Welcome:", cfg.routeURL("sandbar.localhost"))
	fmt.Fprintln(out, "Trust is separate: sandbar trust. Caddy starts at login, after user login.")
	if options.Check {
		return validateDarwinPreview(p, cfg, composition.Candidate, socketPlan{HTTPPort: cfg.HTTPPort, HTTPSPort: cfg.HTTPSPort, IPv6: ipv6}, out, errOut)
	}
	return applyDarwinSetup(p, cfg, source, []byte(routes), globals, composition, expected, prior, priorService, socketPlan{HTTPPort: cfg.HTTPPort, HTTPSPort: cfg.HTTPSPort, IPv6: ipv6}, out, errOut, verify)
}

func applyDarwinSetup(p paths, cfg config, source, routes, globals []byte, composition installedComposition, expected []setupSnapshot, prior serviceState, priorService serviceOperations, plan socketPlan, out, errOut io.Writer, verify func(paths, config) error) (result error) {
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
	priorInstallation := i
	switch service := priorService.(type) {
	case *homebrewService:
		priorInstallation = service.installation
	case *launchdService:
		priorInstallation = service.installation
	}
	undo.PriorInstallation = priorInstallation.identity()
	if info, err := os.Lstat(priorInstallation.Fragment); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("setup refuses non-regular service job: %s", priorInstallation.Fragment)
		}
		data, err := os.ReadFile(priorInstallation.Fragment)
		if err != nil {
			return err
		}
		stat := info.Sys().(*syscall.Stat_t)
		undo.PriorJob = &setupBackup{Path: priorInstallation.Fragment, Data: data, Mode: fileAccessMode(info.Mode()), UID: int(stat.Uid), GID: int(stat.Gid)}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := undo.save(); err != nil {
		return err
	}
	fmt.Fprintln(out, "Setup backup:", backupDir)
	serviceChanged := false
	defer func() {
		if result == nil {
			return
		}
		var rollbackErr error
		if serviceChanged && i.ID == sandbarLaunchdID {
			rollbackErr = unloadSetupLaunchd(i)
			if rollbackErr != nil {
				result = errors.Join(result, rollbackErr, fmt.Errorf("setup rollback cannot restore live service files; backups at %s", backupDir))
				return
			}
		}
		rollbackErr = undo.restore()
		if serviceChanged && rollbackErr == nil {
			rollbackErr = restoreDarwinService(priorService, prior, out, errOut)
		}
		result = errors.Join(result, rollbackErr, fmt.Errorf("setup failed; inspect service state and backups at %s/backup.json", backupDir))
	}()
	for _, path := range []string{filepath.Dir(p.config), p.state, p.file("backups"), p.workDir(), p.file("routes"), p.file("admin"), p.file("validation")} {
		if err := darwinSetupDirectory(&undo, path, i); err != nil {
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
	if i.ID == sandbarLaunchdID {
		runtime, err := convertSocketRuntime(adapted, plan)
		if err != nil {
			return err
		}
		if err := validateLaunchdRuntime(p, runtime, out, errOut); err != nil {
			return err
		}
	} else if err := i.Service.Validate(out, errOut); err != nil {
		return err
	}
	if err := verifyInputManifest(inputs); err != nil {
		return err
	}
	if err := checkSetupSnapshots(expected); err != nil {
		return err
	}
	serviceChanged = true
	if prior.State == "active" || prior.State == "failed" || prior.Boot == "enabled" {
		if _, ok := priorService.(*launchdService); ok {
			if err := unloadSetupLaunchd(i); err != nil {
				return err
			}
		} else {
			pid := ""
			if old, ok := priorService.(*homebrewService); ok {
				pid = loadedLaunchdPID(old.installation)
			}
			if err := priorService.Control("stop", out, errOut); err != nil {
				return err
			}
			if old, ok := priorService.(*homebrewService); ok {
				if err := waitLaunchdRemoval(old.installation, launchdShutdownLimit, pid); err != nil {
					return err
				}
			}
		}
	}
	for _, file := range []struct {
		path string
		data []byte
	}{{i.Globals, globals}, {p.generatedPath(), routes}, {i.Config, composition.Top}, {p.config, source}} {
		if err := undo.write(file.path, file.data, 0600, -1, -1); err != nil {
			return err
		}
	}
	_, manifest, err := stageInstalledCandidate(i.Config, i.Globals, p.generatedPath(), routes)
	if err != nil {
		return err
	}
	record := setupRecord{Identity: i.identity(), Manifest: manifest}
	if i.ID == sandbarLaunchdID {
		record.SocketPlan = &plan
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	if i.ID == sandbarLaunchdID {
		for _, dir := range []string{filepath.Dir(launchdTemplate(i)), filepath.Dir(i.Fragment)} {
			if err := darwinSetupDirectory(&undo, dir, i); err != nil {
				return err
			}
		}
		job, err := renderLaunchdJob(i, plan)
		if err != nil {
			return err
		}
		if err := undo.write(launchdTemplate(i), job, 0600, -1, -1); err != nil {
			return err
		}
		if err := undo.write(i.Fragment, job, 0600, -1, -1); err != nil {
			return err
		}
	}
	if err := undo.write(p.file("setup.json"), append(data, '\n'), 0600, -1, -1); err != nil {
		return err
	}
	if err := i.Service.Control("start", out, errOut); err != nil {
		return err
	}
	if _, err := readServiceRoot(p); err != nil {
		return err
	}
	if err := verify(p, cfg); err != nil {
		return err
	}
	fmt.Fprintln(out, "Setup complete. Run sandbar status.")
	fmt.Fprintln(out, "Welcome:", cfg.routeURL("sandbar.localhost"))
	return nil
}

func restoreDarwinService(service serviceOperations, prior serviceState, out, errOut io.Writer) error {
	if selected, ok := service.(*launchdService); ok {
		// Undo already restored the prior login copy. Bootstrap the private template
		// only if a job existed, including a job without login registration.
		state, err := selected.Inspect()
		if err != nil {
			return err
		}
		if prior.State != "active" && prior.State != "failed" {
			return nil
		}
		if state.Sockets != "released" {
			return errors.New("cannot restore the prior launchd job while another job is loaded")
		}
		if err := launchdControl("bootstrap", launchdDomain(selected.installation), launchdTemplate(selected.installation)); err != nil {
			return err
		}
		return nil
	}
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

// Existing matching global port settings remain outside Sandbar's owned fragment.
func renderDarwinGlobals(p paths, c config, top []byte, address string) ([]byte, error) {
	globals := renderInstalledGlobals(c, address, "", "")
	clean, err := stripOwnedMarker(top, globalMarkerStart, globalMarkerEnd)
	if err != nil {
		return nil, err
	}
	clean, err = stripOwnedMarker(clean, routesMarkerStart, routesMarkerEnd)
	if err != nil {
		return nil, err
	}
	expanded, _, err := composeCandidate(p.installed.Config, clean, map[string][]byte{filepath.Clean(p.installed.Config): clean}, p.generatedPath())
	if err != nil {
		return nil, err
	}
	tokens, err := scanCaddyfile(expanded)
	if err != nil {
		return nil, err
	}
	for n, token := range tokens {
		if token.depth != 1 || (token.text != "http_port" && token.text != "https_port") {
			continue
		}
		selected := c.HTTPPort
		if token.text == "https_port" {
			selected = c.HTTPSPort
		}
		if n+1 >= len(tokens) || tokens[n+1].line != token.line {
			return nil, fmt.Errorf("the existing Caddy %s is invalid", token.text)
		}
		value, err := strconv.Atoi(tokens[n+1].text)
		if err != nil || value != selected {
			return nil, fmt.Errorf("the existing Caddy %s conflicts with selected port %d; review the shared Caddy configuration", token.text, selected)
		}
		globals = strings.Replace(globals, fmt.Sprintf("%s %d\n", token.text, selected), "", 1)
	}
	return []byte(globals), nil
}

func validateDarwinPreview(p paths, c config, candidate []byte, plan socketPlan, out, errOut io.Writer) error {
	file, err := os.CreateTemp("", "sandbar-setup-preview-*.Caddyfile")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(candidate); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	data, err := adaptCaddyfile(p, file.Name(), errOut)
	if err != nil {
		return err
	}
	address, err := p.adminAddress()
	if err != nil {
		return err
	}
	if err := checkInstalledAdapted(data, c, address); err != nil {
		return err
	}
	if p.installed.ID == sandbarLaunchdID {
		data, err = convertSocketRuntime(data, plan)
		if err != nil {
			return err
		}
	}
	// Validation can create a CA. Keep preview state in temporary storage.
	scratch, err := os.MkdirTemp("", "sandbar-preview-storage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(scratch)
	env := append([]string{}, caddyEnv(p)...)
	for n, item := range env {
		if strings.HasPrefix(item, "HOME=") {
			env[n] = "HOME=" + scratch
		}
		if strings.HasPrefix(item, "XDG_DATA_HOME=") {
			env[n] = "XDG_DATA_HOME=" + scratch
		}
	}
	return invokeSelectedCaddy(p, env, bytes.NewReader(data), out, errOut, "validate", "--config", "-")
}
func unloadSetupLaunchd(i *installation) error {
	_, err := launchdOutput("/bin/launchctl", "print", launchdTarget(i))
	if err != nil {
		if launchdJobMissing(err, i.Unit) {
			return nil
		}
		return err
	}
	pid := loadedLaunchdPID(i)
	if err := launchdControl("bootout", launchdTarget(i)); err != nil {
		return err
	}
	return waitLaunchdRemoval(i, launchdShutdownLimit, pid)
}

func darwinSetupDirectory(undo *setupUndo, path string, i *installation) error {
	gid := i.GID
	if info, err := os.Lstat(path); err == nil {
		gid = int(info.Sys().(*syscall.Stat_t).Gid)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// macOS private directories need no group transfer. Preserve existing groups.
	return undo.directory(path, 0700, i.UID, gid)
}

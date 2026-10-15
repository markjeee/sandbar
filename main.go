package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"syscall"
)

var version = "development"

func main() {
	// Private development files and Caddy subprocesses use a restrictive mask.
	// Installed shared files set their group permissions explicitly.
	syscall.Umask(0077)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	if err := execute(args, out, errOut); err != nil {
		fmt.Fprintf(errOut, "sandbar: %v\n", err)
		var result *caddyError
		if errors.As(err, &result) {
			return result.code
		}
		return 1
	}
	return 0
}

func execute(args []string, out, errOut io.Writer) error {
	if len(args) > 0 && args[0] == "_uninstall-system" {
		return uninstallSystem(args[1:], out, errOut)
	}
	if len(args) > 0 && args[0] == "_launchd-caddy" {
		return launchdCaddyBridge(args[1:], errOut)
	}
	flags := flag.NewFlagSet("sandbar", flag.ContinueOnError)
	flags.SetOutput(errOut)
	home := flags.String("home", os.Getenv("SANDBAR_HOME"), "private Sandbar home")
	showVersion := flags.Bool("version", false, "show version")
	flags.Usage = func() { fmt.Fprint(out, topLevelHelp()) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		if flags.NArg() != 0 {
			return errors.New("--version accepts no command")
		}
		fmt.Fprintln(out, "sandbar", version)
		return nil
	}
	if flags.NArg() == 0 || flags.Arg(0) == "help" {
		fmt.Fprint(out, topLevelHelp())
		return nil
	}
	command, rest := flags.Arg(0), flags.Args()[1:]
	if command != "init" && command != "start" && command != "stop" && command != "trust" && command != "untrust" && command != "add" && command != "rm" && command != "ls" && command != "reload" && command != "status" && command != "setup" && command != "teleport" && command != "config" && command != "doctor" && command != "uninstall" {
		return fmt.Errorf("unknown command %q (use --help)", command)
	}
	if command == "teleport" && commandHelpRequested(rest) {
		fmt.Fprint(out, teleportHelp(rest))
		return nil
	}
	if command != "teleport" && commandHelpRequested(rest) {
		text, _ := helpText(command)
		fmt.Fprint(out, text)
		return nil
	}
	homeFlag := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "home" {
			homeFlag = true
		}
	})
	if homeFlag && *home == "" {
		return errors.New("--home requires a directory")
	}
	if command == "config" {
		return inspectConfig(*home, rest, out, errOut)
	}
	if command == "doctor" {
		if len(rest) != 0 {
			return errors.New("doctor accepts no arguments")
		}
		return doctor(*home, out, errOut)
	}
	if command == "uninstall" {
		if homeFlag || *home != "" {
			return errors.New("uninstall does not accept --home or SANDBAR_HOME")
		}
		return uninstall(rest, out, errOut)
	}
	if command == "setup" {
		if homeFlag || *home != "" {
			return errors.New("setup does not accept --home or SANDBAR_HOME")
		}
		return setup(rest, out, errOut)
	}
	if command != "init" && command != "add" && command != "rm" && command != "teleport" && len(rest) != 0 {
		return fmt.Errorf("%s accepts no arguments", command)
	}
	paths, err := resolvePaths(*home)
	if err != nil {
		return err
	}
	if paths.installed != nil && paths.installed.ID == "homebrew-launchd-v1" {
		switch command {
		case "init", "start", "add", "rm", "reload", "teleport":
			return errors.New("migrate the Homebrew Caddy service with sandbar setup before changing installed routes or starting Caddy")
		}
	}
	if command == "teleport" {
		return executeTeleport(paths, rest, out, errOut)
	}
	if command == "init" {
		return initialize(paths, rest, out, errOut)
	}
	if command == "status" {
		return status(paths, out, errOut)
	}
	return withLock(paths, func() error {
		switch command {
		case "start":
			return start(paths, out, errOut)
		case "add", "rm", "reload":
			return changeRoutes(paths, command, rest, out, errOut)
		case "ls":
			return listRoutes(paths, out)
		case "stop":
			return stop(paths, out, errOut)
		default:
			return changeTrust(paths, command, out, errOut)
		}
	})
}

func initialize(paths paths, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(errOut)
	httpPort := flags.Int("http-port", 80, "HTTP redirect port")
	httpsPort := flags.Int("https-port", 443, "HTTPS port")
	machine := flags.String("machine", "", "stable machine name")
	flags.Usage = func() { text, _ := helpText("init"); fmt.Fprint(out, text) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 && flags.NArg() != 2 {
		return errors.New("init accepts either no arguments or a hostname and upstream (use --help)")
	}
	httpSet, httpsSet, machineSet := false, false, false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "machine":
			machineSet = true
		case "http-port":
			httpSet = true
		case "https-port":
			httpsSet = true
		}
	})
	if machineSet && *machine == "" {
		return errors.New("--machine requires a DNS label")
	}
	return withLock(paths, func() error {
		if err := recoverTransaction(paths, errOut); err != nil {
			return err
		}
		previous, err := readOptional(paths.config)
		if err != nil {
			return err
		}
		cfg := config{Version: 2, HTTPPort: *httpPort, HTTPSPort: *httpsPort, Routes: []route{}}
		if previous != nil {
			existing, err := decodeConfig(bytes.NewReader(previous))
			if err != nil {
				return err
			}
			if httpSet && *httpPort != existing.HTTPPort || httpsSet && *httpsPort != existing.HTTPSPort {
				if paths.installed != nil && customInstalledPorts {
					return errors.New("change installed macOS ports with sandbar setup --http-port <port> --https-port <port>")
				}
				return fmt.Errorf("configuration already exists with different settings: %s", paths.config)
			}
			cfg = existing
			if flags.NArg() == 2 {
				requested := config{Version: 2, HTTPPort: cfg.HTTPPort, HTTPSPort: cfg.HTTPSPort, Routes: []route{{flags.Arg(0), flags.Arg(1)}}}
				if err := requested.validate(); err != nil {
					return err
				}
				if !reflect.DeepEqual(existing.Routes, requested.Routes) {
					return fmt.Errorf("configuration already exists with different settings: %s", paths.config)
				}
			}
			if paths.installed != nil && existing.Version < 3 {
				return errors.New("upgrade installed machine identity with sandbar setup")
			}
		} else if flags.NArg() == 2 {
			cfg.Routes = append(cfg.Routes, route{flags.Arg(0), flags.Arg(1)})
		}
		previousVersion := cfg.Version
		cfg, err = upgradeMachineConfig(cfg, *machine)
		if err != nil {
			return err
		}
		if paths.installed != nil && (!customInstalledPorts || previous == nil) && (cfg.HTTPPort != 80 || cfg.HTTPSPort != 443) {
			return errors.New("select installed ports with sandbar setup; use --home for development ports")
		}
		if previous != nil {
			if previousVersion == 3 {
				fmt.Fprintln(out, "Configuration already exists:", paths.config)
				return nil
			}
			if err := publishConfig(paths, previous, cfg, true, out, errOut); err != nil {
				return err
			}
			fmt.Fprintln(out, "Configuration upgraded:", paths.config)
			return nil
		}
		if err := createSelectedConfig(paths, cfg); err != nil {
			return err
		}
		fmt.Fprintln(out, "Configuration:", paths.config)
		return nil
	})
}

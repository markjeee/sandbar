package main

import (
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
	if command != "init" && command != "start" && command != "stop" && command != "trust" && command != "untrust" && command != "add" && command != "rm" && command != "ls" && command != "reload" && command != "status" && command != "setup" {
		return fmt.Errorf("unknown command %q (use --help)", command)
	}
	if commandHelpRequested(rest) {
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
	if command == "setup" {
		if homeFlag || *home != "" {
			return errors.New("setup does not accept --home or SANDBAR_HOME")
		}
		return setup(rest, out, errOut)
	}
	if command != "init" && command != "add" && command != "rm" && len(rest) != 0 {
		return fmt.Errorf("%s accepts no arguments", command)
	}
	paths, err := resolvePaths(*home)
	if err != nil {
		return err
	}
	if paths.installed != nil && paths.installed.ID == "homebrew-launchd-v1" {
		switch command {
		case "init", "start", "add", "rm", "reload":
			return errors.New("migrate the Homebrew Caddy service with sandbar setup before changing installed routes or starting Caddy")
		}
	}
	if command == "init" {
		return initialize(paths, rest, out, errOut)
	}
	return withLock(paths, func() error {
		switch command {
		case "start":
			return start(paths, out, errOut)
		case "add", "rm", "reload":
			return changeRoutes(paths, command, rest, out, errOut)
		case "ls":
			return listRoutes(paths, out)
		case "status":
			return status(paths, out, errOut)
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
	flags.Usage = func() { fmt.Fprint(out, topLevelHelp()) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 && flags.NArg() != 2 {
		return errors.New("init accepts either no arguments or a hostname and upstream (use --help)")
	}
	cfg := config{Version: 2, HTTPPort: *httpPort, HTTPSPort: *httpsPort, Routes: []route{}}
	if flags.NArg() == 2 {
		cfg.Routes = append(cfg.Routes, route{flags.Arg(0), flags.Arg(1)})
	}
	if paths.installed == nil || !customInstalledPorts {
		if err := cfg.validate(); err != nil {
			return err
		}
	}
	if paths.installed != nil && !customInstalledPorts && (cfg.HTTPPort != 80 || cfg.HTTPSPort != 443) {
		return errors.New("installed Sandbar uses ports 80 and 443; use --home for development ports")
	}
	return withLock(paths, func() error {
		if err := recoverTransaction(paths, errOut); err != nil {
			return err
		}
		existing, err := readConfig(paths.config)
		if err == nil {
			if paths.installed != nil && customInstalledPorts {
				conflict := false
				flags.Visit(func(f *flag.Flag) {
					switch f.Name {
					case "http-port":
						conflict = conflict || cfg.HTTPPort != existing.HTTPPort
					case "https-port":
						conflict = conflict || cfg.HTTPSPort != existing.HTTPSPort
					}
				})
				if conflict {
					return errors.New("change installed macOS ports with sandbar setup --http-port <port> --https-port <port>")
				}
				cfg.HTTPPort, cfg.HTTPSPort = existing.HTTPPort, existing.HTTPSPort
				if err := cfg.validate(); err != nil {
					return err
				}
			}
			if existing.HTTPPort != cfg.HTTPPort || existing.HTTPSPort != cfg.HTTPSPort || !reflect.DeepEqual(existing.Routes, cfg.Routes) {
				return fmt.Errorf("configuration already exists with different settings: %s", paths.config)
			}
			fmt.Fprintln(out, "Configuration already exists:", paths.config)
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if paths.installed != nil && customInstalledPorts {
			if cfg.HTTPPort != 80 || cfg.HTTPSPort != 443 {
				return errors.New("select installed macOS ports with sandbar setup --http-port <port> --https-port <port>")
			}
			if err := cfg.validate(); err != nil {
				return err
			}
		}
		if err := createSelectedConfig(paths, cfg); err != nil {
			return err
		}
		fmt.Fprintln(out, "Configuration:", paths.config)
		return nil
	})
}

//go:build linux

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

const usage = `Sandbar serves local routes through Caddy on Linux.

Usage:
  sandbar [--home <directory>] init [--http-port <port>] [--https-port <port>] [<hostname> <upstream>]
  sandbar [--home <directory>] add [--replace] <hostname> <upstream>
  sandbar [--home <directory>] rm <hostname>
  sandbar [--home <directory>] ls
  sandbar [--home <directory>] reload
  sandbar [--home <directory>] status
  sandbar [--home <directory>] start
  sandbar [--home <directory>] stop
  sandbar [--home <directory>] trust
  sandbar [--home <directory>] untrust
  sandbar --version

Flags must precede positional arguments. Hostnames must be below sandbar.localhost.
HTTP port 80 redirects to HTTPS port 443 by default. Upstream ports must differ from router ports.
Use --http-port 8080 --https-port 8443 for a proof without low-port permissions.

Home precedence: --home, SANDBAR_HOME, then Linux XDG directories.
Init preserves existing config.json. Reload validates and applies source edits.
Add and rm apply live changes when Caddy runs. Upstreams must use loopback.
Start regenerates the Caddyfile. Do not edit the generated file.
Start and stop delegate to installed Caddy. Only Caddy stays running.
Lifecycle commands leave system DNS and certificate trust unchanged.
Trust and untrust select this home's CA, using the caller's trust stores.
Caddy can request elevated access. Command success does not verify browser trust.
See the browser guide for verification, manual import, and complete removal.
`

func main() {
	// This CLI has no concurrent file creation outside its own private state.
	// Caddy inherits this mask, including when it starts its background process.
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
	flags := flag.NewFlagSet("sandbar", flag.ContinueOnError)
	flags.SetOutput(errOut)
	home := flags.String("home", os.Getenv("SANDBAR_HOME"), "private Sandbar home")
	showVersion := flags.Bool("version", false, "show version")
	flags.Usage = func() { fmt.Fprint(out, usage) }
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
		fmt.Fprint(out, usage)
		return nil
	}
	command, rest := flags.Arg(0), flags.Args()[1:]
	if command != "init" && command != "start" && command != "stop" && command != "trust" && command != "untrust" && command != "add" && command != "rm" && command != "ls" && command != "reload" && command != "status" {
		return fmt.Errorf("unknown command %q (use --help)", command)
	}
	if command != "init" && command != "add" && command != "rm" && len(rest) != 0 {
		return fmt.Errorf("%s accepts no arguments", command)
	}
	paths, err := resolvePaths(*home)
	if err != nil {
		return err
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
	flags.Usage = func() { fmt.Fprint(out, usage) }
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
	if err := cfg.validate(); err != nil {
		return err
	}
	return withLock(paths, func() error {
		if err := recoverTransaction(paths, errOut); err != nil {
			return err
		}
		existing, err := readConfig(paths.config)
		if err == nil {
			if existing.HTTPPort != cfg.HTTPPort || existing.HTTPSPort != cfg.HTTPSPort || !reflect.DeepEqual(existing.Routes, cfg.Routes) {
				return fmt.Errorf("configuration already exists with different settings: %s", paths.config)
			}
			fmt.Fprintln(out, "Configuration already exists:", paths.config)
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := writeConfig(paths.config, cfg); err != nil {
			return err
		}
		fmt.Fprintln(out, "Configuration:", paths.config)
		return nil
	})
}

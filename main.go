//go:build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
)

var version = "development"

const usage = `Sandbar serves one local HTTP backend through Caddy on Linux.

Usage:
  sandbar [--home <directory>] init [--http-port <port>] [--https-port <port>] <hostname> <upstream-port>
  sandbar [--home <directory>] start
  sandbar [--home <directory>] stop
  sandbar --version

Flags must precede positional arguments. Hostnames must be below sandbar.localhost.
HTTP port 80 redirects to HTTPS port 443 by default. All three ports must differ.
Use --http-port 8080 --https-port 8443 for a proof without low-port permissions.

Home precedence: --home, SANDBAR_HOME, then Linux XDG directories.
Init preserves existing config.json. Edit that source file while stopped.
Start regenerates the Caddyfile. Do not edit the generated file.
Start and stop delegate to installed Caddy. Only Caddy stays running.
No system DNS or certificate trust changes are made.
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
	if command != "init" && command != "start" && command != "stop" {
		return fmt.Errorf("unknown command %q (use --help)", command)
	}
	if command != "init" && len(rest) != 0 {
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
		if command == "start" {
			return start(paths, out, errOut)
		}
		return stop(paths, out, errOut)
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
	if flags.NArg() != 2 {
		return errors.New("init requires a hostname and upstream port (use --help)")
	}
	upstream, err := strconv.Atoi(flags.Arg(1))
	if err != nil {
		return errors.New("upstream port must be an integer from 1 through 65535")
	}
	cfg := config{
		Version: 1, Hostname: flags.Arg(0), UpstreamPort: upstream,
		HTTPPort: *httpPort, HTTPSPort: *httpsPort,
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	return withLock(paths, func() error {
		existing, err := readConfig(paths.config)
		if err == nil {
			if existing != cfg {
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

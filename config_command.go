package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
)

// Source selection does not require installation or runtime discovery.
func sourceConfigPath(home string) (string, error) {
	if home != "" {
		absolute, err := filepath.Abs(home)
		if err != nil {
			return "", err
		}
		return filepath.Join(absolute, "config.json"), nil
	}
	switch {
	case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
		return "/etc/sandbar/config.json", nil
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		account, err := user.Current()
		if err != nil {
			return "", err
		}
		return filepath.Join(account.HomeDir, "Library/Application Support/sandbar/config.json"), nil
	default:
		return "", errors.New("installed mode supports Linux amd64 and macOS arm64; use --home for development")
	}
}

func inspectConfig(home string, args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("config", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.Bool("path", false, "show source path")
	print := flags.Bool("print", false, "print source bytes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *path == *print {
		return errors.New("config requires exactly one of --path or --print and no arguments (use --help)")
	}
	selected, err := sourceConfigPath(home)
	if err != nil {
		return err
	}
	if *path {
		_, err := fmt.Fprintln(out, selected)
		return err
	}
	file, err := os.Open(selected)
	if err != nil {
		return fmt.Errorf("read source configuration %s: %w", selected, err)
	}
	defer file.Close()
	if _, err := io.Copy(out, file); err != nil {
		return fmt.Errorf("print source configuration %s: %w", selected, err)
	}
	return nil
}

func selectedCommand(p paths, args ...string) string {
	command := "sandbar"
	if p.installed == nil {
		command += " --home " + quoteRemoteArg(filepath.Dir(p.config))
	}
	return command + " " + strings.Join(args, " ")
}

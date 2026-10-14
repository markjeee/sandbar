package main

import (
	"errors"
	"io"
)

func launchdCaddyBridge(_ []string, _ io.Writer) error {
	return errors.New("launchd socket activation requires macOS")
}

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

type config struct {
	Version      int    `json:"version"`
	Hostname     string `json:"hostname"`
	UpstreamPort int    `json:"upstream_port"`
	HTTPPort     int    `json:"http_port"`
	HTTPSPort    int    `json:"https_port"`
}

func (c *config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("unsupported configuration version %d (want 1)", c.Version)
	}
	for _, ch := range c.Hostname {
		if ch > 127 {
			return errors.New("hostname must contain only ASCII characters")
		}
	}
	c.Hostname = strings.ToLower(c.Hostname)
	if len(c.Hostname) > 253 || !strings.HasSuffix(c.Hostname, ".sandbar.localhost") {
		return errors.New("hostname must be an ASCII name below sandbar.localhost")
	}
	for _, label := range strings.Split(c.Hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname has an invalid DNS label")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errors.New("hostname may contain only ASCII letters, digits, hyphens, and label separators")
			}
		}
	}
	for _, port := range []struct {
		name  string
		value int
	}{
		{"upstream_port", c.UpstreamPort}, {"http_port", c.HTTPPort}, {"https_port", c.HTTPSPort},
	} {
		if port.value < 1 || port.value > 65535 {
			return fmt.Errorf("%s must be from 1 through 65535", port.name)
		}
	}
	if c.UpstreamPort == c.HTTPPort || c.UpstreamPort == c.HTTPSPort || c.HTTPPort == c.HTTPSPort {
		return errors.New("upstream_port, http_port, and https_port must differ")
	}
	return nil
}

func (c config) httpsURL() string {
	if c.HTTPSPort == 443 {
		return "https://" + c.Hostname
	}
	return fmt.Sprintf("https://%s:%d", c.Hostname, c.HTTPSPort)
}

func readConfig(path string) (config, error) {
	var c config
	file, err := os.Open(path)
	if err != nil {
		return c, fmt.Errorf("read configuration: %w", err)
	}
	defer file.Close()
	return decodeConfig(file)
}

func decodeConfig(input io.Reader) (config, error) {
	var c config
	decoder := json.NewDecoder(input)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("read configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return c, errors.New("configuration must contain exactly one JSON object")
	}
	if err := c.validate(); err != nil {
		return c, err
	}
	return c, nil
}

func writeConfig(path string, c config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create configuration: %w", err)
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}

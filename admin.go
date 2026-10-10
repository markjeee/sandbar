package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"syscall"
	"time"
)

func readActiveConfig(p paths) ([]byte, error) {
	if _, err := p.adminAddress(); err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p.file("admin.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get("http://localhost/config/")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("private admin endpoint returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if !json.Valid(data) {
		return nil, errors.New("private admin endpoint returned invalid configuration JSON")
	}
	return data, nil
}

func isRouterStopped(err error) bool {
	return errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED)
}

func jsonEqual(a, b []byte) bool {
	if !json.Valid(a) || !json.Valid(b) {
		return false
	}
	var left, right any
	da, db := json.NewDecoder(bytes.NewReader(a)), json.NewDecoder(bytes.NewReader(b))
	da.UseNumber()
	db.UseNumber()
	if da.Decode(&left) != nil || db.Decode(&right) != nil {
		return false
	}
	return reflect.DeepEqual(left, right)
}

func adaptCaddyfile(p paths, path string, errOut io.Writer) ([]byte, error) {
	var adapted bytes.Buffer
	if err := invokeSelectedCaddy(p, caddyEnv(p), nil, &adapted, errOut, "adapt", "--config", path, "--adapter", "caddyfile"); err != nil {
		return nil, err
	}
	if !json.Valid(adapted.Bytes()) {
		return nil, errors.New("caddy adapt returned invalid configuration JSON")
	}
	return adapted.Bytes(), nil
}

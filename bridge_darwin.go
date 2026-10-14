package main

/*
#include <launch.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type socketBinding struct {
	Group                  string
	FD, Family, Type, Port int
}

func socketBindings(plan socketPlan) []socketBinding {
	result := []socketBinding{}
	for n, group := range []string{"HTTP", "HTTPS", "QUIC"} {
		port, kind := plan.HTTPSPort, syscall.SOCK_STREAM
		if group == "HTTP" {
			port = plan.HTTPPort
		}
		if group == "QUIC" {
			kind = syscall.SOCK_DGRAM
		}
		result = append(result, socketBinding{group, 100 + n*2, syscall.AF_INET, kind, port})
		if plan.IPv6 {
			result = append(result, socketBinding{group, 101 + n*2, syscall.AF_INET6, kind, port})
		}
	}
	return result
}

func activateSocketGroup(group string) ([]int, error) {
	name := C.CString(group)
	defer C.free(unsafe.Pointer(name))
	var descriptors *C.int
	var count C.size_t
	code := C.launch_activate_socket(name, &descriptors, &count)
	if code != 0 {
		return nil, fmt.Errorf("launchd socket activation %s: %w", group, syscall.Errno(code))
	}
	defer C.free(unsafe.Pointer(descriptors))
	result := make([]int, int(count))
	for n, fd := range unsafe.Slice(descriptors, int(count)) {
		result[n] = int(fd)
		syscall.CloseOnExec(result[n])
	}
	return result, nil
}

// Match addresses rather than relying on launchd's descriptor order.
func matchSocketDescriptors(groups map[string][]int, plan socketPlan) (map[int]int, error) {
	expected := socketBindings(plan)
	result, seen := map[int]int{}, map[int]bool{}
	for _, group := range []string{"HTTP", "HTTPS", "QUIC"} {
		count := 1
		if plan.IPv6 {
			count = 2
		}
		if len(groups[group]) != count {
			return nil, fmt.Errorf("launchd %s socket count: got %d, want %d", group, len(groups[group]), count)
		}
		for _, fd := range groups[group] {
			if fd < 3 || seen[fd] {
				return nil, fmt.Errorf("invalid or repeated launchd descriptor %d", fd)
			}
			seen[fd] = true
			kind, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
			if err != nil {
				return nil, fmt.Errorf("inspect launchd descriptor %d: %w", fd, err)
			}
			address, err := syscall.Getsockname(fd)
			if err != nil {
				return nil, err
			}
			family, port, loopback := 0, 0, false
			switch address := address.(type) {
			case *syscall.SockaddrInet4:
				family, port, loopback = syscall.AF_INET, address.Port, address.Addr == [4]byte{127, 0, 0, 1}
			case *syscall.SockaddrInet6:
				family, port, loopback = syscall.AF_INET6, address.Port, address.Addr == [16]byte{15: 1} && address.ZoneId == 0
			}
			matched := false
			for _, binding := range expected {
				if binding.Group == group && binding.Family == family && binding.Type == kind && binding.Port == port && loopback {
					if _, exists := result[binding.FD]; exists {
						return nil, fmt.Errorf("duplicate launchd %s address family", group)
					}
					result[binding.FD], matched = fd, true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("launchd %s descriptor %d does not match saved loopback socket plan", group, fd)
			}
		}
	}
	return result, nil
}

func closeSocketGroups(groups map[string][]int) {
	for _, fds := range groups {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
	}
}

// Copy every source above the reserved slots before moving any descriptor.
func normalizeSocketDescriptors(mapping map[int]int) error {
	copies := map[int]int{}
	defer func() {
		for _, fd := range copies {
			_ = syscall.Close(fd)
		}
	}()
	for destination, source := range mapping {
		fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(source), syscall.F_DUPFD, 106)
		if errno != 0 {
			return errno
		}
		syscall.CloseOnExec(int(fd))
		copies[destination] = int(fd)
	}
	for _, source := range mapping {
		_ = syscall.Close(source)
	}
	normalized := []int{}
	for destination, source := range copies {
		if err := syscall.Dup2(source, destination); err != nil {
			for _, fd := range normalized {
				_ = syscall.Close(fd)
			}
			return err
		}
		// dup2 clears FD_CLOEXEC on the destination.
		normalized = append(normalized, destination)
	}
	return nil
}

func launchdCaddyBridge(args []string, errOut io.Writer) error {
	flags := flag.NewFlagSet("_launchd-caddy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	binary := flags.String("caddy", "", "")
	configPath := flags.String("config", "", "")
	recordPath := flags.String("setup-record", "", "")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*binary) || !filepath.IsAbs(*configPath) || !filepath.IsAbs(*recordPath) {
		return errors.New("launchd activation requires generated absolute paths")
	}
	data, err := os.ReadFile(*recordPath)
	if err != nil {
		return err
	}
	var record setupRecord
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return err
	}
	var installed installation
	if err := json.Unmarshal([]byte(record.Identity), &installed); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if installed.ID != "sandbar-launchd-v1" || record.SocketPlan == nil || installed.UID != os.Geteuid() || installed.UID == 0 || installed.Binary != *binary || installed.Config != *configPath || filepath.Join(installed.State, "setup.json") != *recordPath || installed.CLI != executable {
		return errors.New("launchd activation arguments do not match the saved installation")
	}
	info, err := os.Stat(installed.Binary)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return errors.New("configured Caddy is not an executable regular file")
	}
	groups := map[string][]int{}
	defer func() { closeSocketGroups(groups) }()
	for _, group := range []string{"HTTP", "HTTPS", "QUIC"} {
		groups[group], err = activateSocketGroup(group)
		if err != nil {
			return err
		}
	}
	mapping, err := matchSocketDescriptors(groups, *record.SocketPlan)
	if err != nil {
		return err
	}
	runtime, err := loadLaunchdRuntime(&installed, record, errOut)
	if err != nil {
		return err
	}
	if err := normalizeSocketDescriptors(mapping); err != nil {
		return err
	}
	// Sources are now closed. The reserved slots belong to Caddy after exec.
	groups = nil
	defer func() {
		for fd := range mapping {
			_ = syscall.Close(fd)
		}
	}()
	return execCaddyRuntime(&installed, runtime)
}

func execCaddyRuntime(installed *installation, runtime []byte) error {
	input, err := os.CreateTemp(installed.State, ".launchd-config-*")
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.Remove(input.Name()); err != nil {
		return err
	}
	if _, err := input.Write(runtime); err != nil {
		return err
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := syscall.Dup2(int(input.Fd()), 0); err != nil {
		return err
	}
	env := []string{}
	for _, item := range installedCaddyEnv(installed) {
		if !strings.HasPrefix(item, "SANDBAR_HOME=") {
			env = append(env, item)
		}
	}
	return syscall.Exec(installed.Binary, []string{installed.Binary, "run", "--config", "-"}, env)
}

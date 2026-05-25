package portcleanup

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"sniproxy/internal/config"
)

type owner struct {
	PID      int
	Port     int
	Protocol string
	Name     string
}

func Cleanup(cfg config.PortCleanupConfig, logger *log.Logger) error {
	if !cfg.Enabled {
		return nil
	}
	if logger == nil {
		logger = log.Default()
	}

	owners, err := findOwners(cfg)
	if err != nil {
		if cfg.FailOnError {
			return err
		}
		logger.Printf("port cleanup lookup failed: %v", err)
		return nil
	}

	self := os.Getpid()
	byPID := make(map[int][]owner)
	for _, item := range owners {
		if item.PID == 0 || item.PID == self {
			continue
		}
		byPID[item.PID] = append(byPID[item.PID], item)
	}
	if len(byPID) == 0 {
		logger.Printf("port cleanup: ports %v are free", cfg.Ports)
		return nil
	}

	pids := make([]int, 0, len(byPID))
	for pid := range byPID {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	for _, pid := range pids {
		items := byPID[pid]
		name := items[0].Name
		logger.Printf("port cleanup: killing pid=%d name=%q owners=%s", pid, name, describeOwners(items))
		if err := killPID(pid); err != nil && !isProcessDone(err) {
			if cfg.FailOnError {
				return fmt.Errorf("kill pid %d: %w", pid, err)
			}
			logger.Printf("port cleanup: kill pid=%d failed: %v", pid, err)
		}
	}

	deadline := time.Now().Add(cfg.KillTimeout.Duration)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		remaining, err := findOwners(cfg)
		if err != nil {
			if cfg.FailOnError {
				return err
			}
			logger.Printf("port cleanup lookup failed after kill: %v", err)
			return nil
		}
		if onlySelfOrNone(remaining, self) {
			logger.Printf("port cleanup: ports %v are free after killing %d process(es)", cfg.Ports, len(pids))
			return nil
		}
	}

	remaining, _ := findOwners(cfg)
	err = fmt.Errorf("port cleanup timed out; remaining owners: %s", describeOwners(remaining))
	if cfg.FailOnError {
		return err
	}
	logger.Printf("%v", err)
	return nil
}

func findOwners(cfg config.PortCleanupConfig) ([]owner, error) {
	ports := make(map[int]bool, len(cfg.Ports))
	for _, port := range cfg.Ports {
		ports[port] = true
	}
	protocols := make(map[string]bool, len(cfg.Protocols))
	for _, proto := range cfg.Protocols {
		protocols[strings.ToLower(proto)] = true
	}

	switch runtime.GOOS {
	case "linux":
		return findOwnersLinux(ports, protocols)
	case "windows":
		return findOwnersWindows(ports, protocols)
	case "darwin", "freebsd", "openbsd", "netbsd":
		return findOwnersLsof(ports, protocols)
	default:
		return nil, fmt.Errorf("port cleanup is not implemented for %s", runtime.GOOS)
	}
}

func killPID(pid int) error {
	if runtime.GOOS == "windows" {
		return exec.Command("taskkill", "/PID", strconv.Itoa(pid), "/T", "/F").Run()
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return proc.Kill()
}

func isProcessDone(err error) bool {
	if err == nil {
		return true
	}
	return errors.Is(err, os.ErrProcessDone)
}

func onlySelfOrNone(owners []owner, self int) bool {
	for _, item := range owners {
		if item.PID != 0 && item.PID != self {
			return false
		}
	}
	return true
}

func describeOwners(owners []owner) string {
	if len(owners) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(owners))
	for _, item := range owners {
		name := item.Name
		if name == "" {
			name = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s/%d pid=%d name=%s", item.Protocol, item.Port, item.PID, name))
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func findOwnersLinux(ports map[int]bool, protocols map[string]bool) ([]owner, error) {
	inodes := make(map[string]owner)
	if protocols["tcp"] {
		if err := collectProcNet("/proc/net/tcp", "tcp", ports, true, inodes); err != nil {
			return nil, err
		}
		if err := collectProcNet("/proc/net/tcp6", "tcp", ports, true, inodes); err != nil {
			return nil, err
		}
	}
	if protocols["udp"] {
		if err := collectProcNet("/proc/net/udp", "udp", ports, false, inodes); err != nil {
			return nil, err
		}
		if err := collectProcNet("/proc/net/udp6", "udp", ports, false, inodes); err != nil {
			return nil, err
		}
	}
	if len(inodes) == 0 {
		return nil, nil
	}

	var out []owner
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", proc.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			item, ok := inodes[inode]
			if !ok {
				continue
			}
			item.PID = pid
			item.Name = linuxProcessName(pid)
			out = append(out, item)
		}
	}
	return dedupeOwners(out), nil
}

func collectProcNet(path, proto string, ports map[int]bool, tcpListenOnly bool, out map[string]owner) error {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if tcpListenOnly && fields[3] != "0A" {
			continue
		}
		port, err := parseProcNetPort(fields[1])
		if err != nil || !ports[port] {
			continue
		}
		inode := fields[9]
		if inode == "0" {
			continue
		}
		out[inode] = owner{Port: port, Protocol: proto}
	}
	return nil
}

func parseProcNetPort(local string) (int, error) {
	i := strings.LastIndexByte(local, ':')
	if i < 0 || i+1 >= len(local) {
		return 0, fmt.Errorf("invalid proc net local address %q", local)
	}
	v, err := strconv.ParseInt(local[i+1:], 16, 32)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

func linuxProcessName(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func findOwnersWindows(ports map[int]bool, protocols map[string]bool) ([]owner, error) {
	var out []owner
	if protocols["tcp"] {
		items, err := parseWindowsNetstat("tcp", ports)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	if protocols["udp"] {
		items, err := parseWindowsNetstat("udp", ports)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
	}
	for i := range out {
		out[i].Name = windowsProcessName(out[i].PID)
	}
	return dedupeOwners(out), nil
}

func parseWindowsNetstat(proto string, ports map[int]bool) ([]owner, error) {
	cmd := exec.Command("netstat", "-ano", "-p", proto)
	b, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var out []owner
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.EqualFold(fields[0], proto) {
			continue
		}
		if proto == "tcp" && !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		pidField := fields[len(fields)-1]
		pid, err := strconv.Atoi(pidField)
		if err != nil {
			continue
		}
		port, err := parseAddrPort(fields[1])
		if err != nil || !ports[port] {
			continue
		}
		out = append(out, owner{PID: pid, Port: port, Protocol: proto})
	}
	return out, nil
}

func windowsProcessName(pid int) string {
	b, err := exec.Command("tasklist", "/FI", "PID eq "+strconv.Itoa(pid), "/FO", "CSV", "/NH").Output()
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(string(b))
	if line == "" || strings.Contains(line, "No tasks") {
		return ""
	}
	fields := strings.Split(line, "\",\"")
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "\"")
}

func findOwnersLsof(ports map[int]bool, protocols map[string]bool) ([]owner, error) {
	if _, err := exec.LookPath("lsof"); err != nil {
		return nil, fmt.Errorf("lsof is required for port cleanup on %s", runtime.GOOS)
	}
	var out []owner
	for port := range ports {
		if protocols["tcp"] {
			items, err := lsofPort("tcp", port)
			if err != nil {
				return nil, err
			}
			out = append(out, items...)
		}
		if protocols["udp"] {
			items, err := lsofPort("udp", port)
			if err != nil {
				return nil, err
			}
			out = append(out, items...)
		}
	}
	return dedupeOwners(out), nil
}

func lsofPort(proto string, port int) ([]owner, error) {
	args := []string{"-nP", "-t"}
	if proto == "tcp" {
		args = append(args, "-iTCP:"+strconv.Itoa(port), "-sTCP:LISTEN")
	} else {
		args = append(args, "-iUDP:"+strconv.Itoa(port))
	}
	b, err := exec.Command("lsof", args...).Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok && len(exit.Stderr) == 0 && len(b) == 0 {
			return nil, nil
		}
		return nil, err
	}
	var out []owner
	for _, line := range strings.Split(string(b), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		out = append(out, owner{PID: pid, Port: port, Protocol: proto, Name: processName(pid)})
	}
	return out, nil
}

func processName(pid int) string {
	b, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func parseAddrPort(addr string) (int, error) {
	addr = strings.TrimSpace(addr)
	if i := strings.LastIndexByte(addr, ':'); i >= 0 && i+1 < len(addr) {
		return strconv.Atoi(addr[i+1:])
	}
	return 0, fmt.Errorf("address has no port: %q", addr)
}

func dedupeOwners(in []owner) []owner {
	seen := make(map[string]bool, len(in))
	out := make([]owner, 0, len(in))
	for _, item := range in {
		key := fmt.Sprintf("%s/%d/%d", item.Protocol, item.Port, item.PID)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].PID < out[j].PID
	})
	return out
}

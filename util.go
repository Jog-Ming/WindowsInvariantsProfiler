package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	appName       = "WindowsInvariantsProfiler"
	legacyAppName = "windows-invariants-profiler" // pre-rename layout; used only for migration
	taskName      = "winvar-daemon"
)

var buildVersion = "dev"

var (
	sourceImageLock     syscall.Handle
	stagedSourcePath    string
	stagedSourceDir     string
	stagedSourceDirLock syscall.Handle
	stagedSourceHash    string
	stagedSourceLock    syscall.Handle
)

// lockStagedDir pins the staging directory itself. A handle without
// FILE_SHARE_DELETE makes the directory impossible to rename or delete while
// UAC is open, so the path the elevated process is launched from cannot be
// redirected even though the directory ACL grants the creating user full
// control.
func lockStagedDir(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING,
		flagBackupSemantics|flagOpenReparsePoint, 0)
	if err != nil {
		return err
	}
	if _, reparse, err := handleAttrTag(h); err != nil || reparse {
		syscall.CloseHandle(h)
		return errors.New("staging directory is not a plain directory")
	}
	stagedSourceDirLock = h
	return nil
}

// lockSourceImage opens the running executable without FILE_SHARE_DELETE so a
// same-user process cannot rename or replace the image while the installer
// copies it into Program Files. Failure is reported so setup refuses to
// continue.
func lockSourceImage() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(exe)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	sourceImageLock = h
	return nil
}

// stageSourceImage copies the already-locked running image into a temp file,
// hashes it, and keeps the temp open with FILE_SHARE_READ so the elevated child
// can verify and use it without ever reopening the original path.
func stageSourceImage() error {
	if sourceImageLock == 0 {
		return errors.New("source image is not locked")
	}
	base, err := stableStagingBase()
	if err != nil {
		return err
	}
	// A private staging directory keeps every user except the installer out of
	// the image's application directory: a sibling manifest or DLL planted
	// there would otherwise load into the elevated process before main runs.
	sid := currentUserSID()
	dirSDDL := "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")"
	var stageDir string
	for i := 0; i < 16; i++ {
		candidate := filepath.Join(base, "winvar-stage-"+newID())
		if err := createSecureDir(candidate, dirSDDL); err == nil {
			stageDir = candidate
			break
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if stageDir == "" {
		return errors.New("cannot create a private staging directory")
	}
	if err := lockStagedDir(stageDir); err != nil {
		removeTreeNoFollow(stageDir)
		return err
	}
	success := false
	defer func() {
		if !success {
			if stagedSourceDirLock != 0 {
				procCloseHandle.Call(uintptr(stagedSourceDirLock))
				stagedSourceDirLock = 0
			}
			removeTreeNoFollow(stageDir)
		}
	}()
	// The staging file is created with a DACL that gives the installing user
	// only read and delete; the elevated process needs only read. A file
	// created with the default security would be fully writable by its creator.
	sddl := "D:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;" + sid + ")(A;;SD;;;" + sid + ")"
	sd, err := convertSecurityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	sa := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	var tmpPath string
	var h syscall.Handle
	for i := 0; i < 16; i++ {
		tmpPath = filepath.Join(stageDir, "winvar-setup-"+newID()+".exe")
		p, err := syscall.UTF16PtrFromString(tmpPath)
		if err != nil {
			return err
		}
		h, err = syscall.CreateFile(p,
			syscall.GENERIC_READ|syscall.GENERIC_WRITE,
			syscall.FILE_SHARE_READ,
			&sa,
			syscall.CREATE_NEW,
			syscall.FILE_ATTRIBUTE_NORMAL,
			0)
		if err == nil {
			break
		}
		h = 0
	}
	if h == 0 {
		return errors.New("cannot create a unique staging file in ProgramData")
	}
	hasher := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		var n uint32
		if err := syscall.ReadFile(sourceImageLock, buf, &n, nil); err != nil {
			syscall.CloseHandle(h)
			os.Remove(tmpPath)
			return err
		}
		if n == 0 {
			break
		}
		if _, err := hasher.Write(buf[:n]); err != nil {
			syscall.CloseHandle(h)
			os.Remove(tmpPath)
			return err
		}
		var written uint32
		if err := syscall.WriteFile(h, buf[:n], &written, nil); err != nil || written != n {
			syscall.CloseHandle(h)
			os.Remove(tmpPath)
			return errors.New("cannot write the staging file")
		}
	}
	if err := syscall.CloseHandle(h); err != nil {
		os.Remove(tmpPath)
		return err
	}
	ro, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	lock, err := syscall.CreateFile(ro, accessFileReadData|accessReadControl|accessSynchronize,
		syscall.FILE_SHARE_READ, nil, openExistingOnly, flagBackupSemantics|flagOpenReparsePoint, 0)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}
	if attrs, reparse, err := handleAttrTag(lock); err != nil || reparse || attrs&fileAttributeDirectory != 0 {
		syscall.CloseHandle(lock)
		os.Remove(tmpPath)
		return errors.New("staging file changed after it was written")
	}
	// Re-read through the share-read handle that stays open while UAC runs: if
	// the file was replaced in the handoff, the bytes differ and setup aborts.
	recheck := sha256.New()
	rbuf := make([]byte, 1<<20)
	for {
		var n uint32
		if err := syscall.ReadFile(lock, rbuf, &n, nil); err != nil {
			syscall.CloseHandle(lock)
			os.Remove(tmpPath)
			return err
		}
		if n == 0 {
			break
		}
		recheck.Write(rbuf[:n])
	}
	expected := hex.EncodeToString(hasher.Sum(nil))
	if hex.EncodeToString(recheck.Sum(nil)) != expected {
		syscall.CloseHandle(lock)
		os.Remove(tmpPath)
		return errors.New("staging file changed after it was written")
	}
	stagedSourcePath = tmpPath
	stagedSourceDir = stageDir
	stagedSourceHash = expected
	stagedSourceLock = lock
	success = true
	return nil
}

// stageVerifiedSource reads the caller-provided staged image exactly once,
// verifies it against the hash produced by the unprivileged parent, and copies
// it into the administrator-only staging directory. Later installation steps
// use only this protected copy, never the caller-controlled path again.
func stageVerifiedSource(args []string) (string, error) {
	want := flagValue(args, "--source-sha256")
	if want == "" {
		return "", nil
	}
	// Only the running installer image is an acceptable source. The hash the
	// unprivileged parent supplies must match this image, not an arbitrary
	// --source-temp file the caller chose.
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	const maxStagedBytes = 64 << 20
	if st, err := os.Stat(exe); err != nil {
		return "", err
	} else if st.Size() > maxStagedBytes {
		return "", errors.New("installer image is too large")
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), want) {
		return "", errors.New("staged source does not match the running installer image")
	}
	dst := filepath.Join(adminTempDir(), "install-source-"+newID()+".exe")
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(dst)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(dst)
		return "", err
	}
	return dst, nil
}

var (
	shell32             = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin   = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteExW = shell32.NewProc("ShellExecuteExW")
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procWaitForSingle   = kernel32.NewProc("WaitForSingleObject")
	procGetExitCode     = kernel32.NewProc("GetExitCodeProcess")
	procCloseHandle     = kernel32.NewProc("CloseHandle")
	procMoveFileEx      = kernel32.NewProc("MoveFileExW")
	procQueryFullPath   = kernel32.NewProc("QueryFullProcessImageNameW")
	procSetDllDirs      = kernel32.NewProc("SetDefaultDllDirectories")
	procLoadLibraryEx   = kernel32.NewProc("LoadLibraryExW")
	procTerminate       = kernel32.NewProc("TerminateProcess")
)

const loadLibrarySearchSystem32 = 0x00000800

// hardenDllSearch removes the application directory and the working directory
// from the DLL search order and preloads every DLL loaded by name from
// System32. The elevated installer can run from a user-writable staging
// directory, where a planted crypt32.dll would otherwise load into the
// administrator process on the first certificate-store call.
func hardenDllSearch() {
	procSetDllDirs.Call(loadLibrarySearchSystem32)
	for _, name := range []string{"advapi32.dll", "ole32.dll", "shell32.dll", "crypt32.dll"} {
		p, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		procLoadLibraryEx.Call(uintptr(unsafe.Pointer(p)), 0, loadLibrarySearchSystem32)
	}
}

func isAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     uintptr
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

// elevateSelf relaunches this executable with the given arguments under UAC and
// waits for it, returning the elevated process's exit code.
func elevateSelf(args []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return -1, err
	}
	return elevateSelfPath(exe, args)
}

func elevateSelfPath(exe string, args []string) (int, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	sei := shellExecuteInfo{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfo{})),
		fMask:        0x40 | 0x100, // SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
		lpVerb:       utf16Ptr("runas"),
		lpFile:       utf16Ptr(exe),
		lpParameters: utf16Ptr(strings.Join(quoted, " ")),
		nShow:        1,
	}
	r, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == 1223 {
			return -1, errors.New("elevation was cancelled")
		}
		return -1, callErr
	}
	defer procCloseHandle.Call(sei.hProcess)
	procWaitForSingle.Call(sei.hProcess, 0xFFFFFFFF)
	var code uint32
	procGetExitCode.Call(sei.hProcess, uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

func currentUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	domain := os.Getenv("USERDOMAIN")
	name := os.Getenv("USERNAME")
	if domain == "" {
		return name
	}
	return domain + `\` + name
}

func currentUserSID() string {
	if u, err := user.Current(); err == nil {
		return u.Uid
	}
	return ""
}

func resolveTool(name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	switch strings.ToLower(filepath.Base(name)) {
	case "schtasks.exe", "icacls.exe", "taskkill.exe", "reg.exe", "msiexec.exe", "cmd.exe", "tasklist.exe", "where.exe":
		return system32(filepath.Base(name))
	case "powershell.exe":
		return systemPowerShell()
	}
	return name
}

func runCommand(name string, args ...string) (string, int, error) {
	cmd := exec.Command(resolveTool(name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Dir = system32("")
	cmd.Env = sanitizedEnvironment()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if err == nil {
		return buf.String(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return buf.String(), exitErr.ExitCode(), nil
	}
	return buf.String(), -1, err
}

func runCommandTimeout(timeout time.Duration, name string, args ...string) (string, int, error) {
	cmd := exec.Command(resolveTool(name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Dir = system32("")
	cmd.Env = sanitizedEnvironment()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return buf.String(), -1, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return buf.String(), 0, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return buf.String(), exitErr.ExitCode(), nil
		}
		return buf.String(), -1, err
	case <-time.After(timeout):
		cmd.Process.Kill()
		select {
		case <-done:
			return buf.String(), -2, fmt.Errorf("timed out after %s", timeout)
		case <-time.After(5 * time.Second):
			return "", -2, fmt.Errorf("timed out after %s", timeout)
		}
	}
}

// runCommandWatched runs a tool and kills it as soon as watchPath grows past
// maxBytes, so a trace tool cannot fill the disk before a later size check.
func runCommandWatched(timeout time.Duration, watchPath string, maxBytes int64, name string, args ...string) (string, int, error) {
	cmd := exec.Command(resolveTool(name), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Dir = system32("")
	cmd.Env = sanitizedEnvironment()
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Start(); err != nil {
		return buf.String(), -1, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	kill := func() {
		cmd.Process.Kill()
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(timeout)
	for {
		select {
		case err := <-done:
			if err == nil {
				if st, serr := os.Stat(watchPath); serr == nil && st.Size() > maxBytes {
					os.Remove(watchPath)
					return buf.String(), -3, fmt.Errorf("output exceeded %d bytes", maxBytes)
				}
				return buf.String(), 0, nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return buf.String(), exitErr.ExitCode(), nil
			}
			return buf.String(), -1, err
		case <-ticker.C:
			if st, err := os.Stat(watchPath); err == nil && st.Size() > maxBytes {
				kill()
				select {
				case <-done:
					os.Remove(watchPath)
					return buf.String(), -3, fmt.Errorf("output exceeded %d bytes", maxBytes)
				case <-time.After(5 * time.Second):
					os.Remove(watchPath)
					return "", -3, fmt.Errorf("output exceeded %d bytes", maxBytes)
				}
			}
		case <-deadline:
			kill()
			select {
			case <-done:
				return buf.String(), -2, fmt.Errorf("timed out after %s", timeout)
			case <-time.After(5 * time.Second):
				return "", -2, fmt.Errorf("timed out after %s", timeout)
			}
		}
	}
}

// terminateIfImage verifies the process image and terminates it through the
// same handle, so a recycled PID can never redirect the kill to another
// process after the check.
func terminateIfImage(pid int, image string) bool {
	const processQueryLimitedInformation = 0x1000
	const processTerminate = 0x0001
	h, err := syscall.OpenProcess(processQueryLimitedInformation|processTerminate, false, uint32(pid))
	if err != nil || h == 0 {
		return false
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r, _, _ := procQueryFullPath.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 || size == 0 || size > uint32(len(buf)) {
		return false
	}
	if !samePath(syscall.UTF16ToString(buf[:size]), image) {
		return false
	}
	r, _, _ = procTerminate.Call(uintptr(h), 1)
	return r != 0
}

func processImagePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	const processQueryLimitedInformation = 0x1000
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return ""
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r, _, _ := procQueryFullPath.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 || size == 0 || size > uint32(len(buf)) {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func dirExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func copyLockedImage(dst string) error {
	if sourceImageLock == 0 {
		return errors.New("source image is not locked")
	}
	var data []byte
	buf := make([]byte, 1<<20)
	for {
		var n uint32
		if err := syscall.ReadFile(sourceImageLock, buf, &n, nil); err != nil {
			return err
		}
		if n == 0 {
			break
		}
		data = append(data, buf[:n]...)
		if len(data) > 128<<20 {
			return errors.New("installer image is too large")
		}
	}
	return writeFileSecure(dst, data, installFileACL())
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if len(data) > 128<<20 {
		return errors.New("installer image is too large")
	}
	return writeFileSecure(dst, data, installFileACL())
}

func machineRootPool() *x509.CertPool {
	name, err := syscall.UTF16PtrFromString("ROOT")
	if err != nil {
		return nil
	}
	const certStoreProvSystem = 10
	const certSystemStoreLocalMachine = 0x00020000
	store, err := syscall.CertOpenStore(certStoreProvSystem, 0, 0, certSystemStoreLocalMachine, uintptr(unsafe.Pointer(name)))
	if err != nil {
		return nil
	}
	defer syscall.CertCloseStore(store, 0)
	pool := x509.NewCertPool()
	var ctx *syscall.CertContext
	for {
		ctx, err = syscall.CertEnumCertificatesInStore(store, ctx)
		if err != nil || ctx == nil {
			break
		}
		der := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
		if cert, err := x509.ParseCertificate(der); err == nil {
			pool.AddCert(cert)
		}
	}
	return pool
}

func downloadFile(url, dst string) error {
	// No proxy from the environment, and only machine roots for TLS: the
	// elevated installer must not trust a proxy or root certificate the
	// invoking user controls.
	pool := machineRootPool()
	if pool == nil {
		return errors.New("cannot load machine root certificates")
	}
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	client := &http.Client{
		Timeout:   5 * time.Minute,
		Transport: transport,
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	const maxDownload = 512 << 20
	tmp := dst + ".part"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(out, io.LimitReader(resp.Body, maxDownload+1))
	closeErr := out.Close()
	if copyErr != nil {
		os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		os.Remove(tmp)
		return closeErr
	}
	if n > maxDownload {
		os.Remove(tmp)
		return fmt.Errorf("download exceeds %d bytes", maxDownload)
	}
	os.Remove(dst)
	return os.Rename(tmp, dst)
}

func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, ",")
	if neg {
		out = "-" + out
	}
	return out
}

func samePath(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return strings.EqualFold(a, b)
	}
	return strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
}

func sameDir(a, b string) bool {
	return samePath(a, b)
}

func flagValue(args []string, name string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], name+"=") {
			return strings.TrimPrefix(args[i], name+"=")
		}
	}
	return ""
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func logLine(path, format string, args ...interface{}) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	line := time.Now().Format("2006-01-02 15:04:05") + " " + fmt.Sprintf(format, args...) + "\n"
	f.WriteString(line)
}

func scheduleDeleteOnReboot(path string) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	const moveFileDelayUntilReboot = 0x00000004
	procMoveFileEx.Call(uintptr(unsafe.Pointer(p)), 0, moveFileDelayUntilReboot)
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

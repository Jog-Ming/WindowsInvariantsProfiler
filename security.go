package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	folderProgramFiles    = guid{0x905e63b6, 0xc1bf, 0x494e, [8]byte{0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a}}
	folderProgramFilesX86 = guid{0x7c5a40ef, 0xa0fb, 0x4bfc, [8]byte{0x87, 0x4a, 0xc0, 0xf2, 0xe0, 0xb9, 0xfa, 0x8e}}
	folderProgramData     = guid{0x62ab5d82, 0xfdc1, 0x4dc3, [8]byte{0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97}}
	folderSystem          = guid{0x1ac14e77, 0x02e7, 0x4e5d, [8]byte{0xb7, 0x44, 0x2e, 0xb1, 0xae, 0x51, 0x98, 0xb7}}
	folderWindows         = guid{0xf38bf404, 0x1d43, 0x42f2, [8]byte{0x93, 0x05, 0x67, 0xde, 0x0b, 0x28, 0xfc, 0x23}}
	folderProfile         = guid{0x5e6c858f, 0x0e22, 0x4760, [8]byte{0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73}}
	folderRoamingAppData  = guid{0x3eb685db, 0x65f9, 0x4cf6, [8]byte{0xa0, 0x3a, 0xe3, 0xef, 0x65, 0x72, 0x9f, 0x3d}}
	folderLocalAppData    = guid{0xf1b32785, 0x6fba, 0x4fcf, [8]byte{0x9d, 0x55, 0x7b, 0x8e, 0x7f, 0x15, 0x70, 0x91}}
)

var (
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")
	ole32                     = syscall.NewLazyDLL("ole32.dll")
	ntdll                     = syscall.NewLazyDLL("ntdll.dll")
	procSHGetKnownFolderPath  = shell32.NewProc("SHGetKnownFolderPath")
	procGetNamedSecurityInfo  = advapi32.NewProc("GetNamedSecurityInfoW")
	procConvertSidToStringSid = advapi32.NewProc("ConvertSidToStringSidW")
	procConvertStringSD       = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procConvertStringSid      = advapi32.NewProc("ConvertStringSidToSidW")
	procConvertSDToString     = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	procGetSdOwner            = advapi32.NewProc("GetSecurityDescriptorOwner")
	procGetSdDacl             = advapi32.NewProc("GetSecurityDescriptorDacl")
	procSetSecurityInfo       = advapi32.NewProc("SetSecurityInfo")
	procGetAce                = advapi32.NewProc("GetAce")
	procEqualSid              = advapi32.NewProc("EqualSid")
	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation   = advapi32.NewProc("GetTokenInformation")
	procGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	procLocalFree             = kernel32.NewProc("LocalFree")
	procGetFileAttributes     = kernel32.NewProc("GetFileAttributesW")
	procGetFileInformation    = kernel32.NewProc("GetFileInformationByHandleEx")
	procSetFileInformation    = kernel32.NewProc("SetFileInformationByHandle")
	procCoTaskMemFree         = ole32.NewProc("CoTaskMemFree")
	procNtCreateFile          = ntdll.NewProc("NtCreateFile")
	procLookupPrivilegeValue  = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	procRegOpenKeyEx          = advapi32.NewProc("RegOpenKeyExW")
	procRegQueryValueEx       = advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey           = advapi32.NewProc("RegCloseKey")
)

const (
	accessDelete              = 0x00010000
	accessReadControl         = 0x00020000
	accessWriteDac            = 0x00040000
	accessWriteOwner          = 0x00080000
	accessSynchronize         = 0x00100000
	accessFileReadData        = 0x00000001
	accessFileReadAttributes  = 0x00000080
	accessFileWriteAttributes = 0x00000100

	shareAllAccess       = 0x00000007
	openExistingOnly     = 3
	flagBackupSemantics  = 0x02000000
	flagOpenReparsePoint = 0x00200000

	fileAttributeDirectory    = 0x00000010
	fileAttributeNormal       = 0x00000080
	fileAttributeReparsePoint = 0x00000400

	fileBasicInfoClass             = 0
	fileStandardInfoClass          = 1
	fileDispositionInfoClass       = 4
	fileAttributeTagInfoClass      = 9
	fileIdBothDirectoryInfo        = 10
	fileIdBothDirectoryRestartInfo = 11

	objCaseInsensitive          = 0x00000040
	ntFileOpen                  = 1
	ntFileDirectoryFile         = 0x00000001
	ntFileSynchronousIoNonAlert = 0x00000020
	ntFileOpenForBackupIntent   = 0x00004000
	ntFileOpenReparsePoint      = 0x00200000

	ntStatusObjectNameNotFound = 0xC0000034
	ntStatusDeletePending      = 0xC0000056
	ntStatusAccessDenied       = 0xC0000022
	ntStatusNotADirectory      = 0xC00000A2
	ntStatusFileIsADirectory   = 0xC00000BA
)

type luidAndAttributes struct {
	LuidLow    uint32
	LuidHigh   int32
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

func enablePrivilege(name string) {
	const tokenQuery = 0x0008
	const tokenAdjust = 0x0020
	const sePrivilegeEnabled = 0x00000002
	var token uintptr
	proc, _, _ := procGetCurrentProcess.Call()
	if r, _, _ := procOpenProcessToken.Call(proc, tokenQuery|tokenAdjust,
		uintptr(unsafe.Pointer(&token))); r == 0 || token == 0 {
		return
	}
	defer syscall.CloseHandle(syscall.Handle(token))
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var luid luidAndAttributes
	if r, _, _ := procLookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(n)),
		uintptr(unsafe.Pointer(&luid))); r == 0 {
		return
	}
	luid.Attributes = sePrivilegeEnabled
	tp := tokenPrivileges{PrivilegeCount: 1, Privileges: [1]luidAndAttributes{luid}}
	procAdjustTokenPrivileges.Call(token, 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
}

// enableTakeoverPrivileges lets the elevated installer reclaim directories a
// user squatted with a deny-all DACL instead of failing the repair.
func enableTakeoverPrivileges() {
	enablePrivilege("SeTakeOwnershipPrivilege")
	enablePrivilege("SeRestorePrivilege")
	enablePrivilege("SeBackupPrivilege")
}

type winUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type winObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *winUnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type winIoStatusBlock struct {
	Status      uintptr
	Information uintptr
}

type fileAttrTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
}

type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
}

type dirEntryInfo struct {
	name  string
	isDir bool
}

func openNoFollow(path string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(p, access, shareAllAccess, nil, openExistingOnly,
		flagBackupSemantics|flagOpenReparsePoint, 0)
}

func handleAttrTag(h syscall.Handle) (uint32, bool, error) {
	var info fileAttrTagInfo
	r, _, callErr := procGetFileInformation.Call(uintptr(h), fileAttributeTagInfoClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		return 0, false, callErr
	}
	return info.FileAttributes, info.FileAttributes&fileAttributeReparsePoint != 0, nil
}

func handleLinkCount(h syscall.Handle) (uint32, error) {
	var info fileStandardInfo
	r, _, callErr := procGetFileInformation.Call(uintptr(h), fileStandardInfoClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		return 0, callErr
	}
	return info.NumberOfLinks, nil
}

func deleteOpened(h syscall.Handle) error {
	var disposition struct{ DeleteFile byte }
	disposition.DeleteFile = 1
	r, _, callErr := procSetFileInformation.Call(uintptr(h), fileDispositionInfoClass,
		uintptr(unsafe.Pointer(&disposition)), 1)
	if r != 0 {
		return nil
	}
	// Clearing attributes writes the shared file object, so a hardlink must
	// never take that path.
	if links, lerr := handleLinkCount(h); lerr != nil || links > 1 {
		return callErr
	}
	basic := fileBasicInfo{FileAttributes: fileAttributeNormal}
	procSetFileInformation.Call(uintptr(h), fileBasicInfoClass, uintptr(unsafe.Pointer(&basic)), unsafe.Sizeof(basic))
	r, _, callErr = procSetFileInformation.Call(uintptr(h), fileDispositionInfoClass,
		uintptr(unsafe.Pointer(&disposition)), 1)
	if r == 0 {
		return callErr
	}
	return nil
}

func listDirHandle(h syscall.Handle) ([]dirEntryInfo, error) {
	buf := make([]byte, 64<<10)
	var entries []dirEntryInfo
	class := uintptr(fileIdBothDirectoryRestartInfo)
	for {
		r, _, callErr := procGetFileInformation.Call(uintptr(h), class,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		class = fileIdBothDirectoryInfo
		if r == 0 {
			if callErr == syscall.ERROR_NO_MORE_FILES {
				break
			}
			return nil, callErr
		}
		off := uintptr(0)
		for {
			if off+64 > uintptr(len(buf)) {
				return nil, errors.New("invalid directory enumeration")
			}
			base := unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + off)
			next := *(*uint32)(base)
			attrs := *(*uint32)(unsafe.Add(base, 56))
			nameLen := *(*uint32)(unsafe.Add(base, 60))
			if nameLen > 0 && nameLen <= 512 && off+104+uintptr(nameLen) <= uintptr(len(buf)) {
				nameUTF16 := unsafe.Slice((*uint16)(unsafe.Add(base, 104)), nameLen/2)
				name := syscall.UTF16ToString(nameUTF16)
				if strings.ContainsAny(name, `\/`) {
					return nil, errors.New("invalid directory entry name")
				}
				if name != "." && name != ".." {
					entries = append(entries, dirEntryInfo{name: name, isDir: attrs&fileAttributeDirectory != 0})
					if len(entries) > 200000 {
						return nil, errors.New("too many directory entries")
					}
				}
			}
			if next == 0 {
				break
			}
			off += uintptr(next)
			if off >= uintptr(len(buf)) {
				return nil, errors.New("invalid directory enumeration")
			}
		}
	}
	return entries, nil
}

// openRelative opens a child by name anchored at an already-verified parent
// handle, so no path component is ever resolved through the filesystem again.
// FILE_OPEN_REPARSE_POINT makes the returned handle refer to the link itself.
func openRelative(parent syscall.Handle, name string, isDir bool) (syscall.Handle, uint32, error) {
	return openRelativeAccess(parent, name, isDir,
		accessDelete|accessFileReadData|accessFileReadAttributes|accessFileWriteAttributes|
			accessReadControl|accessSynchronize)
}

func openRelativeAccess(parent syscall.Handle, name string, isDir bool, access uint32) (syscall.Handle, uint32, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/`) {
		return 0, 0, errors.New("invalid file name")
	}
	name16, err := syscall.UTF16FromString(name)
	if err != nil || len(name16) < 2 {
		return 0, 0, errors.New("invalid file name")
	}
	us := winUnicodeString{
		Length:        uint16((len(name16) - 1) * 2),
		MaximumLength: uint16(len(name16) * 2),
		Buffer:        &name16[0],
	}
	oa := winObjectAttributes{
		Length:        uint32(unsafe.Sizeof(winObjectAttributes{})),
		RootDirectory: uintptr(parent),
		ObjectName:    &us,
		Attributes:    objCaseInsensitive,
	}
	var iosb winIoStatusBlock
	var raw uintptr
	options := uint32(ntFileOpenReparsePoint | ntFileSynchronousIoNonAlert | ntFileOpenForBackupIntent)
	if isDir {
		options |= ntFileDirectoryFile
	}
	status, _, _ := procNtCreateFile.Call(
		uintptr(unsafe.Pointer(&raw)),
		uintptr(access),
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&iosb)),
		0, 0, shareAllAccess, ntFileOpen, uintptr(options), 0, 0)
	runtime.KeepAlive(name16)
	runtime.KeepAlive(&us)
	runtime.KeepAlive(&oa)
	if uint32(status) != 0 {
		return 0, uint32(status), nil
	}
	return syscall.Handle(raw), 0, nil
}

func removeOpened(h syscall.Handle, depth int) error {
	if depth > 256 {
		return errors.New("directory tree is too deep")
	}
	attrs, reparse, err := handleAttrTag(h)
	if err != nil {
		return err
	}
	if reparse || attrs&fileAttributeDirectory == 0 {
		return deleteOpened(h)
	}
	for attempt := 0; attempt < 4; attempt++ {
		entries, err := listDirHandle(h)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			break
		}
		for _, entry := range entries {
			child, status, err := openRelative(h, entry.name, entry.isDir)
			if err != nil {
				return err
			}
			if status == ntStatusFileIsADirectory || status == ntStatusNotADirectory {
				child, status, err = openRelative(h, entry.name, !entry.isDir)
				if err != nil {
					return err
				}
			}
			if status == ntStatusAccessDenied {
				if terr := takeoverRelative(h, entry.name, entry.isDir); terr == nil {
					child, status, err = openRelative(h, entry.name, entry.isDir)
					if err != nil {
						return err
					}
				}
			}
			if status != 0 {
				if status == ntStatusObjectNameNotFound || status == ntStatusDeletePending {
					continue
				}
				return fmt.Errorf("cannot open %q: 0x%x", entry.name, status)
			}
			err = removeOpened(child, depth+1)
			syscall.CloseHandle(child)
			if err != nil {
				return err
			}
		}
		if err := deleteOpened(h); err == nil {
			return nil
		}
	}
	return errors.New("directory did not become empty")
}

func utf16z(p *uint16) string {
	if p == nil {
		return ""
	}
	var b []uint16
	for i := 0; ; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i*2)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return syscall.UTF16ToString(b)
}

func knownFolder(g *guid) string {
	var p *uint16
	hr, _, _ := procSHGetKnownFolderPath.Call(uintptr(unsafe.Pointer(g)), 0, 0, uintptr(unsafe.Pointer(&p)))
	if hr != 0 || p == nil {
		return ""
	}
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
	return utf16z(p)
}

func programFilesDir() string {
	if s := knownFolder(&folderProgramFiles); s != "" {
		return s
	}
	return `C:\Program Files`
}

func programFilesX86Dir() string {
	if s := knownFolder(&folderProgramFilesX86); s != "" {
		return s
	}
	return `C:\Program Files (x86)`
}

func programDataBaseDir() string {
	if s := knownFolder(&folderProgramData); s != "" {
		return s
	}
	return `C:\ProgramData`
}

func system32(name string) string {
	root := knownFolder(&folderSystem)
	if root == "" {
		root = `C:\Windows\System32`
	}
	return filepath.Join(root, name)
}

func systemPowerShell() string {
	return filepath.Join(system32("WindowsPowerShell"), "v1.0", "powershell.exe")
}

func sanitizedEnvironment() []string {
	win := knownFolder(&folderWindows)
	if win == "" {
		win = `C:\Windows`
	}
	sys := filepath.Join(win, "System32")
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0")
	env := []string{
		"SystemRoot=" + win,
		"windir=" + win,
		"SystemDrive=" + filepath.VolumeName(win),
		"ComSpec=" + filepath.Join(sys, "cmd.exe"),
		"ProgramFiles=" + programFilesDir(),
		"ProgramFiles(x86)=" + programFilesX86Dir(),
		"ProgramData=" + programDataBaseDir(),
		"PATH=" + sys + ";" + win + ";" + ps,
		"PSModulePath=" + filepath.Join(ps, "Modules"),
	}
	// The temp and per-user data directories are redirected to the admin-only
	// staging directory. PowerShell module analysis caches and SDK temp files
	// then live somewhere the invoking user cannot write.
	tmp := adminTempDir()
	env = append(env,
		"TEMP="+tmp,
		"TMP="+tmp,
		"USERPROFILE="+tmp,
		"APPDATA="+tmp,
		"LOCALAPPDATA="+tmp,
	)
	return env
}

func sanitizeProcessEnv() {
	for _, k := range []string{
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	} {
		os.Unsetenv(k)
	}
	for _, e := range sanitizedEnvironment() {
		if i := strings.IndexByte(e, '='); i > 0 {
			os.Setenv(e[:i], e[i+1:])
		}
	}
	os.Chdir(system32(""))
}

func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func underAdminPath(path string) bool {
	clean := filepath.Clean(path)
	for _, root := range []string{programFilesDir(), programFilesX86Dir()} {
		if root == "" {
			continue
		}
		prefix := strings.ToLower(filepath.Clean(root)) + string(os.PathSeparator)
		if strings.HasPrefix(strings.ToLower(clean), prefix) {
			return true
		}
	}
	return false
}

func trustedTracelog() string {
	var candidates []string
	candidates = append(candidates, installedTracelog())
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "tracelog.exe"))
	}
	for _, p := range candidates {
		if fileExists(p) && underAdminPath(p) && fileSHA256(p) == tracelogSHA256 {
			return p
		}
	}
	return ""
}

func trustedXperf() string {
	sid := currentUserSID()
	for _, root := range []string{programFilesX86Dir(), programFilesDir()} {
		if root == "" {
			continue
		}
		p := filepath.Join(root, "Windows Kits", "10", "Windows Performance Toolkit", "xperf.exe")
		if !fileExists(p) || !underAdminPath(p) {
			continue
		}
		if !fileOwnerTrusted(p) || !fileOwnerTrusted(filepath.Dir(p)) {
			continue
		}
		if userCanWriteDir(p, sid) || userCanWriteDir(filepath.Dir(p), sid) {
			continue
		}
		return p
	}
	return ""
}

func icacls(path string, args ...string) error {
	full := append([]string{path}, args...)
	out, code, err := runCommand(system32("icacls.exe"), full...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("icacls %s failed (exit %d): %s", path, code, truncate(out, 500))
	}
	return nil
}

func setOwnerAndDaclHandle(h syscall.Handle) error {
	return setHandleACL(h, "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
}

func setHandleACL(h syscall.Handle, sddl string) error {
	sd, err := convertSecurityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	var owner uintptr
	var ownerDefaulted int32
	if r, _, _ := procGetSdOwner.Call(sd, uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&ownerDefaulted))); r == 0 || owner == 0 {
		return errors.New("takeover descriptor has no owner")
	}
	var present int32
	var dacl unsafe.Pointer
	var defaulted int32
	if r, _, _ := procGetSdDacl.Call(sd, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 || present == 0 || dacl == nil {
		return errors.New("takeover descriptor has no DACL")
	}
	const seFileObject = 1
	const ownerSecurityInformation = 0x1
	const daclSecurityInformation = 0x4
	const protectedDaclSecurityInformation = 0x80000000
	if r, _, callErr := procSetSecurityInfo.Call(uintptr(h), seFileObject,
		ownerSecurityInformation|daclSecurityInformation|protectedDaclSecurityInformation,
		owner, 0, uintptr(dacl), 0); r != 0 {
		return fmt.Errorf("cannot take ownership: %v", callErr)
	}
	return nil
}

func takeoverOpened(h syscall.Handle) error {
	attrs, reparse, err := handleAttrTag(h)
	if err != nil {
		return err
	}
	if reparse {
		return errors.New("refusing to take ownership of a reparse point")
	}
	// Directories cannot be hardlinked; restricting takeover to them keeps a
	// hardlink in a squatted location from rewriting the descriptor of a file
	// outside the product directories.
	if attrs&fileAttributeDirectory == 0 {
		return errors.New("refusing to take ownership of a file")
	}
	return setOwnerAndDaclHandle(h)
}

func takeoverPath(path string) error {
	h, err := openNoFollow(path, accessWriteOwner|accessWriteDac|accessReadControl|
		accessFileReadAttributes|accessSynchronize)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	return takeoverOpened(h)
}

func takeoverRelative(parent syscall.Handle, name string, isDir bool) error {
	h, status, err := openRelativeAccess(parent, name, isDir,
		accessWriteOwner|accessWriteDac|accessReadControl|accessFileReadAttributes|accessSynchronize)
	if err != nil {
		return err
	}
	if status != 0 {
		return fmt.Errorf("cannot open %q for takeover: 0x%x", name, status)
	}
	defer syscall.CloseHandle(h)
	return takeoverOpened(h)
}

// removeTreeNoFollow deletes a tree through directory handles. Every child is
// opened relative to its verified parent with FILE_OPEN_REPARSE_POINT, so a
// junction swapped in mid-delete is removed as a link and never traversed;
// no path is ever re-resolved between listing and deletion. Objects a user
// squatted with a deny-all DACL are taken over with SeTakeOwnership.
func removeTreeNoFollow(path string) error {
	access := uint32(accessDelete | accessFileReadData | accessFileReadAttributes |
		accessFileWriteAttributes | accessReadControl | accessSynchronize)
	h, err := openNoFollow(path, access)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return err
		}
		if terr := takeoverPath(path); terr != nil {
			return err
		}
		h, err = openNoFollow(path, access)
		if err != nil {
			return err
		}
	}
	defer syscall.CloseHandle(h)
	return removeOpened(h, 0)
}

func hasReparse(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	const invalid = ^uintptr(0)
	const reparsePoint = 0x400
	r, _, _ := procGetFileAttributes.Call(uintptr(unsafe.Pointer(p)))
	if r == invalid {
		return false
	}
	return r&reparsePoint != 0
}

func fileOwnerTrusted(path string) bool {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var owner uintptr
	var sd uintptr
	const seFileObject = 1
	const ownerSecurityInformation = 1
	rc, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(p)),
		seFileObject,
		ownerSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&sd)))
	if rc != 0 || owner == 0 {
		return false
	}
	if sd != 0 {
		defer procLocalFree.Call(sd)
	}
	var sidStr *uint16
	ok, _, _ := procConvertSidToStringSid.Call(owner, uintptr(unsafe.Pointer(&sidStr)))
	if ok == 0 || sidStr == nil {
		return false
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(sidStr)))
	sid := utf16z(sidStr)
	return sid == "S-1-5-32-544" || sid == "S-1-5-18" ||
		sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

func dataDirTrusted() bool {
	if st, err := os.Lstat(programDataDir()); err != nil {
		if os.IsNotExist(err) {
			return true
		}
		return false
	} else if !st.IsDir() {
		return false
	}
	if hasReparse(programDataDir()) || !fileOwnerTrusted(programDataDir()) {
		return false
	}
	if userCanWriteDir(programDataDir(), currentUserSID()) {
		return false
	}
	if fileExists(statePath()) {
		if !fileOwnerTrusted(statePath()) || hasReparse(statePath()) ||
			userCanWriteDir(statePath(), currentUserSID()) {
			return false
		}
	}
	return true
}

func dirMatchesACL(path, expected string) bool {
	if expected == "" {
		return false
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	var sd uintptr
	const seFileObject = 1
	const ownerGroupDacl = 0x1 | 0x2 | 0x4
	rc, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(p)),
		seFileObject,
		ownerGroupDacl,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&sd)))
	if rc != 0 || sd == 0 {
		return false
	}
	defer procLocalFree.Call(sd)
	var str *uint16
	var size uint32
	const sddlRevision1 = 1
	ok, _, _ := procConvertSDToString.Call(
		sd,
		sddlRevision1,
		ownerGroupDacl,
		uintptr(unsafe.Pointer(&str)),
		uintptr(unsafe.Pointer(&size)))
	if ok == 0 || str == nil {
		return false
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(str)))
	return strings.EqualFold(utf16z(str), expected)
}

func legacyDataDirTrusted() bool {
	if !dirExists(legacyProgramDataDir()) {
		return true
	}
	if hasReparse(legacyProgramDataDir()) || !fileOwnerTrusted(legacyProgramDataDir()) {
		return false
	}
	if userCanWriteDir(legacyProgramDataDir(), currentUserSID()) {
		return false
	}
	if fileExists(legacyStatePath()) {
		if !fileOwnerTrusted(legacyStatePath()) || hasReparse(legacyStatePath()) ||
			userCanWriteDir(legacyStatePath(), currentUserSID()) {
			return false
		}
	}
	return true
}

type aclHeader struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type aceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

type accessAllowedAce struct {
	Header   aceHeader
	Mask     uint32
	SidStart uint32
}

type sidAndAttributes struct {
	Sid        uintptr
	Attributes uint32
}

type tokenGroups struct {
	GroupCount uint32
	Groups     [1]sidAndAttributes
}

// tokenGroupSIDs returns the backing buffer together with the SIDs that point
// into it; the caller must keep the buffer alive until the last EqualSid call.
func tokenGroupSIDs() ([]byte, []uintptr) {
	var token uintptr
	const tokenQuery = 0x0008
	proc, _, _ := procGetCurrentProcess.Call()
	if r, _, _ := procOpenProcessToken.Call(proc, tokenQuery, uintptr(unsafe.Pointer(&token))); r == 0 || token == 0 {
		return nil, nil
	}
	defer syscall.CloseHandle(syscall.Handle(token))
	var size uint32
	const tokenGroupsInfo = 2
	procGetTokenInformation.Call(token, tokenGroupsInfo, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if r, _, _ := procGetTokenInformation.Call(token, tokenGroupsInfo,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, nil
	}
	tg := (*tokenGroups)(unsafe.Pointer(&buf[0]))
	n := int(tg.GroupCount)
	if n <= 0 || n > 1024 {
		return nil, nil
	}
	groups := unsafe.Slice(&tg.Groups[0], n)
	out := make([]uintptr, 0, n)
	const seGroupUseForDenyOnly = 0x10
	for _, g := range groups {
		if g.Sid == 0 || g.Attributes&seGroupUseForDenyOnly != 0 {
			continue
		}
		if sidEqualsString(g.Sid, "S-1-5-32-544") || sidEqualsString(g.Sid, "S-1-5-18") {
			continue
		}
		out = append(out, g.Sid)
	}
	return buf, out
}

func sidEqualsString(sid uintptr, s string) bool {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		return false
	}
	var other uintptr
	if r, _, _ := procConvertStringSid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&other))); r == 0 || other == 0 {
		return false
	}
	defer procLocalFree.Call(other)
	eq, _, _ := procEqualSid.Call(sid, other)
	return eq != 0
}

// userCanWriteDir fails closed: any unreadable DACL, null DACL, deny ACE for
// the user, or allow ACE granting write/delete/ownership rights is treated as
// writable.
func userCanWriteDir(path, sidString string) bool {
	const (
		fileWriteData       = 0x2
		fileAppendData      = 0x4
		fileWriteEA         = 0x10
		fileWriteAttributes = 0x100
		fileDeleteChild     = 0x40
		fileDelete          = 0x10000
		writeDac            = 0x40000
		writeOwner          = 0x80000
		genericAll          = 0x10000000
		genericWrite        = 0x40000000
	)
	return userHasRights(path, sidString, fileWriteData|fileAppendData|fileWriteEA|fileWriteAttributes|
		fileDeleteChild|fileDelete|writeDac|writeOwner|genericAll|genericWrite)
}

// userCanModifyDirObject reports whether the user can rename, delete, or
// rewrite the security of the directory itself. Create-file rights inside it
// are deliberately ignored.
func userCanModifyDirObject(path, sidString string) bool {
	const (
		fileDeleteChild = 0x40
		fileDelete      = 0x10000
		writeDac        = 0x40000
		writeOwner      = 0x80000
		genericAll      = 0x10000000
	)
	return userHasRights(path, sidString, fileDeleteChild|fileDelete|writeDac|writeOwner|genericAll)
}

// userHasRights fails closed: any unreadable DACL, null DACL, deny ACE for
// the user, or allow ACE granting the requested rights is treated as writable.
func userHasRights(path, sidString string, mask uint32) bool {
	if sidString == "" {
		return true
	}
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	sidStr, err := syscall.UTF16PtrFromString(sidString)
	if err != nil {
		return true
	}
	var userSid uintptr
	ok, _, _ := procConvertStringSid.Call(uintptr(unsafe.Pointer(sidStr)), uintptr(unsafe.Pointer(&userSid)))
	if ok == 0 || userSid == 0 {
		return true
	}
	defer procLocalFree.Call(userSid)
	groupBuf, groups := tokenGroupSIDs()
	defer runtime.KeepAlive(groupBuf)
	var trustees []uintptr
	if !sidEqualsString(userSid, "S-1-5-18") && !sidEqualsString(userSid, "S-1-5-32-544") {
		trustees = append(trustees, userSid)
	}
	trustees = append(trustees, groups...)

	var sd uintptr
	const seFileObject = 1
	const daclSecurityInformation = 4
	rc, _, _ := procGetNamedSecurityInfo.Call(
		uintptr(unsafe.Pointer(p)),
		seFileObject,
		daclSecurityInformation,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&sd)))
	if rc != 0 || sd == 0 {
		return true
	}
	defer procLocalFree.Call(sd)

	var present int32
	var dacl unsafe.Pointer
	var defaulted int32
	ok, _, _ = procGetSdDacl.Call(
		sd,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || dacl == nil {
		return true
	}

	count := (*aclHeader)(dacl).AceCount
	for i := uint16(0); i < count; i++ {
		var ace unsafe.Pointer
		if r, _, _ := procGetAce.Call(uintptr(dacl), uintptr(i), uintptr(unsafe.Pointer(&ace))); r == 0 || ace == nil {
			return true
		}
		h := (*aceHeader)(ace)
		if h.AceType != 0 && h.AceType != 1 {
			return true
		}
		const inheritOnlyAce = 0x08
		if h.AceFlags&inheritOnlyAce != 0 {
			continue
		}
		sidAt := uintptr(unsafe.Add(ace, unsafe.Offsetof(accessAllowedAce{}.SidStart)))
		matched := sidEqualsString(sidAt, "S-1-1-0")
		for _, trustee := range trustees {
			eq, _, _ := procEqualSid.Call(sidAt, trustee)
			if eq != 0 {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if h.AceType == 1 {
			return true
		}
		a := (*accessAllowedAce)(ace)
		if a.Mask&mask != 0 {
			return true
		}
	}
	return false
}

func adminTempDir() string { return filepath.Join(programDataBaseDir(), appName+"Admin") }

// stableStagingBase returns a directory whose path components the invoking
// user can neither rename nor repoint and whose owner is trusted. ProgramData
// lets standard users create files but not modify the directory object.
// imagePathStableForElevation reports whether the running image and its whole
// path can be trusted through UAC without staging: the file and every ancestor
// are administrator-owned, not reparse points, and not modifiable by the
// invoking user.
func imagePathStableForElevation(exe string) bool {
	sid := currentUserSID()
	if sid == "" || !fileExists(exe) || hasReparse(exe) {
		return false
	}
	if !fileOwnerTrusted(exe) || userCanWriteDir(exe, sid) {
		return false
	}
	// The image's own directory must also deny the user file creation: a
	// sibling <name>.exe.manifest or .local would load before main runs.
	if userCanWriteDir(filepath.Dir(exe), sid) {
		return false
	}
	dir := filepath.Dir(exe)
	for {
		if hasReparse(dir) || !fileOwnerTrusted(dir) || userCanModifyDirObject(dir, sid) {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
		dir = parent
	}
}

func stableStagingBase() (string, error) {
	base := programDataBaseDir()
	if base == "" {
		return "", errors.New("cannot locate the ProgramData directory")
	}
	sid := currentUserSID()
	if sid == "" {
		return "", errors.New("cannot determine the current user SID")
	}
	for _, p := range []string{base, filepath.Dir(base)} {
		if hasReparse(p) {
			return "", fmt.Errorf("%s is a reparse point", p)
		}
	}
	if !fileOwnerTrusted(base) {
		return "", fmt.Errorf("%s is not owned by Administrators or SYSTEM", base)
	}
	if userCanModifyDirObject(base, sid) || userCanModifyDirObject(filepath.Dir(base), sid) {
		return "", fmt.Errorf("%s can be modified by the current user", base)
	}
	return base, nil
}

func verifyAuthenticode(path string) error {
	script := fmt.Sprintf(`$s=Get-AuthenticodeSignature -LiteralPath %s; `+
		`if ($s.Status -ne 'Valid') { 'status: '+$s.Status; exit } `+
		`$c=$s.SignerCertificate; `+
		`$cn=($c.Subject -split ',' | Where-Object { $_ -match '^\s*CN=' } | Select-Object -First 1); `+
		`if ($cn.Trim() -ne 'CN=Microsoft Corporation') { 'signer: '+$c.Subject; exit } `+
		`$chain=New-Object System.Security.Cryptography.X509Certificates.X509Chain; `+
		`$chain.ChainPolicy.RevocationMode='Online'; `+
		`$chain.ChainPolicy.TrustMode='CustomRootTrust'; `+
		`foreach ($r in (Get-ChildItem Cert:\LocalMachine\Root)) { [void]$chain.ChainPolicy.CustomTrustStore.Add($r) }; `+
		`if (-not $chain.Build($c)) { 'chain: signer is not trusted by machine roots'; exit } `+
		`'ok'`, psQuote(path))
	out, code, err := runCommand(systemPowerShell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("Authenticode check failed (exit %d): %s", code, truncate(out, 400))
	}
	if strings.TrimSpace(out) != "ok" {
		return fmt.Errorf("Authenticode verification failed: %s", truncate(out, 400))
	}
	return nil
}

func convertSecurityDescriptor(sddl string) (uintptr, error) {
	p, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return 0, err
	}
	var sd uintptr
	var size uint32
	const revision1 = 1
	ok, _, _ := procConvertStringSD.Call(
		uintptr(unsafe.Pointer(p)),
		revision1,
		uintptr(unsafe.Pointer(&sd)),
		uintptr(unsafe.Pointer(&size)))
	if ok == 0 || sd == 0 {
		return 0, fmt.Errorf("cannot parse security descriptor")
	}
	return sd, nil
}

func createSecureDir(path, sddl string) error {
	sd, err := convertSecurityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	if err := syscall.CreateDirectory(p, &sa); err != nil {
		if err == syscall.ERROR_ALREADY_EXISTS {
			return fmt.Errorf("%s already exists: %w", path, os.ErrExist)
		}
		return err
	}
	return nil
}

func setSecureDir(path, sddl string) error {
	h, err := openNoFollow(path, accessReadControl|accessWriteDac|accessWriteOwner|accessFileReadAttributes)
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	attrs, reparse, err := handleAttrTag(h)
	if err != nil {
		return err
	}
	if reparse {
		return fmt.Errorf("%s is a reparse point", path)
	}
	if attrs&fileAttributeDirectory == 0 {
		return fmt.Errorf("%s is not a directory", path)
	}
	sd, err := convertSecurityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	var owner uintptr
	var ownerDefaulted int32
	if r, _, _ := procGetSdOwner.Call(sd, uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&ownerDefaulted))); r == 0 || owner == 0 {
		return fmt.Errorf("security descriptor for %s has no owner", path)
	}
	var present int32
	var dacl unsafe.Pointer
	var defaulted int32
	if r, _, _ := procGetSdDacl.Call(sd, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 || present == 0 || dacl == nil {
		return fmt.Errorf("security descriptor for %s has no DACL", path)
	}
	const seFileObject = 1
	const ownerSecurityInformation = 0x1
	const daclSecurityInformation = 0x4
	const protectedDaclSecurityInformation = 0x80000000
	if r, _, callErr := procSetSecurityInfo.Call(uintptr(h), seFileObject,
		ownerSecurityInformation|daclSecurityInformation|protectedDaclSecurityInformation,
		owner, 0, uintptr(dacl), 0); r != 0 {
		return fmt.Errorf("SetSecurityInfo %s: %v", path, callErr)
	}
	return nil
}

func dataDirACL(sid string) string {
	return "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;" + sid + ")"
}

func ipcDirACL(sid string) string {
	return "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GX;;;" + sid + ")"
}

func adminDirACL() string {
	return "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"
}

func installDirACL() string {
	return "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)"
}

func installFileACL() string {
	return "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GRGX;;;BU)"
}

func fileReadACL(sid string) string {
	if sid == "" {
		return "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)"
	}
	return "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;" + sid + ")"
}

// ensureSecureFile replaces a file the invoking user owns with one created
// under an explicit administrator owner and protected DACL.
func ensureSecureFile(path, sddl string) error {
	if fileExists(path) {
		if fileOwnerTrusted(path) {
			return nil
		}
		if err := removeTreeNoFollow(path); err != nil {
			return err
		}
	}
	return writeFileSecure(path, nil, sddl)
}

// writeFileSecure creates the file with an explicit owner and a protected DACL,
// then atomically replaces the destination. A file created with the default
// owner would stay owned by the installing user, who has implicit WRITE_DAC on
// it and could rewrite an executable that the elevated task later runs.
func writeFileSecure(path string, data []byte, sddl string) error {
	sd, err := convertSecurityDescriptor(sddl)
	if err != nil {
		return err
	}
	defer procLocalFree.Call(sd)
	tmp := path + ".new-" + newID()
	p, err := syscall.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	sa := syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_WRITE, 0, &sa, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	for written := 0; written < len(data); {
		var n uint32
		if err := syscall.WriteFile(h, data[written:], &n, nil); err != nil || n == 0 {
			syscall.CloseHandle(h)
			os.Remove(tmp)
			return fmt.Errorf("cannot write %s", path)
		}
		written += int(n)
	}
	if err := syscall.CloseHandle(h); err != nil {
		os.Remove(tmp)
		return err
	}
	src, err := syscall.UTF16PtrFromString(tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	dst, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	const replaceExisting = 0x1
	const writeThrough = 0x8
	if r, _, callErr := procMoveFileEx.Call(uintptr(unsafe.Pointer(src)),
		uintptr(unsafe.Pointer(dst)), replaceExisting|writeThrough); r == 0 {
		os.Remove(tmp)
		return fmt.Errorf("cannot replace %s: %v", path, callErr)
	}
	return nil
}

func secureInstallDir() error {
	path := installDir()
	if !dirExists(path) {
		if err := createSecureDir(path, installDirACL()); err == nil {
			return nil
		} else if !errors.Is(err, os.ErrExist) {
			return err
		}
	}
	if hasReparse(path) {
		return fmt.Errorf("%s is a reparse point", path)
	}
	if !fileOwnerTrusted(path) {
		return fmt.Errorf("%s is not owned by Administrators or SYSTEM", path)
	}
	return setSecureDir(path, installDirACL())
}

func secureDataDir(user string) error {
	if user == "" {
		return fmt.Errorf("cannot secure data directory without a user")
	}
	sid := currentUserSID()
	if sid == "" {
		return fmt.Errorf("cannot determine the current user SID")
	}
	specs := []struct{ path, sddl string }{
		{programDataDir(), dataDirACL(sid)},
		{filepath.Join(programDataDir(), "ipc"), ipcDirACL(sid)},
		{sessionsDir(), ipcDirACL(sid)},
		{filepath.Join(programDataDir(), "logs"), dataDirACL(sid)},
		{adminTempDir(), adminDirACL()},
	}
	for _, s := range specs {
		if !dirExists(s.path) {
			if err := createSecureDir(s.path, s.sddl); err == nil {
				continue
			} else if !errors.Is(err, os.ErrExist) {
				return err
			}
		}
		if hasReparse(s.path) {
			return fmt.Errorf("%s is a reparse point", s.path)
		}
		if !fileOwnerTrusted(s.path) {
			return fmt.Errorf("%s is not owned by Administrators or SYSTEM", s.path)
		}
		if err := setSecureDir(s.path, s.sddl); err != nil {
			return err
		}
	}
	return nil
}

// secureTraceTree transfers ownership of a kept trace to Administrators and
// gives the user read (and delete) access without the owner's implicit
// WRITE_DAC, so a kept ETL cannot be rewritten after parsing.
func secureTraceTree(root, user string) error {
	sid := currentUserSID()
	if user == "" || sid == "" {
		return fmt.Errorf("cannot secure the trace directory without a user")
	}
	dirACL := "O:BAG:SYD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;" + sid + ")(A;OICI;SD;;;" + sid + ")"
	fileACL := "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;" + sid + ")(A;;SD;;;" + sid + ")"
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		h, oerr := openNoFollow(path, accessWriteOwner|accessWriteDac|accessReadControl|
			accessFileReadAttributes|accessSynchronize)
		if oerr != nil {
			return oerr
		}
		sddl := fileACL
		if info.IsDir() {
			sddl = dirACL
		}
		aerr := setHandleACL(h, sddl)
		syscall.CloseHandle(h)
		return aerr
	})
}

// verifySocketACL reads the socket's effective DACL and requires a trusted
// owner with exactly Administrators, SYSTEM, and the installing user, where the
// user holds no right beyond read, write, read-control, and synchronize.
func verifySocketACL(user string) error {
	sidString := currentUserSID()
	if user == "" || sidString == "" {
		return errors.New("cannot verify the socket ACL without a user")
	}
	p, err := syscall.UTF16PtrFromString(socketPath())
	if err != nil {
		return err
	}
	var sd uintptr
	const seFileObject = 1
	const ownerDacl = 0x1 | 0x4
	if rc, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(p)), seFileObject,
		ownerDacl, 0, 0, 0, 0, uintptr(unsafe.Pointer(&sd))); rc != 0 || sd == 0 {
		return errors.New("cannot read the socket security descriptor")
	}
	defer procLocalFree.Call(sd)
	var owner uintptr
	var ownerDefaulted int32
	if r, _, _ := procGetSdOwner.Call(sd, uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&ownerDefaulted))); r == 0 || owner == 0 || !ownerSIDTrusted(owner) {
		return errors.New("the socket is not owned by a trusted principal")
	}
	var present int32
	var dacl unsafe.Pointer
	var defaulted int32
	if r, _, _ := procGetSdDacl.Call(sd, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 || present == 0 || dacl == nil {
		return errors.New("the socket has no DACL")
	}
	sidPtr, err := syscall.UTF16PtrFromString(sidString)
	if err != nil {
		return err
	}
	var userSid uintptr
	if ok, _, _ := procConvertStringSid.Call(uintptr(unsafe.Pointer(sidPtr)),
		uintptr(unsafe.Pointer(&userSid))); ok == 0 || userSid == 0 {
		return errors.New("cannot parse the current user SID")
	}
	defer procLocalFree.Call(userSid)
	const allowedUserRights = 0x1 | 0x2 | 0x20000 | 0x100000
	count := (*aclHeader)(dacl).AceCount
	for i := uint16(0); i < count; i++ {
		var ace unsafe.Pointer
		if r, _, _ := procGetAce.Call(uintptr(dacl), uintptr(i), uintptr(unsafe.Pointer(&ace))); r == 0 || ace == nil {
			return errors.New("cannot read the socket DACL")
		}
		h := (*aceHeader)(ace)
		if h.AceType != 0 {
			return errors.New("the socket DACL contains a non-allow ACE")
		}
		sidAt := uintptr(unsafe.Add(ace, unsafe.Offsetof(accessAllowedAce{}.SidStart)))
		mask := (*accessAllowedAce)(ace).Mask
		switch {
		case sidEqualsString(sidAt, "S-1-5-32-544"), sidEqualsString(sidAt, "S-1-5-18"):
		case func() bool { eq, _, _ := procEqualSid.Call(sidAt, userSid); return eq != 0 }():
			if mask&^uint32(allowedUserRights) != 0 {
				return errors.New("the socket DACL grants the user extra access")
			}
		default:
			return errors.New("the socket DACL grants an unexpected principal")
		}
	}
	return nil
}

func secureSocket(user string) error {
	if user == "" {
		return fmt.Errorf("cannot secure socket without a user")
	}
	if err := icacls(socketPath(),
		"/inheritance:r",
		"/grant:r", "*S-1-5-18:F",
		"*S-1-5-32-544:F",
		user+":(RD,WD,RC,S)"); err != nil {
		return err
	}
	if err := icacls(socketPath(), "/setowner", "*S-1-5-32-544"); err != nil {
		return err
	}
	if err := icacls(socketPath(), "/setintegritylevel", "M"); err != nil {
		return err
	}
	return nil
}

func taskSecurityDescriptor(user string) string {
	if sid := currentUserSID(); sid != "" {
		return "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;GRGX;;;" + sid + ")"
	}
	return "O:BAG:SYD:P(A;;FA;;;BA)(A;;FA;;;SY)"
}

type taskDefinition struct {
	Registration struct {
		SecurityDescriptor string `xml:"SecurityDescriptor"`
	} `xml:"RegistrationInfo"`
	Principals struct {
		Principal struct {
			UserID    string `xml:"UserId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Triggers struct {
		Logon struct {
			UserID string `xml:"UserId"`
		} `xml:"LogonTrigger"`
	} `xml:"Triggers"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
	Settings struct {
		DisallowStartIfOnBatteries string `xml:"DisallowStartIfOnBatteries"`
		StopIfGoingOnBatteries     string `xml:"StopIfGoingOnBatteries"`
		ExecutionTimeLimit         string `xml:"ExecutionTimeLimit"`
	} `xml:"Settings"`
}

func verifyTaskSecurity(user string) error {
	out, code, err := runCommand("schtasks.exe", "/Query", "/TN", taskName, "/XML")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("schtasks /Query failed: %s", truncate(out, 800))
	}
	text := decodeTaskFile([]byte(out))
	var def taskDefinition
	dec := xml.NewDecoder(strings.NewReader(text))
	// decodeTaskFile has already converted the bytes to UTF-8; the XML
	// declaration still says UTF-16, so accept the already-decoded stream.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := dec.Decode(&def); err != nil {
		return fmt.Errorf("cannot parse task definition: %w", err)
	}
	if len(def.Actions.Exec) != 1 {
		return fmt.Errorf("task must have exactly one Exec action")
	}
	command := strings.Trim(strings.TrimSpace(def.Actions.Exec[0].Command), `"`)
	if !samePath(command, installDaemonPath()) {
		return fmt.Errorf("task command is %q, want %q", command, installDaemonPath())
	}
	if strings.TrimSpace(def.Actions.Exec[0].Arguments) != "daemon-run" {
		return fmt.Errorf("task arguments are %q", def.Actions.Exec[0].Arguments)
	}
	if def.Principals.Principal.RunLevel != "HighestAvailable" {
		return fmt.Errorf("task run level is %q", def.Principals.Principal.RunLevel)
	}
	wantLogon := "InteractiveToken"
	if isSystemUser(user) {
		wantLogon = "ServiceAccount"
	}
	if def.Principals.Principal.LogonType != wantLogon {
		return fmt.Errorf("task logon type is %q", def.Principals.Principal.LogonType)
	}
	if def.Settings.DisallowStartIfOnBatteries != "false" ||
		def.Settings.StopIfGoingOnBatteries != "false" ||
		def.Settings.ExecutionTimeLimit != "PT0S" {
		return fmt.Errorf("task power settings are not the expected values")
	}
	sid := currentUserSID()
	if sid == "" {
		return fmt.Errorf("cannot determine the current user SID")
	}
	principal := strings.TrimSpace(def.Principals.Principal.UserID)
	if !strings.EqualFold(principal, sid) && !strings.EqualFold(principal, user) {
		return fmt.Errorf("task principal is %q", principal)
	}
	trigger := strings.TrimSpace(def.Triggers.Logon.UserID)
	if trigger != "" && !strings.EqualFold(trigger, sid) && !strings.EqualFold(trigger, user) {
		return fmt.Errorf("task logon trigger user is %q", trigger)
	}
	sd := strings.TrimSpace(def.Registration.SecurityDescriptor)
	if !strings.HasPrefix(sd, "O:BAG:SYD:P") {
		return fmt.Errorf("task security descriptor is not protected and administrator owned: %s", sd)
	}
	if !strings.EqualFold(sd, taskSecurityDescriptor(user)) {
		return fmt.Errorf("task DACL is not exactly the expected descriptor: %s", sd)
	}
	if !isSystemUser(user) {
		if !strings.Contains(sd, "(A;;GRGX;;;"+sid+")") {
			return fmt.Errorf("task DACL does not grant the user execute-only access: %s", sd)
		}
		if strings.Count(sd, sid) != 1 {
			return fmt.Errorf("task DACL grants the user additional access: %s", sd)
		}
	}
	if err := verifyEffectiveTaskACL(); err != nil {
		return err
	}
	return nil
}

func ownerSIDTrusted(owner uintptr) bool {
	var str *uint16
	if ok, _, _ := procConvertSidToStringSid.Call(owner, uintptr(unsafe.Pointer(&str))); ok == 0 || str == nil {
		return false
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(str)))
	sid := utf16z(str)
	return sid == "S-1-5-32-544" || sid == "S-1-5-18" ||
		sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// taskCacheSD reads the self-relative security descriptor the Task Scheduler
// stored for the task. The registry value is the descriptor used for access
// checks; the XML field is only the registration input.
func taskCacheSD() ([]byte, error) {
	const hkeyLocalMachine = 0x80000002
	const keyRead = 0x20019
	key, err := syscall.UTF16PtrFromString(
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\` + taskName)
	if err != nil {
		return nil, err
	}
	var hkey uintptr
	if r, _, _ := procRegOpenKeyEx.Call(hkeyLocalMachine, uintptr(unsafe.Pointer(key)), 0,
		keyRead, uintptr(unsafe.Pointer(&hkey))); r != 0 || hkey == 0 {
		return nil, fmt.Errorf("cannot open the task cache key (error %d)", r)
	}
	defer procRegCloseKey.Call(hkey)
	name, err := syscall.UTF16PtrFromString("SD")
	if err != nil {
		return nil, err
	}
	var valueType, size uint32
	if r, _, _ := procRegQueryValueEx.Call(hkey, uintptr(unsafe.Pointer(name)), 0,
		uintptr(unsafe.Pointer(&valueType)), 0, uintptr(unsafe.Pointer(&size))); r != 0 || size == 0 {
		return nil, errors.New("the scheduled task has no stored security descriptor")
	}
	if size > 64<<10 {
		return nil, errors.New("the stored task security descriptor is too large")
	}
	buf := make([]byte, size)
	if r, _, _ := procRegQueryValueEx.Call(hkey, uintptr(unsafe.Pointer(name)), 0,
		uintptr(unsafe.Pointer(&valueType)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size))); r != 0 {
		return nil, errors.New("cannot read the stored task security descriptor")
	}
	const regBinary = 3
	if valueType != regBinary {
		return nil, errors.New("the stored task security descriptor has an unexpected type")
	}
	return buf[:size], nil
}

// verifyEffectiveTaskACL reads the security descriptor the Task Scheduler
// actually stored, not the one echoed from the task XML, and requires that no
// ACE grants the invoking user any write, delete, or ownership right.
func verifyEffectiveTaskACL() error {
	buf, err := taskCacheSD()
	if err != nil {
		return err
	}
	sd := uintptr(unsafe.Pointer(&buf[0]))
	defer runtime.KeepAlive(buf)
	var owner uintptr
	var ownerDefaulted int32
	if r, _, _ := procGetSdOwner.Call(sd, uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&ownerDefaulted))); r == 0 || owner == 0 {
		return errors.New("the effective task descriptor has no owner")
	}
	if !ownerSIDTrusted(owner) {
		return errors.New("the scheduled task is not owned by Administrators or SYSTEM")
	}
	var present int32
	var dacl unsafe.Pointer
	var defaulted int32
	if r, _, _ := procGetSdDacl.Call(sd, uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted))); r == 0 || present == 0 || dacl == nil {
		return errors.New("the effective task descriptor has no DACL")
	}
	sidString := currentUserSID()
	sidPtr, err := syscall.UTF16PtrFromString(sidString)
	if err != nil || sidString == "" {
		return errors.New("cannot determine the current user SID")
	}
	var userSid uintptr
	if ok, _, _ := procConvertStringSid.Call(uintptr(unsafe.Pointer(sidPtr)),
		uintptr(unsafe.Pointer(&userSid))); ok == 0 || userSid == 0 {
		return errors.New("cannot parse the current user SID")
	}
	defer procLocalFree.Call(userSid)
	groupBuf, groups := tokenGroupSIDs()
	defer runtime.KeepAlive(groupBuf)
	var trustees []uintptr
	if !sidEqualsString(userSid, "S-1-5-18") && !sidEqualsString(userSid, "S-1-5-32-544") {
		trustees = append(trustees, userSid)
	}
	trustees = append(trustees, groups...)
	const (
		fileWriteData       = 0x2
		fileAppendData      = 0x4
		fileWriteEA         = 0x10
		fileDeleteChild     = 0x40
		fileWriteAttributes = 0x100
		fileDelete          = 0x10000
		writeDac            = 0x40000
		writeOwner          = 0x80000
		genericAll          = 0x10000000
		genericWrite        = 0x40000000
	)
	writeMask := uint32(fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild |
		fileWriteAttributes | fileDelete | writeDac | writeOwner | genericAll | genericWrite)
	count := (*aclHeader)(dacl).AceCount
	for i := uint16(0); i < count; i++ {
		var ace unsafe.Pointer
		if r, _, _ := procGetAce.Call(uintptr(dacl), uintptr(i), uintptr(unsafe.Pointer(&ace))); r == 0 || ace == nil {
			return errors.New("cannot read the effective task DACL")
		}
		h := (*aceHeader)(ace)
		if h.AceType != 0 && h.AceType != 1 {
			return errors.New("the effective task DACL contains an unsupported ACE")
		}
		sidAt := uintptr(unsafe.Add(ace, unsafe.Offsetof(accessAllowedAce{}.SidStart)))
		if h.AceType == 1 {
			if sidEqualsString(sidAt, "S-1-5-32-544") || sidEqualsString(sidAt, "S-1-5-18") {
				return errors.New("the effective task DACL denies Administrators or SYSTEM")
			}
			continue
		}
		matched := sidEqualsString(sidAt, "S-1-1-0")
		for _, trustee := range trustees {
			if eq, _, _ := procEqualSid.Call(sidAt, trustee); eq != 0 {
				matched = true
				break
			}
		}
		if matched && (*accessAllowedAce)(ace).Mask&writeMask != 0 {
			return fmt.Errorf("the effective task DACL grants the user write access (mask 0x%x)",
				(*accessAllowedAce)(ace).Mask)
		}
	}
	return nil
}

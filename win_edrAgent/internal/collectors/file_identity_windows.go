//go:build windows
// +build windows

package collectors

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─────────────────────────────────────────────────────────────────────────────
// File identity: SHA-256, PE version resource and Authenticode signature.
//
// Signature status values (consumed by the sigma engine risk scorer):
//   microsoft — valid signature (embedded or Windows catalog) by Microsoft
//   trusted   — valid signature by another publisher
//   unsigned  — no embedded signature and no catalog entry
//   invalid   — a signature is present but does not verify (tampered,
//               untrusted root, explicitly distrusted, ...)
//   ""        — file unreadable
//
// Verification uses WinVerifyTrust (WINTRUST_ACTION_GENERIC_VERIFY_V2) on the
// embedded signature, then on the Windows catalogs (most OS binaries are
// catalog-signed and carry no embedded signature). Revocation is not checked
// online (no network I/O on the telemetry path). Results are cached per
// (path, size, modification time), so each file version is verified once.
// ─────────────────────────────────────────────────────────────────────────────

// FileIdentity describes an executable image.
type FileIdentity struct {
	SHA256           string
	OriginalFileName string
	Company          string
	Product          string
	Description      string
	SignatureStatus  string
	Signer           string
}

const (
	maxHashBytes      = 128 << 20 // larger files are not hashed
	maxVerifyBytes    = 512 << 20 // larger files are not signature-verified
	identityCacheSize = 8192
)

type identityKey struct {
	path  string
	size  int64
	mtime int64
}

type identityCache struct {
	mu    sync.Mutex
	ll    *list.List
	items map[identityKey]*list.Element
	cap   int
}

type identityEntry struct {
	key identityKey
	val FileIdentity
}

var fileIdentities = &identityCache{ll: list.New(), items: map[identityKey]*list.Element{}, cap: identityCacheSize}

func (c *identityCache) get(k identityKey) (FileIdentity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.ll.MoveToFront(e)
		return e.Value.(*identityEntry).val, true
	}
	return FileIdentity{}, false
}

func (c *identityCache) put(k identityKey, v FileIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		e.Value.(*identityEntry).val = v
		c.ll.MoveToFront(e)
		return
	}
	c.items[k] = c.ll.PushFront(&identityEntry{key: k, val: v})
	for c.ll.Len() > c.cap {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.items, last.Value.(*identityEntry).key)
	}
}

// FileIdentityOf returns the (cached) identity of the file at path.
func FileIdentityOf(path string) FileIdentity {
	path = strings.TrimSpace(path)
	if path == "" || !strings.Contains(path, `\`) {
		return FileIdentity{}
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return FileIdentity{}
	}
	k := identityKey{strings.ToLower(path), st.Size(), st.ModTime().UnixNano()}
	if v, ok := fileIdentities.get(k); ok {
		return v
	}
	var id FileIdentity
	if st.Size() <= maxHashBytes {
		id.SHA256 = sha256File(path)
	}
	id.OriginalFileName, id.Company, id.Product, id.Description = versionStrings(path)
	if st.Size() <= maxVerifyBytes {
		id.SignatureStatus, id.Signer = verifyAuthenticode(path)
	}
	fileIdentities.put(k, id)
	return id
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ── PE version resource ──────────────────────────────────────────────────────

var (
	modVersion                   = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSizeEx = modVersion.NewProc("GetFileVersionInfoSizeExW")
	procGetFileVersionInfoEx     = modVersion.NewProc("GetFileVersionInfoExW")
)

// fileVerGetNeutral (FILE_VER_GET_NEUTRAL) reads the language-neutral
// version resource of the binary itself. Without it Windows returns the
// localized MUI resource (OriginalFilename "Cmd.Exe.MUI" instead of
// "Cmd.Exe"), which breaks Sigma OriginalFileName matching.
const fileVerGetNeutral = 0x02

// versionInfo loads the neutral version resource (falls back to the default
// lookup on systems without the Ex API).
func versionInfo(path string) []byte {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil
	}
	if procGetFileVersionInfoSizeEx.Find() == nil && procGetFileVersionInfoEx.Find() == nil {
		var zero uint32
		size, _, _ := procGetFileVersionInfoSizeEx.Call(fileVerGetNeutral, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&zero)))
		if size > 0 && size <= 4<<20 {
			buf := make([]byte, size)
			if r, _, _ := procGetFileVersionInfoEx.Call(fileVerGetNeutral, uintptr(unsafe.Pointer(p)), 0, size, uintptr(unsafe.Pointer(&buf[0]))); r != 0 {
				return buf
			}
		}
	}
	var zero windows.Handle
	size, err := windows.GetFileVersionInfoSize(path, &zero)
	if err != nil || size == 0 || size > 4<<20 {
		return nil
	}
	buf := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])) != nil {
		return nil
	}
	return buf
}

func versionStrings(path string) (original, company, product, description string) {
	buf := versionInfo(path)
	if len(buf) == 0 {
		return
	}
	var trans *[2]uint16
	var tlen uint32
	prefixes := []string{}
	if windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&trans), &tlen) == nil && tlen >= 4 && trans != nil {
		prefixes = append(prefixes, fmt.Sprintf(`\StringFileInfo\%04x%04x\`, trans[0], trans[1]))
	}
	// Common fallbacks: US English with Unicode / Western code pages.
	prefixes = append(prefixes, `\StringFileInfo\040904b0\`, `\StringFileInfo\040904e4\`)
	query := func(name string) string {
		for _, p := range prefixes {
			var ptr *uint16
			var n uint32
			if windows.VerQueryValue(unsafe.Pointer(&buf[0]), p+name, unsafe.Pointer(&ptr), &n) == nil && ptr != nil && n > 0 {
				return strings.TrimSpace(windows.UTF16PtrToString(ptr))
			}
		}
		return ""
	}
	return query("OriginalFilename"), query("CompanyName"), query("ProductName"), query("FileDescription")
}

// ── Authenticode ─────────────────────────────────────────────────────────────

var (
	modWintrust                              = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData        = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain       = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain         = modWintrust.NewProc("WTHelperGetProvCertFromChain")
	procCryptCATAdminAcquireContext          = modWintrust.NewProc("CryptCATAdminAcquireContext")
	procCryptCATAdminAcquireContext2         = modWintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFileHandle  = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle")
	procCryptCATAdminCalcHashFromFileHandle2 = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash     = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext       = modWintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext   = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext          = modWintrust.NewProc("CryptCATAdminReleaseContext")

	// DRIVER_ACTION_VERIFY {F750E6C3-38EE-11d1-85E5-00C04FC295EE}
	driverActionVerify = windows.GUID{Data1: 0xf750e6c3, Data2: 0x38ee, Data3: 0x11d1,
		Data4: [8]byte{0x85, 0xe5, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}
)

// winTrustCatalogInfo mirrors WINTRUST_CATALOG_INFO.
type winTrustCatalogInfo struct {
	Size                   uint32
	CatalogVersion         uint32
	CatalogFilePath        *uint16
	MemberTag              *uint16
	MemberFilePath         *uint16
	MemberFile             windows.Handle
	CalculatedFileHash     *byte
	CalculatedFileHashSize uint32
	CatalogContext         uintptr
	CatAdmin               windows.Handle
}

// cryptProviderCert mirrors the head of CRYPT_PROVIDER_CERT
// { DWORD cbStruct; PCCERT_CONTEXT pCert; ... }.
type cryptProviderCert struct {
	Size uint32
	Cert *windows.CertContext
}

// catalogInfo mirrors CATALOG_INFO.
type catalogInfo struct {
	Size        uint32
	CatalogFile [windows.MAX_PATH]uint16
}

// signerOf returns the leaf signer's display name from WinVerifyTrust state.
func signerOf(state windows.Handle) string {
	if procWTHelperProvDataFromStateData.Find() != nil {
		return ""
	}
	provData, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if provData == 0 {
		return ""
	}
	sgnr, _, _ := procWTHelperGetProvSignerFromChain.Call(provData, 0, 0, 0)
	if sgnr == 0 {
		return ""
	}
	provCert, _, _ := procWTHelperGetProvCertFromChain.Call(sgnr, 0)
	if provCert == 0 {
		return ""
	}
	// provCert points to a CRYPT_PROVIDER_CERT owned by the WinVerifyTrust
	// state (valid until WTD_STATEACTION_CLOSE).
	pc := *(**cryptProviderCert)(unsafe.Pointer(&provCert))
	if pc == nil || pc.Cert == nil {
		return ""
	}
	certCtx := pc.Cert
	buf := make([]uint16, 256)
	n := windows.CertGetNameString(certCtx, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf[:n-1])
}

// winVerify runs WinVerifyTrust for the given union choice and returns the
// verification error (nil = valid) and the signer.
func winVerify(choice uint32, info unsafe.Pointer) (error, string) {
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     choice,
		FileOrCatalogOrBlobOrSgnrOrCert: info,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
	}
	err := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	signer := ""
	if err == nil {
		signer = signerOf(data.StateData)
	}
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	return err, signer
}

func classifySigner(signer string) string {
	if strings.HasPrefix(strings.ToLower(signer), "microsoft ") {
		return "microsoft"
	}
	return "trusted"
}

// verifyAuthenticode returns (status, signer) for the file.
func verifyAuthenticode(path string) (string, string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", ""
	}
	fi := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	verr, signer := winVerify(windows.WTD_CHOICE_FILE, unsafe.Pointer(fi))
	if verr == nil {
		return classifySigner(signer), signer
	}
	if !isNoSignature(verr) {
		// A signature exists but does not verify: tampered or untrusted.
		return "invalid", ""
	}
	if status, signer, ok := verifyCatalog(path, p); ok {
		return status, signer
	}
	return "unsigned", ""
}

// isNoSignature matches the "no signature" family of WinVerifyTrust results.
func isNoSignature(err error) bool {
	if e, ok := err.(windows.Errno); ok {
		switch windows.Handle(e) {
		case windows.TRUST_E_NOSIGNATURE, windows.TRUST_E_SUBJECT_FORM_UNKNOWN, windows.TRUST_E_PROVIDER_UNKNOWN:
			return true
		}
	}
	return false
}

// verifyCatalog checks the Windows catalogs for the file's hash (SHA-256
// catalogs first, then legacy SHA-1). ok is false when no catalog lists it.
func verifyCatalog(path string, p *uint16) (string, string, bool) {
	f, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return "", "", false
	}
	defer windows.CloseHandle(f)

	for _, sha256Catalog := range []bool{true, false} {
		var admin windows.Handle
		if sha256Catalog {
			if procCryptCATAdminAcquireContext2.Find() != nil {
				continue
			}
			alg, _ := windows.UTF16PtrFromString("SHA256")
			if r, _, _ := procCryptCATAdminAcquireContext2.Call(uintptr(unsafe.Pointer(&admin)),
				uintptr(unsafe.Pointer(&driverActionVerify)), uintptr(unsafe.Pointer(alg)), 0, 0); r == 0 {
				continue
			}
		} else {
			if r, _, _ := procCryptCATAdminAcquireContext.Call(uintptr(unsafe.Pointer(&admin)),
				uintptr(unsafe.Pointer(&driverActionVerify)), 0); r == 0 {
				continue
			}
		}
		status, signer, ok := verifyInCatalogs(admin, f, path, sha256Catalog)
		procCryptCATAdminReleaseContext.Call(uintptr(admin), 0)
		if ok {
			return status, signer, true
		}
	}
	return "", "", false
}

func verifyInCatalogs(admin, f windows.Handle, path string, sha256Catalog bool) (string, string, bool) {
	calc := func(size *uint32, hash *byte) bool {
		var r uintptr
		if sha256Catalog {
			r, _, _ = procCryptCATAdminCalcHashFromFileHandle2.Call(uintptr(admin), uintptr(f),
				uintptr(unsafe.Pointer(size)), uintptr(unsafe.Pointer(hash)), 0)
		} else {
			r, _, _ = procCryptCATAdminCalcHashFromFileHandle.Call(uintptr(f),
				uintptr(unsafe.Pointer(size)), uintptr(unsafe.Pointer(hash)), 0)
		}
		return r != 0
	}
	var size uint32
	calc(&size, nil) // obtains the hash size
	if size == 0 || size > 64 {
		return "", "", false
	}
	hash := make([]byte, size)
	if _, err := windows.Seek(f, 0, io.SeekStart); err != nil {
		return "", "", false
	}
	if !calc(&size, &hash[0]) {
		return "", "", false
	}
	catCtx, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(uintptr(admin), uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
	if catCtx == 0 {
		return "", "", false
	}
	defer procCryptCATAdminReleaseCatalogContext.Call(uintptr(admin), catCtx, 0)

	ci := catalogInfo{Size: uint32(unsafe.Sizeof(catalogInfo{}))}
	if r, _, _ := procCryptCATCatalogInfoFromContext.Call(catCtx, uintptr(unsafe.Pointer(&ci)), 0); r == 0 {
		return "", "", false
	}
	tag, _ := windows.UTF16PtrFromString(strings.ToUpper(hex.EncodeToString(hash)))
	member, _ := windows.UTF16PtrFromString(path)
	info := &winTrustCatalogInfo{
		Size:                   uint32(unsafe.Sizeof(winTrustCatalogInfo{})),
		CatalogFilePath:        &ci.CatalogFile[0],
		MemberTag:              tag,
		MemberFilePath:         member,
		MemberFile:             f,
		CalculatedFileHash:     &hash[0],
		CalculatedFileHashSize: size,
		CatAdmin:               admin,
	}
	verr, signer := winVerify(windows.WTD_CHOICE_CATALOG, unsafe.Pointer(info))
	if verr != nil {
		return "invalid", "", true
	}
	return classifySigner(signer), signer, true
}

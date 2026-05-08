// Package security — AES-256-GCM encryption with DPAPI key protection.
//
//go:build windows
// +build windows

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/edr-platform/win-agent/internal/logging"
)

// Encryptor provides AES-256-GCM encrypt/decrypt operations.
// The key is loaded from a DPAPI-protected file on disk so that only
// the SYSTEM account (or the user who encrypted it) can recover it.
type Encryptor struct {
	mu      sync.RWMutex
	gcm     cipher.AEAD
	keyPath string
	logger  *logging.Logger
}

// NewEncryptor creates (or loads) an AES-256 key at keyPath, protecting it
// with Windows DPAPI. The key file is created with 0600 permissions.
func NewEncryptor(keyPath string, logger *logging.Logger) (*Encryptor, error) {
	e := &Encryptor{keyPath: keyPath, logger: logger}

	dir := filepath.Dir(keyPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}

	var rawKey []byte

	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) > 0 {
		// Decrypt existing DPAPI blob → raw AES key.
		rawKey, err = dpApiUnprotect(data)
		if err != nil {
			return nil, fmt.Errorf("DPAPI unprotect key file: %w", err)
		}
		if logger != nil {
			logger.Info("[Security] Encryption key loaded from DPAPI store")
		}
	} else {
		// First run → generate 256-bit key and persist.
		rawKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, rawKey); err != nil {
			return nil, fmt.Errorf("generate key: %w", err)
		}
		blob, err := dpApiProtect(rawKey)
		if err != nil {
			return nil, fmt.Errorf("DPAPI protect key: %w", err)
		}
		if err := os.WriteFile(keyPath, blob, 0600); err != nil {
			return nil, fmt.Errorf("write key file: %w", err)
		}
		if logger != nil {
			logger.Info("[Security] New encryption key generated and DPAPI-protected")
		}
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	e.gcm = gcm

	// Zero the raw key in memory.
	for i := range rawKey {
		rawKey[i] = 0
	}

	return e, nil
}

// Encrypt encrypts plaintext with AES-256-GCM. The returned ciphertext
// contains a random nonce prefix followed by the sealed data + tag.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	// nonce is prepended to ciphertext so Decrypt can extract it.
	return e.gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts ciphertext produced by Encrypt.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	nonceSize := e.gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return e.gcm.Open(nil, nonce, ct, nil)
}

// ============================================================================
// DPAPI wrappers (CryptProtectData / CryptUnprotectData)
// ============================================================================

var (
	modCrypt32          = windows.NewLazyDLL("crypt32.dll")
	procCryptProtect    = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotect  = modCrypt32.NewProc("CryptUnprotectData")
	modKernel32         = windows.NewLazyDLL("kernel32.dll")
	procLocalFree       = modKernel32.NewProc("LocalFree")
)

// DATA_BLOB is the Win32 DATA_BLOB structure used by DPAPI.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newDataBlob(data []byte) dataBlob {
	if len(data) == 0 {
		return dataBlob{}
	}
	return dataBlob{
		cbData: uint32(len(data)),
		pbData: &data[0],
	}
}

func (d *dataBlob) bytes() []byte {
	if d.pbData == nil || d.cbData == 0 {
		return nil
	}
	out := make([]byte, d.cbData)
	copy(out, unsafe.Slice(d.pbData, d.cbData))
	return out
}

// dpApiProtect encrypts data with DPAPI (CRYPTPROTECT_LOCAL_MACHINE flag so any
// process running as LocalSystem on this machine can decrypt it).
func dpApiProtect(plaintext []byte) ([]byte, error) {
	in := newDataBlob(plaintext)
	var out dataBlob

	// CRYPTPROTECT_LOCAL_MACHINE = 0x4 — ties key to machine, not user.
	r, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // szDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		0x4, // CRYPTPROTECT_LOCAL_MACHINE
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

// dpApiUnprotect decrypts data encrypted by dpApiProtect.
func dpApiUnprotect(ciphertext []byte) ([]byte, error) {
	in := newDataBlob(ciphertext)
	var out dataBlob

	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // ppszDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		0, // dwFlags
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

// ProtectPrivateKey encrypts raw PEM key bytes using DPAPI with
// CRYPTPROTECT_LOCAL_MACHINE scope (machine-bound, any SYSTEM process
// on this machine can decrypt). Returns the encrypted blob.
func ProtectPrivateKey(keyPEM []byte) ([]byte, error) {
	return dpApiProtect(keyPEM)
}

// UnprotectPrivateKey decrypts a DPAPI blob produced by ProtectPrivateKey
// back to the original plaintext PEM bytes.
func UnprotectPrivateKey(encryptedBlob []byte) ([]byte, error) {
	return dpApiUnprotect(encryptedBlob)
}


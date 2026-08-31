// mtls_dpapi_windows.go — Windows DPAPI helpers for mTLS private key storage.
//
//go:build windows
// +build windows

package grpcclient

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/edr-platform/win-agent/internal/security"
)

// loadKeyPairDPAPI loads the client certificate from certPath (plaintext PEM on
// disk) and the private key from dpapiKeyPath (DPAPI-encrypted blob on disk).
// If dpapiKeyPath doesn't exist but plaintextKeyPath does, it performs a one-time
// migration: encrypt → save .dpapi → delete plaintext.
// Plaintext key bytes are zeroed in memory immediately after use.
func loadKeyPairDPAPI(certPath, dpapiKeyPath, plaintextKeyPath string) (tls.Certificate, error) {
	// Read the certificate PEM (public — not secret).
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read certificate: %w", err)
	}

	var keyPEM []byte

	// Prefer DPAPI-protected blob.
	if blob, err := os.ReadFile(dpapiKeyPath); err == nil && len(blob) > 0 {
		keyPEM, err = security.UnprotectPrivateKey(blob)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("DPAPI unprotect private key: %w", err)
		}
	} else if plainKey, err := os.ReadFile(plaintextKeyPath); err == nil && len(plainKey) > 0 {
		// Migration path: plaintext exists but .dpapi does not.
		// Encrypt → persist .dpapi → delete plaintext.
		encBlob, protErr := security.ProtectPrivateKey(plainKey)
		if protErr != nil {
			// DPAPI failed — fall back to plaintext for this boot only.
			keyPEM = plainKey
		} else {
			if writeErr := os.WriteFile(dpapiKeyPath, encBlob, 0600); writeErr != nil {
				// Could not persist .dpapi — fall back to plaintext.
				keyPEM = plainKey
			} else {
				// Successfully migrated — delete plaintext.
				_ = os.Remove(plaintextKeyPath)
				keyPEM = plainKey // still have it in memory from ReadFile
			}
		}
	} else {
		return tls.Certificate{}, fmt.Errorf("no private key found at %s or %s", dpapiKeyPath, plaintextKeyPath)
	}

	// Parse the key pair from in-memory PEM — never goes through disk for the key.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)

	// Zero the plaintext key bytes in memory immediately.
	for i := range keyPEM {
		keyPEM[i] = 0
	}

	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse key pair: %w", err)
	}
	return pair, nil
}

// savePrivateKeyDPAPI encrypts keyPEM with DPAPI and writes the blob to
// dpapiKeyPath. The plaintext keyPEM is zeroed in memory after encryption.
// No plaintext private key is ever written to disk.
func savePrivateKeyDPAPI(keyPEM []byte, dpapiKeyPath string) error {
	blob, err := security.ProtectPrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("DPAPI protect private key: %w", err)
	}

	// Zero plaintext in memory now that we have the encrypted blob.
	for i := range keyPEM {
		keyPEM[i] = 0
	}

	if err := os.WriteFile(dpapiKeyPath, blob, 0600); err != nil {
		return fmt.Errorf("write DPAPI key file: %w", err)
	}
	return nil
}

// readKeyPEMFromDisk reads the private key PEM bytes from disk.
// It prefers the DPAPI-encrypted blob (dpapiKeyPath = keyPath+".dpapi") and
// falls back to a plaintext PEM file (plaintextKeyPath) for legacy installs.
//
// Background: savePrivateKey() always writes private.key.dpapi (DPAPI blob),
// never the plaintext private.key. The post-enrollment Registry migration must
// therefore read the .dpapi blob and decrypt it to obtain the PEM bytes that
// will be stored (encrypted at rest) inside the SYSTEM-protected Registry key.
func readKeyPEMFromDisk(dpapiKeyPath, plaintextKeyPath string) ([]byte, error) {
	// Primary: DPAPI-encrypted blob (written by savePrivateKey during CSR generation).
	if blob, err := os.ReadFile(dpapiKeyPath); err == nil && len(blob) > 0 {
		keyPEM, err := security.UnprotectPrivateKey(blob)
		if err != nil {
			return nil, fmt.Errorf("DPAPI unprotect private key for registry migration: %w", err)
		}
		return keyPEM, nil
	}
	// Fallback: plaintext PEM (should not exist in normal flow, kept for safety).
	keyPEM, err := os.ReadFile(plaintextKeyPath)
	if err != nil {
		return nil, fmt.Errorf("private key not found at %s or %s", dpapiKeyPath, plaintextKeyPath)
	}
	return keyPEM, nil
}

// GetKeyPEM decrypts and returns the private key PEM bytes from the
// DPAPI-protected blob on disk. Used by the post-enrollment migration step
// (enroll.go) to populate cfg.Certs.KeyPEM before saving to the protected
// Registry. The caller should zero the returned slice after use.
func (m *CertManager) GetKeyPEM() ([]byte, error) {
	return readKeyPEMFromDisk(m.dpapiKeyPath, m.keyPath)
}

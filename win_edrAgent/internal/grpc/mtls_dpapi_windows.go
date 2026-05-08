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

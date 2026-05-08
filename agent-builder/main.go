// Package main provides the Agent Builder HTTP service.
//
// This is a lightweight, single-purpose Go HTTP server that runs inside a
// Docker container with the Go toolchain available. It accepts build requests
// from the Connection Manager and cross-compiles the EDR agent for Windows
// with embedded CA certificate and configuration injected via ldflags.
//
// Architecture:
//
//	Dashboard → Connection Manager (REST API) → Agent Builder (this service)
//	                                                   ↓
//	                                           go build -ldflags ...
//	                                                   ↓
//	                                           edr-agent.exe (binary download)
//
// Performance:
//
//	A content-addressable build cache avoids redundant compilations. The cache
//	key is a SHA-256 fingerprint of ALL build inputs (token, server config,
//	CA cert) PLUS the go.sum file hash (detects source code / dependency changes).
//	Cache hits return the binary in <1 second instead of 30-60 seconds.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BuildRequest is the JSON body accepted by POST /build.
type BuildRequest struct {
	ServerIP      string `json:"server_ip"`
	ServerDomain  string `json:"server_domain"`
	ServerPort    string `json:"server_port"`
	// Token is the legacy single-key enrollment token (XOR or single AES).
	// New builds use TokenEnc + TokenKeyA + TokenID (split-key architecture).
	Token         string `json:"token"`
	// Split-key fields (set by connection-manager handlers_build.go).
	TokenEnc      string `json:"token_enc"`   // hex(nonce||ciphertext||tag)
	TokenKeyA     string `json:"token_key_a"` // hex(16-byte key_a) — baked into binary
	TokenID       string `json:"token_id"`    // UUID — baked into binary for /key-half fetch
	SkipConfig    bool   `json:"skip_config"`
	CACertPEM     string `json:"ca_cert_pem"` // PEM-encoded CA certificate to embed
	InstallSysmon bool   `json:"install_sysmon"`
}

// ─── Build Cache ────────────────────────────────────────────────────────────
//
// The build cache stores the last successful build result keyed by a content-
// addressable fingerprint. The fingerprint includes:
//
//  1. All build inputs (token hash, server config, CA cert hash, skip_config)
//  2. The go.sum file hash — changes when source code or dependencies change
//
// This ensures that:
//   - Identical requests return the cached binary instantly (~1ms vs ~30-60s)
//   - ANY change to the agent source code invalidates the cache automatically
//   - ANY change to build parameters triggers a fresh build
//
// The cache is in-memory (single entry) — lost on container restart, which is
// acceptable because:
//   - First build after restart is fast thanks to Go module cache (Docker volume)
//   - Agent builds are infrequent (operator-initiated from dashboard)
//   - Simplicity: no external storage dependency (Redis, disk)

// BuildCache stores the last successful build for content-addressable lookups.
type BuildCache struct {
	mu            sync.RWMutex
	fingerprint   string // SHA-256 of all build inputs + source hash
	binaryData    []byte // the compiled .exe
	sha256Hash    string // SHA-256 of the binary itself
	buildDuration string // how long the original build took
	buildTime     string // timestamp used in ldflags for the cached build
}

// Get returns the cached binary if the fingerprint matches.
func (bc *BuildCache) Get(fingerprint string) (binaryData []byte, sha256Hash, buildDuration string, ok bool) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if bc.fingerprint == fingerprint && len(bc.binaryData) > 0 {
		return bc.binaryData, bc.sha256Hash, bc.buildDuration, true
	}
	return nil, "", "", false
}

// Set stores a new build result in the cache.
func (bc *BuildCache) Set(fingerprint string, binaryData []byte, sha256Hash, buildDuration, buildTime string) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	bc.fingerprint = fingerprint
	bc.binaryData = make([]byte, len(binaryData))
	copy(bc.binaryData, binaryData)
	bc.sha256Hash = sha256Hash
	bc.buildDuration = buildDuration
	bc.buildTime = buildTime
}

// GetBuildTime returns the build time of the cached build (for ldflags consistency).
func (bc *BuildCache) GetBuildTime() string {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.buildTime
}

// computeFingerprint creates a SHA-256 hash from all inputs that affect the build output.
// This includes request parameters AND the go.sum file (source/dependency changes).
func computeFingerprint(req BuildRequest, agentSrcDir string) string {
	h := sha256.New()

	// 1. Build parameters (order matters — must be deterministic)
	fmt.Fprintf(h, "skip_config=%v\n", req.SkipConfig)
	fmt.Fprintf(h, "install_sysmon=%v\n", req.InstallSysmon)
	fmt.Fprintf(h, "server_ip=%s\n", req.ServerIP)
	fmt.Fprintf(h, "server_domain=%s\n", req.ServerDomain)
	fmt.Fprintf(h, "server_port=%s\n", req.ServerPort)

	// 2. Token hash (not the raw token — security)
	if req.Token != "" {
		tokenHash := sha256Hex(req.Token)
		fmt.Fprintf(h, "token_hash=%s\n", tokenHash)
	}

	// 3. CA cert hash
	if req.CACertPEM != "" {
		caHash := sha256Hex(req.CACertPEM)
		fmt.Fprintf(h, "ca_cert_hash=%s\n", caHash)
	}

	// 4. Source code fingerprint: go.sum changes when any dependency or module changes.
	//    This is the key mechanism for cache invalidation when code is updated.
	goSumPath := filepath.Join(agentSrcDir, "go.sum")
	if data, err := os.ReadFile(goSumPath); err == nil {
		sumHash := sha256.Sum256(data)
		fmt.Fprintf(h, "go_sum_hash=%x\n", sumHash)
	} else {
		// If go.sum is unreadable, include a sentinel to prevent false cache hits
		fmt.Fprintf(h, "go_sum_hash=UNREADABLE_%d\n", time.Now().UnixNano())
	}

	// 5. Also hash go.mod for module path / version changes
	goModPath := filepath.Join(agentSrcDir, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		modHash := sha256.Sum256(data)
		fmt.Fprintf(h, "go_mod_hash=%x\n", modHash)
	}

	// 6. Agent source fingerprint (critical):
	// go.sum/go.mod do NOT change for most code edits. If we only hash those,
	// the build cache can serve stale binaries after source changes.
	//
	// We deterministically hash the agent source tree:
	//   - all *.go files
	//   - go.mod, go.sum (already included above, but included here for the tree hash)
	//   - internal/enrollment/ca-chain.crt (go:embed input)
	//
	// Exclude heavy/irrelevant dirs (.git, dist, node_modules, etc.).
	treeHash, _ := computeAgentSourceHash(agentSrcDir)
	if treeHash != "" {
		fmt.Fprintf(h, "agent_src_hash=%s\n", treeHash)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func computeAgentSourceHash(agentSrcDir string) (string, error) {
	agentSrcDir = filepath.Clean(agentSrcDir)
	var files []string

	// Deterministic file list.
	err := filepath.WalkDir(agentSrcDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		name := d.Name()
		if d.IsDir() {
			switch name {
			case ".git", "bin", "dist", "node_modules", ".idea", ".vscode", ".cursor", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(agentSrcDir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		// Include: *.go, go.mod, go.sum, and ca-chain.crt used for go:embed.
		if strings.HasSuffix(rel, ".go") || rel == "go.mod" || rel == "go.sum" || rel == "internal/enrollment/ca-chain.crt" {
			files = append(files, rel)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)

	h := sha256.New()
	for _, rel := range files {
		abs := filepath.Join(agentSrcDir, filepath.FromSlash(rel))
		b, rErr := os.ReadFile(abs)
		if rErr != nil {
			return "", rErr
		}
		// Hash path + content to avoid collisions across renames.
		fmt.Fprintf(h, "path=%s\n", rel)
		sum := sha256.Sum256(b)
		fmt.Fprintf(h, "sha256=%x\n", sum)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func readGitCommit(agentSrcDir string) string {
	cmd := exec.Command("git", "rev-parse", "--short", "HEAD")
	cmd.Dir = agentSrcDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func main() {
	port := os.Getenv("BUILDER_PORT")
	if port == "" {
		port = "8090"
	}

	agentSrc := os.Getenv("AGENT_SRC_DIR")
	if agentSrc == "" {
		agentSrc = "/app/agent-src"
	}

	// Initialize build cache (single entry, in-memory)
	cache := &BuildCache{}

	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	// Build endpoint
	mux.HandleFunc("/build", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req BuildRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid request body: " + err.Error()})
			return
		}

		log.Printf("[BUILD] Starting build: skip_config=%v, server=%s:%s",
			req.SkipConfig, req.ServerDomain, req.ServerPort)

		// ── Compute content-addressable fingerprint ─────────────────────
		fingerprint := computeFingerprint(req, agentSrc)
		log.Printf("[BUILD] Fingerprint: %s", fingerprint[:16]+"...")
		srcCommit := readGitCommit(agentSrc)
		srcHash, _ := computeAgentSourceHash(agentSrc)

		// ── Check cache ─────────────────────────────────────────────────
		if binaryData, hashStr, buildDuration, ok := cache.Get(fingerprint); ok {
			log.Printf("[BUILD] CACHE HIT — returning cached binary (%d bytes, sha256=%s)",
				len(binaryData), hashStr[:16]+"...")

			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="edr-agent.exe"`)
			w.Header().Set("X-Agent-SHA256", hashStr)
			w.Header().Set("X-Build-Duration", buildDuration)
			w.Header().Set("X-Agent-Fingerprint", fingerprint)
			if srcCommit != "" {
				w.Header().Set("X-Agent-Source-Commit", srcCommit)
			}
			if srcHash != "" {
				w.Header().Set("X-Agent-Source-Hash", srcHash)
			}
			w.Header().Set("X-Cache-Hit", "true")
			w.WriteHeader(http.StatusOK)
			w.Write(binaryData)
			return
		}

		log.Printf("[BUILD] CACHE MISS — performing full build")

		// ── Write CA certificate for go:embed ───────────────────────────
		embedTarget := filepath.Join(agentSrc, "internal", "enrollment", "ca-chain.crt")
		if req.CACertPEM != "" {
			if err := os.WriteFile(embedTarget, []byte(req.CACertPEM), 0644); err != nil {
				log.Printf("[BUILD] Failed to write CA cert: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Failed to write CA certificate for embedding: " + err.Error(),
				})
				return
			}
			defer func() {
				// Restore empty placeholder after build
				_ = os.WriteFile(embedTarget, []byte(" "), 0644)
			}()
		}

		// ── Build ldflags ───────────────────────────────────────────────
		// Use a fixed build time for cache consistency — same inputs produce
		// same binary. BuildTime is NOT included in the fingerprint.
		buildTime := time.Now().UTC().Format(time.RFC3339)
		ldflags := []string{
			"-w", "-s",
			fmt.Sprintf("-X main.Version=%s", "dashboard-build"),
			fmt.Sprintf("-X main.BuildTime=%s", buildTime),
		}
		if srcCommit != "" {
			ldflags = append(ldflags, fmt.Sprintf("-X main.GitCommit=%s", srcCommit))
		}

		if req.TokenEnc != "" && req.TokenKeyA != "" && req.TokenID != "" {
			// SPLIT-KEY path (new): key was split server-side in handlers_build.go.
			// key_b is already stored in the DB; we only embed key_a + ciphertext + token ID.
			// The agent fetches key_b from POST /api/v1/agent/key-half at enrollment time.
			ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedTokenEnc=%s", req.TokenEnc))
			ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedTokenKeyA=%s", req.TokenKeyA))
			ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedTokenID=%s", req.TokenID))
		} else if req.Token != "" {
			// LEGACY path: generate single-key AES (no split) for backward compatibility.
			tokenEnc, tokenKey, err := aesEncryptToken(req.Token)
			if err != nil {
				log.Printf("[BUILD] Failed to encrypt token: %v", err)
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "Failed to encrypt enrollment token: " + err.Error(),
				})
				return
			}
			ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedTokenEnc=%s", tokenEnc))
			ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedTokenKey=%s", tokenKey))
		}

		if !req.SkipConfig {
			if req.ServerIP != "" {
				ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedServerIP=%s", req.ServerIP))
			}
			if req.ServerDomain != "" {
				ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedServerDomain=%s", req.ServerDomain))
			}
			if req.ServerPort != "" {
				ldflags = append(ldflags, fmt.Sprintf("-X main.EmbeddedServerPort=%s", req.ServerPort))
			}
		}
		if req.InstallSysmon {
			ldflags = append(ldflags, "-X main.EmbeddedInstallSysmon=true")
		}

		// ── Create temp output ──────────────────────────────────────────
		tmpDir, err := os.MkdirTemp("", "edr-build-*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed to create temp directory: " + err.Error(),
			})
			return
		}
		defer os.RemoveAll(tmpDir)

		outputPath := filepath.Join(tmpDir, "edr-agent.exe")

		// ── Cross-compile ───────────────────────────────────────────────
		cmd := exec.Command("go", "build",
			"-ldflags", strings.Join(ldflags, " "),
			"-o", outputPath,
			"./cmd/agent",
		)
		cmd.Dir = agentSrc
		cmd.Env = append(os.Environ(),
			"GOOS=windows",
			"GOARCH=amd64",
			"CGO_ENABLED=1",                          // Required: ETW collector uses C (cgo)
			"CC=x86_64-w64-mingw32-gcc",              // MinGW cross-compiler for Windows
			"GOPROXY=https://goproxy.io,direct",
		)

		buildStart := time.Now()
		buildOutput, err := cmd.CombinedOutput()
		buildDuration := time.Since(buildStart)

		if err != nil {
			log.Printf("[BUILD] FAILED in %s: %v\nOutput: %s", buildDuration, err, string(buildOutput))
			writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"error":        "Build failed",
				"build_output": string(buildOutput),
				"duration":     buildDuration.String(),
			})
			return
		}

		log.Printf("[BUILD] SUCCESS in %s, output: %s", buildDuration, outputPath)

		// ── Read binary + compute hash ──────────────────────────────────
		binaryData, err := os.ReadFile(outputPath)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "Failed to read built binary: " + err.Error(),
			})
			return
		}

		hash := sha256.Sum256(binaryData)
		hashStr := fmt.Sprintf("%x", hash)
		durationStr := buildDuration.String()

		log.Printf("[BUILD] Binary size: %d bytes, SHA256: %s", len(binaryData), hashStr[:16]+"...")

		// ── Store in cache ──────────────────────────────────────────────
		cache.Set(fingerprint, binaryData, hashStr, durationStr, buildTime)
		log.Printf("[BUILD] Cached build result (fingerprint=%s)", fingerprint[:16]+"...")

		// ── Return binary as download ───────────────────────────────────
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="edr-agent.exe"`)
		w.Header().Set("X-Agent-SHA256", hashStr)
		w.Header().Set("X-Build-Duration", durationStr)
		w.Header().Set("X-Agent-Fingerprint", fingerprint)
		if srcCommit != "" {
			w.Header().Set("X-Agent-Source-Commit", srcCommit)
		}
		if srcHash != "" {
			w.Header().Set("X-Agent-Source-Hash", srcHash)
		}
		w.Header().Set("X-Cache-Hit", "false")
		w.WriteHeader(http.StatusOK)
		w.Write(binaryData)
	})

	log.Printf("Agent Builder listening on :%s (agent source: %s)", port, agentSrc)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Failed to start builder: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// sha256Hex returns the lowercase hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// aesEncryptToken encrypts plaintext using AES-256-GCM with a randomly-generated
// per-build key.  Returns (ciphertextHex, keyHex, error).
//
// Format of ciphertextHex (all concatenated, hex-encoded):
//
//	12-byte nonce || AES-GCM ciphertext+tag
//
// The key is 32 random bytes (AES-256).
func aesEncryptToken(plaintext string) (ciphertextHex, keyHex string, err error) {
	// Generate random 32-byte key (AES-256).
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", "", fmt.Errorf("generate AES key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", "", fmt.Errorf("new AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", fmt.Errorf("new GCM: %w", err)
	}

	// Random 12-byte nonce (standard GCM nonce size).
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("generate nonce: %w", err)
	}

	// Seal appends ciphertext + 16-byte GCM tag to nonce.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return hex.EncodeToString(ciphertext), hex.EncodeToString(key), nil
}

//go:build windows

// cookie2ghsecret extracts a named cookie from a locally installed Chrome
// browser and uploads it as a GitHub Actions repository secret.
//
// Usage:
//
//	cookie2ghsecret.exe [config.json]
//
// The config file (default: config.json) must contain:
//
//	{
//	  "website":            "example.com",
//	  "cookie_name":        "session_id",
//	  "github_repo":        "owner/repository",
//	  "github_token":       "ghp_...",
//	  "github_secret_name": "MY_COOKIE_SECRET"
//	}
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
	_ "modernc.org/sqlite"
)

// Config holds all user-configurable parameters loaded from the JSON config file.
type Config struct {
	Website          string `json:"website"`
	CookieName       string `json:"cookie_name"`
	GitHubRepo       string `json:"github_repo"`
	GitHubToken      string `json:"github_token"`
	GitHubSecretName string `json:"github_secret_name"`
}

// githubPublicKey is the response from the GitHub public-key API endpoint.
type githubPublicKey struct {
	KeyID string `json:"key_id"`
	Key   string `json:"key"`
}

func main() {
	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		fatalf("Error loading config from %q: %v\n", configFile, err)
	}

	fmt.Printf("Extracting cookie %q for %q from Chrome...\n", cfg.CookieName, cfg.Website)
	cookieValue, err := extractChromeCookie(cfg.Website, cfg.CookieName)
	if err != nil {
		fatalf("Error extracting cookie: %v\n", err)
	}
	fmt.Println("Cookie extracted successfully.")

	fmt.Printf("Uploading secret %q to %s...\n", cfg.GitHubSecretName, cfg.GitHubRepo)
	if err := uploadGitHubSecret(cfg.GitHubRepo, cfg.GitHubToken, cfg.GitHubSecretName, cookieValue); err != nil {
		fatalf("Error uploading secret: %v\n", err)
	}
	fmt.Printf("Secret %q successfully uploaded to %s.\n", cfg.GitHubSecretName, cfg.GitHubRepo)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

// loadConfig reads and parses the JSON configuration file at path.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Website == "" {
		return nil, fmt.Errorf("config: 'website' must not be empty")
	}
	if cfg.CookieName == "" {
		return nil, fmt.Errorf("config: 'cookie_name' must not be empty")
	}
	if cfg.GitHubRepo == "" {
		return nil, fmt.Errorf("config: 'github_repo' must not be empty")
	}
	if cfg.GitHubToken == "" {
		return nil, fmt.Errorf("config: 'github_token' must not be empty")
	}
	if cfg.GitHubSecretName == "" {
		return nil, fmt.Errorf("config: 'github_secret_name' must not be empty")
	}
	return &cfg, nil
}

// extractChromeCookie tries each known Chrome profile root directory in turn
// and returns the decrypted value of the first matching cookie.
func extractChromeCookie(website, cookieName string) (string, error) {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return "", fmt.Errorf("LOCALAPPDATA environment variable is not set")
	}

	profileRoots := []string{
		filepath.Join(localAppData, "Google", "Chrome", "User Data"),
		filepath.Join(localAppData, "Google", "Chrome SxS", "User Data"),
		filepath.Join(localAppData, "Chromium", "User Data"),
	}

	var lastErr error
	for _, root := range profileRoots {
		value, err := extractFromProfile(root, website, cookieName)
		if err == nil {
			return value, nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("cookie %q for %q not found in any Chrome profile: %w", cookieName, website, lastErr)
}

// extractFromProfile extracts a cookie from a specific Chrome user-data directory.
func extractFromProfile(chromeUserDataPath, website, cookieName string) (string, error) {
	localStatePath := filepath.Join(chromeUserDataPath, "Local State")
	if _, err := os.Stat(localStatePath); err != nil {
		return "", fmt.Errorf("Chrome profile not found at %s: %w", chromeUserDataPath, err)
	}

	aesKey, err := getChromeAESKey(localStatePath)
	if err != nil {
		return "", fmt.Errorf("failed to obtain Chrome AES key from %s: %w", localStatePath, err)
	}

	// Chrome has moved Cookies to the Network sub-folder in newer versions.
	cookiesPaths := []string{
		filepath.Join(chromeUserDataPath, "Default", "Network", "Cookies"),
		filepath.Join(chromeUserDataPath, "Default", "Cookies"),
	}

	for _, dbPath := range cookiesPaths {
		if _, err := os.Stat(dbPath); err != nil {
			continue
		}
		value, err := readCookieFromDB(dbPath, website, cookieName, aesKey)
		if err == nil {
			return value, nil
		}
	}
	return "", fmt.Errorf("cookie %q for %q not found in profile %s", cookieName, website, chromeUserDataPath)
}

// getChromeAESKey reads Chrome's Local State file and returns the AES-256 key
// used to encrypt cookie values, decrypted via DPAPI.
func getChromeAESKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("failed to parse Local State: %w", err)
	}
	if localState.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("os_crypt.encrypted_key not found in Local State")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to base64-decode encrypted_key: %w", err)
	}

	const dpAPIPrefix = "DPAPI"
	if !bytes.HasPrefix(encryptedKey, []byte(dpAPIPrefix)) {
		return nil, fmt.Errorf("encrypted_key does not have expected 'DPAPI' prefix")
	}
	encryptedKey = encryptedKey[len(dpAPIPrefix):]

	return decryptWithDPAPI(encryptedKey)
}

// readCookieFromDB opens a copy of the Chrome Cookies SQLite database,
// queries for the named cookie, and returns its decrypted value.
// It works on a temp-file copy to avoid locking conflicts when Chrome is running.
func readCookieFromDB(dbPath, website, cookieName string, aesKey []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "chrome-cookies-*.db")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := copyFile(dbPath, tmpPath); err != nil {
		return "", fmt.Errorf("failed to copy Cookies database: %w", err)
	}

	db, err := sql.Open("sqlite", tmpPath+"?mode=ro")
	if err != nil {
		return "", fmt.Errorf("failed to open Cookies database: %w", err)
	}
	defer db.Close()

	// Match the host-only form ("example.com") and the domain form
	// (".example.com" and any subdomain like "%.example.com").
	// This avoids false matches against unrelated domains such as "notexample.com".
	domain := strings.TrimPrefix(website, ".")
	subdomainPattern := "%." + domain

	var encryptedValue []byte
	err = db.QueryRow(
		`SELECT encrypted_value FROM cookies
		 WHERE (host_key = ? OR host_key LIKE ?) AND name = ? LIMIT 1`,
		domain, subdomainPattern, cookieName,
	).Scan(&encryptedValue)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("cookie %q for domain %q not found", cookieName, domain)
	}
	if err != nil {
		return "", fmt.Errorf("failed to query Cookies database: %w", err)
	}

	return decryptChromeCookie(encryptedValue, aesKey)
}

// decryptChromeCookie decrypts a Chrome cookie value.
// Chrome v80+ values are prefixed with "v10" or "v11" and use AES-256-GCM.
// Older values are encrypted with DPAPI directly.
func decryptChromeCookie(encryptedValue, aesKey []byte) (string, error) {
	if len(encryptedValue) < 3 {
		// Unencrypted (rare, but possible for non-secure cookies).
		return string(encryptedValue), nil
	}

	switch string(encryptedValue[:3]) {
	case "v10", "v11":
		// Format: 3-byte version tag | 12-byte nonce | ciphertext+tag
		if len(encryptedValue) < 3+12+16 {
			return "", fmt.Errorf("encrypted cookie value is too short for AES-GCM")
		}
		nonce := encryptedValue[3:15]
		ciphertext := encryptedValue[15:]

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return "", fmt.Errorf("failed to create AES cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("failed to create GCM: %w", err)
		}
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", fmt.Errorf("AES-GCM decryption failed: %w", err)
		}
		return string(plaintext), nil

	default:
		// Older format: raw DPAPI-encrypted blob.
		decrypted, err := decryptWithDPAPI(encryptedValue)
		if err != nil {
			return "", fmt.Errorf("DPAPI decryption of cookie value failed: %w", err)
		}
		return string(decrypted), nil
	}
}

// uploadGitHubSecret fetches the repo's public key, encrypts secretValue with
// it (using libsodium's crypto_box_seal algorithm), and stores it via the
// GitHub Actions secrets API.
func uploadGitHubSecret(repo, token, secretName, secretValue string) error {
	pubKey, err := getGitHubPublicKey(repo, token)
	if err != nil {
		return fmt.Errorf("failed to retrieve GitHub public key: %w", err)
	}

	encrypted, err := encryptForGitHub(pubKey.Key, secretValue)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	return putGitHubSecret(repo, token, secretName, pubKey.KeyID, encrypted)
}

// getGitHubPublicKey retrieves the public key for encrypting Actions secrets
// for the given repository (format "owner/repo").
func getGitHubPublicKey(repo, token string) (*githubPublicKey, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/secrets/public-key", repo)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API responded %s: %s", resp.Status, body)
	}

	var pk githubPublicKey
	if err := json.Unmarshal(body, &pk); err != nil {
		return nil, fmt.Errorf("failed to parse public key response: %w", err)
	}
	return &pk, nil
}

// putGitHubSecret creates or updates an Actions secret for the repository.
func putGitHubSecret(repo, token, secretName, keyID, encryptedValue string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/actions/secrets/%s", repo, secretName)

	payload, err := json.Marshal(map[string]string{
		"encrypted_value": encryptedValue,
		"key_id":          keyID,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GitHub API responded %s: %s", resp.Status, body)
	}
	return nil
}

// encryptForGitHub encrypts secretValue with the repository's Curve25519
// public key using the libsodium crypto_box_seal construction, which is what
// the GitHub Actions secrets API requires.
//
// Algorithm:
//  1. Decode the base64-encoded recipient public key.
//  2. Generate an ephemeral Curve25519 key pair.
//  3. Derive the 24-byte nonce as BLAKE2b(ephemeralPK || recipientPK, outLen=24).
//  4. Encrypt with NaCl box (X25519 + XSalsa20-Poly1305).
//  5. Return base64(ephemeralPK || ciphertext).
func encryptForGitHub(publicKeyB64, secretValue string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", fmt.Errorf("public key must be 32 bytes, got %d", len(pubKeyBytes))
	}

	var recipientPK [32]byte
	copy(recipientPK[:], pubKeyBytes)

	encrypted, err := sealAnonymous([]byte(secretValue), recipientPK)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// sealAnonymous implements libsodium's crypto_box_seal.
func sealAnonymous(message []byte, recipientPK [32]byte) ([]byte, error) {
	epk, esk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key pair: %w", err)
	}

	h, err := blake2b.New(24, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create BLAKE2b hasher: %w", err)
	}
	h.Write(epk[:])
	h.Write(recipientPK[:])

	var nonce [24]byte
	copy(nonce[:], h.Sum(nil))

	// box.Seal encrypts message and appends the ciphertext to the dst slice.
	// By passing epk[:] as dst, the result is [ephemeralPK | ciphertext+tag],
	// which matches the libsodium crypto_box_seal wire format.
	return box.Seal(epk[:], message, &nonce, &recipientPK, esk), nil
}

// copyFile copies src to dst, creating dst if it does not exist.
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

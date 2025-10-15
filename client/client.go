// client.go
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
)

const (
	CertbotBaseDir = "/etc/letsencrypt/live"
	TLSCertFile    = "tls/client.crt"
	TLSKeyFile     = "tls/client.key"
	TLSCaFile      = "tls/ca.crt"
	// ServerURL      = "https://cert-server.example.com:8443" // **MUST BE CHANGED**
	ServerURL      = "https://neptune-2024.si.uvsq.fr:8443" // **MUST BE CHANGED**
)

var syslogger *log.Logger

// CertificateHashes represents the SHA256 hashes of the three certificate files.
type CertificateHashes struct {
	FullchainHash string `json:"fullchain_hash"`
	PrivkeyHash   string `json:"privkey_hash"`
	ChainHash     string `json:"chain_hash"`
}

// ServerResponse is used for the /api/check response.
type ServerResponse struct {
	UpdateRequired bool                 `json:"update_required"`
	Message        string               `json:"message"`
	ServerHashes   *CertificateHashes `json:"server_hashes,omitempty"`
}

func init() {
	var err error
	// Setup Syslog logging with daemon facility and info priority
	syslogger, err = syslog.NewLogger(syslog.LOG_INFO|syslog.LOG_DAEMON, log.LstdFlags)
	if err != nil {
		log.Fatalf("Failed to initialize syslog: %v", err)
	}
	syslogger.Print("Client initialized.")
}

// calculateFileHash reads a file and returns its SHA256 hash as a hex string.
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if os.IsNotExist(err) {
		// Return a zero hash if the file doesn't exist (signals a required update)
		return hex.EncodeToString(make([]byte, 32)), nil // 32 bytes for SHA256
	}
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file %s: %w", filePath, err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// getLocalCertbotHashes calculates and returns the hashes of the local Certbot files for a given domain.
func getLocalCertbotHashes(domain string) (*CertificateHashes, error) {
	domainPath := filepath.Join(CertbotBaseDir, domain)
	
	fullchainPath := filepath.Join(domainPath, "fullchain.pem")
	privkeyPath := filepath.Join(domainPath, "privkey.pem")
	chainPath := filepath.Join(domainPath, "chain.pem")

	fullchainHash, err := calculateFileHash(fullchainPath)
	if err != nil {
		return nil, fmt.Errorf("error hashing fullchain.pem: %w", err)
	}

	privkeyHash, err := calculateFileHash(privkeyPath)
	if err != nil {
		return nil, fmt.Errorf("error hashing privkey.pem: %w", err)
	}

	chainHash, err := calculateFileHash(chainPath)
	if err != nil {
		return nil, fmt.Errorf("error hashing chain.pem: %w", err)
	}

	return &CertificateHashes{
		FullchainHash: fullchainHash,
		PrivkeyHash:   privkeyHash,
		ChainHash:     chainHash,
	}, nil
}

// getTLSClient creates an HTTP client configured for mTLS.
func getTLSClient() (*http.Client, error) {
	// Load client cert and key
	cert, err := tls.LoadX509KeyPair(TLSCertFile, TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client key pair: %w", err)
	}

	// Load CA cert
	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile(TLSCaFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool, // Trust the server's certificate signed by this CA
		MinVersion:   tls.VersionTLS12,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

// downloadAndSaveFile downloads a file from the server and saves it locally.
func downloadAndSaveFile(client *http.Client, domain, fileName, localPath string) error {
	downloadURL := fmt.Sprintf("%s/download/%s/%s", ServerURL, domain, fileName)
	
	resp, err := client.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download %s: %w", fileName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to download %s, server returned status %d: %s", fileName, resp.StatusCode, string(bodyBytes))
	}

	// Ensure the directory exists
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Save the file
	out, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file %s: %w", localPath, err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save downloaded content to %s: %w", localPath, err)
	}
	
	syslogger.Printf("Successfully downloaded and saved: %s", localPath)
	return nil
}

func main() {
	if len(os.Args) != 2 {
		syslogger.Fatalf("Client error: Usage: %s <domain_name>", os.Args[0])
	}
	domain := os.Args[1]
	
	// 1. Calculate local hashes
	localHashes, err := getLocalCertbotHashes(domain)
	if err != nil {
		syslogger.Fatalf("Client error: Failed to calculate local hashes for %s: %v", domain, err)
	}
	syslogger.Printf("Local hashes for %s calculated: Fullchain=%s...", domain, localHashes.FullchainHash[:8])

	// 2. Setup mTLS Client
	client, err := getTLSClient()
	if err != nil {
		syslogger.Fatalf("Client error: Failed to setup mTLS client: %v", err)
	}

	// 3. Prepare and send check request
	checkURL := fmt.Sprintf("%s/api/check", ServerURL)
	requestBody, _ := json.Marshal(map[string]interface{}{
		"domain": domain,
		"hashes": localHashes,
	})
	
	resp, err := client.Post(checkURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		syslogger.Fatalf("Client error: Failed to connect or send check request to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		syslogger.Fatalf("Client error: Server returned non-OK status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var serverResponse ServerResponse
	if err := json.NewDecoder(resp.Body).Decode(&serverResponse); err != nil {
		syslogger.Fatalf("Client error: Failed to decode server response: %v", err)
	}

	syslogger.Printf("Server response: %s", serverResponse.Message)

	// 4. Conditional Update
	if serverResponse.UpdateRequired {
		syslogger.Printf("Update required. Starting download process for %s...", domain)

		certFiles := []string{"fullchain.pem", "privkey.pem", "chain.pem"}
		domainPath := filepath.Join(CertbotBaseDir, domain)

		// Download and replace all three files atomically (sequentially in this implementation)
		for _, fileName := range certFiles {
			localFilePath := filepath.Join(domainPath, fileName)
			if err := downloadAndSaveFile(client, domain, fileName, localFilePath); err != nil {
				// Log the error and stop the update process for this domain
				syslogger.Fatalf("Client error: Failed to download and save %s: %v", fileName, err)
			}
		}
		
		syslogger.Printf("SUCCESS: All certificates for %s updated successfully.", domain)
	} else {
		syslogger.Printf("Skipping update for %s. Certificates are current.", domain)
	}
}

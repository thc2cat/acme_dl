// server.go
package main

import (
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
	"strings"
)

const (
	CertbotBaseDir = "/etc/letsencrypt/live"
	TLSCertFile    = "tls/server.crt"
	TLSKeyFile     = "tls/server.key"
	TLSCaFile      = "tls/ca.crt"
	Port           = "8443"
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
	syslogger.Print("Server initialized and ready to start.")
}

// calculateFileHash reads a file and returns its SHA256 hash as a hex string.
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
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

// getDomainPath safely constructs the path to the domain's certificate files.
func getDomainPath(domain string) string {
	// Sanitize the domain to prevent directory traversal issues
	safeDomain := filepath.Base(domain)
	return filepath.Join(CertbotBaseDir, safeDomain)
}

// getCertbotHashes calculates and returns the hashes of the server's Certbot files for a given domain.
func getCertbotHashes(domain string) (*CertificateHashes, error) {
	domainPath := getDomainPath(domain)
	
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

// compareHashesHandler handles the client's request to check for updates.
func compareHashesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		syslogger.Printf("Client error: Invalid method %s on /api/check", r.Method)
		return
	}

	var clientData struct {
		Domain string `json:"domain"`
		ClientHashes CertificateHashes `json:"hashes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&clientData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		syslogger.Printf("Client error: Failed to decode JSON body: %v", err)
		return
	}

	domain := clientData.Domain
	
	serverHashes, err := getCertbotHashes(domain)
	if err != nil {
		http.Error(w, "Server error: Could not retrieve server hashes", http.StatusInternalServerError)
		syslogger.Printf("Server error: Failed to get server hashes for %s: %v", domain, err)
		return
	}

	// Compare client and server hashes
	updateRequired := false
	message := "Certificates are up to date."

	if clientData.ClientHashes.FullchainHash != serverHashes.FullchainHash ||
		clientData.ClientHashes.PrivkeyHash != serverHashes.PrivkeyHash ||
		clientData.ClientHashes.ChainHash != serverHashes.ChainHash {
		updateRequired = true
		message = "Update required: Certificate hashes differ."
		syslogger.Printf("Update required for %s. Client/Server hashes differ.", domain)
	} else {
		syslogger.Printf("No update required for %s. Hashes match.", domain)
	}

	response := ServerResponse{
		UpdateRequired: updateRequired,
		Message:        message,
	}

	// If update is required, provide the server hashes (optional, but useful for client verification/logging)
	if updateRequired {
		response.ServerHashes = serverHashes
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// downloadCertHandler allows direct download of a specific certificate file.
func downloadCertHandler(w http.ResponseWriter, r *http.Request) {
	pathSegments := strings.Split(r.URL.Path, "/")
	if len(pathSegments) != 4 { // Expected /download/<domain>/<filename>
		http.Error(w, "Invalid download URL format", http.StatusBadRequest)
		syslogger.Printf("Client error: Invalid URL format on /download: %s", r.URL.Path)
		return
	}

	domain := pathSegments[2]
	fileName := pathSegments[3]

	// Basic validation of filename
	if fileName != "fullchain.pem" && fileName != "privkey.pem" && fileName != "chain.pem" {
		http.Error(w, "Invalid file requested", http.StatusBadRequest)
		syslogger.Printf("Client error: Invalid file name requested: %s for domain %s", fileName, domain)
		return
	}
	
	filePath := filepath.Join(getDomainPath(domain), fileName)

	// Use http.ServeFile for atomic serving
	http.ServeFile(w, r, filePath)
	syslogger.Printf("File served: %s for domain %s", fileName, domain)
}

// main configures mTLS and starts the server.
func main() {
	// 1. Load CA to verify client certificates (mTLS)
	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile(TLSCaFile)
	if err != nil {
		syslogger.Fatalf("Server error: Failed to read CA file: %v", err)
	}
	if !caCertPool.AppendCertsFromPEM(caCert) {
		syslogger.Fatalf("Server error: Failed to append CA cert")
	}

	// 2. Configure TLS with ClientAuth
	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":" + Port,
		TLSConfig: tlsConfig,
	}
	
	// Register Handlers
	http.HandleFunc("/api/check", compareHashesHandler)
	http.HandleFunc("/download/", downloadCertHandler) // Use /download/<domain>/<filename>

	syslogger.Printf("Server starting on port %s with mTLS enforced...", Port)
	
	// Start the TLS server
	err = server.ListenAndServeTLS(TLSCertFile, TLSKeyFile)
	if err != nil {
		syslogger.Fatalf("Server error: ListenAndServeTLS failed: %v", err)
	}
}
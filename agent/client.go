package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("server returned HTTP %d: %s", e.Status, e.Body)
}

type Client struct {
	cfg        *Config
	http       *http.Client
	privateKey ed25519.PrivateKey
}

func newHTTPClient(cfg *Config) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	if cfg.CAFile != "" {
		pemData, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificates", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.Insecure {
		tlsConfig.InsecureSkipVerify = true // #nosec G402 -- explicit --insecure opt-in
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return &http.Client{Timeout: 45 * time.Second, Transport: transport}, nil
}

func newClient(cfg *Config) (*Client, error) {
	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(cfg.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("config has no private key; run the enroll command first")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has invalid length")
	}

	return &Client{cfg: cfg, http: httpClient, privateKey: privateKey}, nil
}

func (c *Client) post(path string, payload any, signed bool) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(c.cfg.Server, "/") + path
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("oat-agent/%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH))

	if signed {
		if len(c.privateKey) == 0 {
			return nil, fmt.Errorf("agent is not enrolled: missing private key")
		}
		timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
		nonceBytes := make([]byte, 16)
		if _, err := rand.Read(nonceBytes); err != nil {
			return nil, err
		}
		nonce := hex.EncodeToString(nonceBytes)
		sum := sha256.Sum256(body)
		canonical := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", http.MethodPost, path, timestamp, nonce, hex.EncodeToString(sum[:]))
		signature := ed25519.Sign(c.privateKey, []byte(canonical))

		req.Header.Set("X-OAT-Agent", c.cfg.AgentID)
		req.Header.Set("X-OAT-Timestamp", timestamp)
		req.Header.Set("X-OAT-Nonce", nonce)
		req.Header.Set("X-OAT-Signature", base64.StdEncoding.EncodeToString(signature))
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		text := strings.TrimSpace(string(responseBody))
		if len(text) > 500 {
			text = text[:500]
		}
		return nil, &APIError{Status: resp.StatusCode, Body: text}
	}
	return responseBody, nil
}

func (c *Client) SendBatch(batch *Batch) error {
	_, err := c.post("/api/agents/ingest", batch, true)
	return err
}

func (c *Client) Heartbeat(metrics Metrics) (*HeartbeatResponse, error) {
	payload := Batch{
		Agent:   currentAgentInfo(c.cfg),
		Metrics: &metrics,
	}
	body, err := c.post("/api/agents/heartbeat", payload, true)
	if err != nil {
		return nil, err
	}
	// The console owns the website binding: the operator may point this agent
	// at another website at any time, so the answer carries the current one.
	var response HeartbeatResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, nil
	}
	if response.Application != nil && response.Application.ID != "" {
		c.cfg.ApplicationID = response.Application.ID
		c.cfg.ApplicationName = response.Application.Name
		c.cfg.ApplicationDomain = response.Application.Domain
	}
	return &response, nil
}

// ScanMalwareSample sends a newly created web file to the analysis engine. The
// server answers with the verdict and the containment the agent must apply
// immediately (QUARANTINE for malicious payloads).
func (c *Client) ScanMalwareSample(req MalwareScanRequest) (*MalwareScanResponse, error) {
	body, err := c.post("/api/agents/malware/scan", req, true)
	if err != nil {
		return nil, err
	}
	var response MalwareScanResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}
	if !response.OK {
		return nil, fmt.Errorf("malware scan rejected: %s", response.Error)
	}
	return &response, nil
}

// ReportMalwareResult acknowledges a containment order so the console can show
// whether the file was actually quarantined or deleted on the host.
func (c *Client) ReportMalwareResult(scanID, status, quarantinedPath, errMessage string) error {
	_, err := c.post("/api/agents/malware/result", map[string]any{
		"scanId":          scanID,
		"status":          status,
		"quarantinedPath": quarantinedPath,
		"error":           errMessage,
	}, true)
	return err
}

type enrollRequest struct {
	Token         string            `json:"token"`
	PublicKey     string            `json:"publicKey"`
	Name          string            `json:"name"`
	Hostname      string            `json:"hostname"`
	OS            string            `json:"os"`
	Arch          string            `json:"arch"`
	Version       string            `json:"version"`
	IP            string            `json:"ip,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	DetectedSites []DetectedSite    `json:"detectedSites,omitempty"`
}

func enrollAgent(cfg *Config, token, name string) (*EnrollResponse, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))

	httpClient, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	client := &Client{cfg: cfg, http: httpClient}
	// Auto-detect websites running on this host and include them in the
	// enrollment payload so the server can create Applications automatically.
	detectedSites := detectLocalSites()

	payload := enrollRequest{
		Token:         token,
		PublicKey:     publicPEM,
		Name:          name,
		Hostname:      cfg.Hostname,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       version,
		IP:            hostIP(),
		Labels:        cfg.Labels,
		DetectedSites: detectedSites,
	}

	// Without a token the agent asks the server to provision the tenant: the
	// first installed agent creates the organization and its website.
	endpoint := "/api/agents/enroll"
	if token == "" {
		endpoint = "/api/agents/bootstrap"
	}

	responseBody, err := client.post(endpoint, payload, false)
	if err != nil {
		return nil, err
	}

	var response EnrollResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return nil, fmt.Errorf("decode enrollment response: %w", err)
	}
	if response.AgentID == "" || response.OrganizationID == "" {
		return nil, fmt.Errorf("server returned an incomplete enrollment response")
	}

	cfg.AgentID = response.AgentID
	cfg.OrganizationID = response.OrganizationID
	cfg.ApplicationID = response.ApplicationID
	cfg.ApplicationName = response.ApplicationName
	cfg.ApplicationDomain = response.ApplicationDomain
	cfg.PrivateKey = string(privatePEM)
	cfg.Name = name
	cfg.EnrolledAt = time.Now().UTC().Format(time.RFC3339)
	if response.HeartbeatSeconds > 0 {
		cfg.HeartbeatSeconds = response.HeartbeatSeconds
	}
	if response.FlushSeconds > 0 {
		cfg.FlushSeconds = response.FlushSeconds
	}
	return &response, nil
}

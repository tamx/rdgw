package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	digest "github.com/tamx/golang-digest"
)

// helper to back up and restore usermap
func backupUserMap() func() {
	orig := make(map[string]string)
	for k, v := range usermap {
		orig[k] = v
	}
	return func() {
		usermap = orig
	}
}

func TestCheckAuth(t *testing.T) {
	restore := backupUserMap()
	defer restore()

	usermap["testuser"] = "testpass"

	// Test registered user
	if pass := checkAuth("testuser"); pass != "testpass" {
		t.Errorf("expected testpass, got %s", pass)
	}

	// Test unregistered user
	if pass := checkAuth("nonexistent"); pass != "" {
		t.Errorf("expected empty string, got %s", pass)
	}
}

func TestCheckHandler(t *testing.T) {
	restore := backupUserMap()
	defer restore()

	usermap["testuser"] = "testpass"
	realm := "secret"

	expected := digest.ComputeMD5Password("testuser", realm, "testpass")
	actual := checkHandler("testuser", realm)
	if actual != expected {
		t.Errorf("expected %s, got %s", expected, actual)
	}
}

func TestCreateRandom(t *testing.T) {
	sizes := []int{0, 1, 10, 100}
	for _, size := range sizes {
		buf := createRandom(size)
		if len(buf) != size {
			t.Errorf("expected size %d, got %d", size, len(buf))
		}
	}
}

func TestReadLine(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		expected string
		hasErr   bool
	}{
		{"CRLF", "hello\r\nworld", "hello", false},
		{"LF", "hello\nworld", "hello", false},
		{"NoNewlineEOF", "hello", "", true}, // triggers EOF since there is no newline
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := io.NopCloser(bytes.NewReader([]byte(tc.input)))
			line, err := ReadLine(rc)
			if tc.hasErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if line != tc.expected {
					t.Errorf("expected %q, got %q", tc.expected, line)
				}
			}
		})
	}
}

func TestReadWriteHTTPPacket(t *testing.T) {
	body := []byte("hello-packet-body-data")
	packetType := byte(0x2)

	var buf bytes.Buffer
	err := WriteHTTPPacket(&buf, int(packetType), body)
	if err != nil {
		t.Fatalf("failed to write HTTP packet: %v", err)
	}

	rc := io.NopCloser(&buf)
	gotType, gotBody, err := ReadHTTPPacket(rc)
	if err != nil {
		t.Fatalf("failed to read HTTP packet: %v", err)
	}

	if gotType != packetType {
		t.Errorf("expected type %d, got %d", packetType, gotType)
	}

	if !bytes.Equal(gotBody, body) {
		t.Errorf("expected body %v, got %v", body, gotBody)
	}
}

func TestResponseUnauth(t *testing.T) {
	// Case 1: Empty challenge message
	rec1 := httptest.NewRecorder()
	responseUnauth(rec1, "")

	res1 := rec1.Result()
	if res1.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, res1.StatusCode)
	}
	if server := res1.Header.Get("Server"); server != "Microsoft-HTTPAPI/2.0" {
		t.Errorf("expected Server header Microsoft-HTTPAPI/2.0, got %s", server)
	}

	wwwAuthHeaders := res1.Header.Values("WWW-Authenticate")
	if len(wwwAuthHeaders) < 3 {
		t.Errorf("expected at least 3 WWW-Authenticate headers (Digest, Basic, Negotiate), got %v", wwwAuthHeaders)
	}

	// Case 2: Specific challenge message
	rec2 := httptest.NewRecorder()
	challenge := "NTLM TlRMTVNTUAACAAA..."
	responseUnauth(rec2, challenge)

	res2 := rec2.Result()
	if res2.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, res2.StatusCode)
	}
	if auth := res2.Header.Get("WWW-Authenticate"); auth != challenge {
		t.Errorf("expected WWW-Authenticate header to match challenge, got %s", auth)
	}
}

func TestAuth(t *testing.T) {
	restore := backupUserMap()
	defer restore()

	usermap["user1"] = "pass1"
	ctx := context.Background()

	// 1. Missing Authorization header
	rec := httptest.NewRecorder()
	if ok := auth(ctx, "", rec); ok {
		t.Errorf("expected auth to fail for empty header")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	// 2. Correct Basic Authentication
	rec = httptest.NewRecorder()
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("user1:pass1"))
	if ok := auth(ctx, authHeader, rec); !ok {
		t.Errorf("expected auth to succeed for correct basic credentials")
	}

	// 3. Incorrect Basic Authentication
	rec = httptest.NewRecorder()
	authHeaderWrong := "Basic " + base64.StdEncoding.EncodeToString([]byte("user1:wrongpass"))
	if ok := auth(ctx, authHeaderWrong, rec); ok {
		t.Errorf("expected auth to fail for incorrect basic credentials")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestAuth_NTLMConnectionIsolation(t *testing.T) {
	// Setup context with connection container for connection 1
	ctx1 := context.WithValue(context.Background(), ntlmSessionKey, &NtlmSessionContainer{})
	rec1 := httptest.NewRecorder()
	
	// Send raw string causing parse error in ParseAuthenticateMessage
	// which acts as the initial negotiate step, generating a challenge
	authHeader := "NTLM " + base64.StdEncoding.EncodeToString([]byte("dummy-negotiate-token"))
	
	ok1 := auth(ctx1, authHeader, rec1)
	if ok1 {
		t.Errorf("expected NTLM negotiate step to return false")
	}
	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec1.Code)
	}
	wwwAuth := rec1.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(wwwAuth, "NTLM ") {
		t.Errorf("expected WWW-Authenticate header to start with NTLM, got %q", wwwAuth)
	}
	
	// Verify connection 1 container got a session assigned
	container1, _ := ctx1.Value(ntlmSessionKey).(*NtlmSessionContainer)
	if container1.Session == nil {
		t.Errorf("expected NTLM session to be created in connection 1 container")
	}
	
	// Create another separate connection context
	ctx2 := context.WithValue(context.Background(), ntlmSessionKey, &NtlmSessionContainer{})
	container2, _ := ctx2.Value(ntlmSessionKey).(*NtlmSessionContainer)
	if container2.Session != nil {
		t.Errorf("expected brand new connection context container to have no active session")
	}
}

func TestHttpHandler_MethodNotAllowed(t *testing.T) {
	restore := backupUserMap()
	defer restore()

	usermap["user1"] = "pass1"

	// Create request with valid basic auth, but unsupported method (e.g. GET)
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte("user1:pass1"))
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()

	httpHandler(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

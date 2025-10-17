package main

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// helper: perform authorize flow: GET /authorize?client_id=...&redirect_uri=...&code_challenge=... then POST /authorize with selected user
func doAuthorize(t *testing.T, srv http.Handler, clientID, redirectURI, codeChallenge, method string) (code string) {
	t.Helper()
	// GET authorize to get login page (we don't parse it, just ensure 200)
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", method)
	}
	req := httptest.NewRequest("GET", "/authorize?"+v.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /authorize returned %d", w.Code)
	}

	// POST authorize - choose the first user from users.yaml (email present in file)
	form := url.Values{}
	form.Set("sub", users[0].Email)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	if codeChallenge != "" {
		form.Set("code_challenge", codeChallenge)
		form.Set("code_challenge_method", method)
	}
	req = httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// Expect redirect to redirectURI with code param
	if w.Code != 302 {
		t.Fatalf("POST /authorize returned %d, body: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect location: %v", err)
	}
	return u.Query().Get("code")
}

func doToken(t *testing.T, srv http.Handler, code, clientID, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestPKCE_S256(t *testing.T) {
	loadUsers()
	generateKey()
	srv := setupRouter()

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	// choose a verifier and compute S256 challenge
	verifier := "test-verifier-123"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := doAuthorize(t, srv, clientID, redirectURI, challenge, "S256")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	w := doToken(t, srv, code, clientID, verifier)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("token exchange failed: %d %s", w.Code, string(body))
	}
}

func TestPKCE_Plain(t *testing.T) {
	loadUsers()
	generateKey()
	srv := setupRouter()

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "plain-verifier"
	challenge := verifier

	code := doAuthorize(t, srv, clientID, redirectURI, challenge, "plain")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	w := doToken(t, srv, code, clientID, verifier)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("token exchange failed: %d %s", w.Code, string(body))
	}
}

func TestPKCE_WrongVerifier(t *testing.T) {
	loadUsers()
	generateKey()
	srv := setupRouter()

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "test-verifier-123"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := doAuthorize(t, srv, clientID, redirectURI, challenge, "S256")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	// Use wrong verifier
	w := doToken(t, srv, code, clientID, "wrong-verifier")
	if w.Code == 200 {
		t.Fatalf("expected token exchange to fail with wrong verifier")
	}
}

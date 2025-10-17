package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v2"
)

type User struct {
	Sub   string `yaml:"sub"`
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

type Config struct {
	Users []User `yaml:"users"`
}

// In-memory store for auth codes
type AuthCodeData struct {
	User      User
	ClientID  string
	ExpiresAt time.Time
}

var (
	users        []User
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	keyID        string
	authCodes    = map[string]AuthCodeData{}
	authCodesMux sync.Mutex
	templates    *template.Template
)

func loadUsers() {
	usersPath := os.Getenv("USERS")
	if usersPath == "" {
		usersPath = "users.yaml"
	}
	data, err := os.ReadFile(usersPath)
	if err != nil {
		log.Fatalf("Failed to read users file (%s): %v", usersPath, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse users.yaml: %v", err)
	}
	// Infer sub from email when not provided.
	for i := range cfg.Users {
		if cfg.Users[i].Sub == "" {
			cfg.Users[i].Sub = cfg.Users[i].Email
		}
	}
	users = cfg.Users
}

func generateKey() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("RSA key generation failed: %v", err)
	}
	publicKey = &privateKey.PublicKey
	// Compute kid (SHA-256 of modulus)
	hash := sha256.Sum256(publicKey.N.Bytes())
	keyID = base64.URLEncoding.EncodeToString(hash[:])[:8]
}

func main() {
	loadUsers()
	generateKey()

	// Parse templates
	tplGlob := filepath.Join("templates", "*.html")
	var err error
	templates, err = template.ParseGlob(tplGlob)
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	// Serve static assets
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/login", handleLoginRedirect)
	http.HandleFunc("/jwks.json", handleJWKS)
	http.HandleFunc("/.well-known/openid-configuration", handleDiscovery)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}
	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("Mock OIDC server listening at http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleLoginRedirect(w http.ResponseWriter, r *http.Request) {
	// Redirect /login?params => /authorize?params
	u := url.URL{
		Path:     "/authorize",
		RawQuery: r.URL.RawQuery,
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	// Render the layout which will include the index content block
	// Pass users so the index can render a clickable user list
	err := templates.ExecuteTemplate(w, "layout.html", map[string]interface{}{
		"Users": users,
	})
	if err != nil {
		// fallback minimal page
		fmt.Fprintf(w, "<html><body><h1>Mock OIDC Server</h1><p>Use /authorize to start login.</p></body></html>")
		return
	}
}

// GET /authorize shows user login form
// POST /authorize processes login, issues code and redirects
func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// Show login page with users and preserve query params
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		nonce := r.URL.Query().Get("nonce")

		if clientID == "" || redirectURI == "" {
			http.Error(w, "Missing client_id or redirect_uri", http.StatusBadRequest)
			return
		}

		// Render the layout which will include the login content block
		err := templates.ExecuteTemplate(w, "layout.html", map[string]interface{}{
			"Users":       users,
			"ClientID":    clientID,
			"RedirectURI": redirectURI,
			"State":       state,
			"Nonce":       nonce,
		})
		if err != nil {
			http.Error(w, "Template render error", http.StatusInternalServerError)
		}
		return
	}

	// POST /authorize: process login, issue code, redirect back
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	sub := r.FormValue("sub") // now contains the user's email
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	// nonce := r.FormValue("nonce")

	if sub == "" || clientID == "" || redirectURI == "" {
		http.Error(w, "Missing parameters", http.StatusBadRequest)
		return
	}

	// Find user by email (sub now holds email)
	var user *User
	for _, u := range users {
		if u.Email == sub {
			user = &u
			break
		}
	}
	if user == nil {
		http.Error(w, "Invalid user", http.StatusBadRequest)
		return
	}

	// Generate a random auth code (base64 32 bytes)
	b := make([]byte, 32)
	_, err = rand.Read(b)
	if err != nil {
		http.Error(w, "Failed to generate code", http.StatusInternalServerError)
		return
	}
	code := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)

	// Store code with user and client
	authCodesMux.Lock()
	authCodes[code] = AuthCodeData{
		User:      *user,
		ClientID:  clientID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	authCodesMux.Unlock()

	// Redirect back to client with code and state
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	// clientSecret ignored in mock

	authCodesMux.Lock()
	authData, ok := authCodes[code]
	if !ok || authData.ExpiresAt.Before(time.Now()) {
		authCodesMux.Unlock()
		http.Error(w, "Invalid or expired code", http.StatusBadRequest)
		return
	}
	// Optional: check clientID matches stored clientID
	if clientID != authData.ClientID {
		authCodesMux.Unlock()
		http.Error(w, "Invalid client_id for code", http.StatusBadRequest)
		return
	}
	delete(authCodes, code) // one-time use
	authCodesMux.Unlock()

	now := time.Now()
	issuer := fmt.Sprintf("http://%s", r.Host)

	claims := jwt.MapClaims{
		"sub":   authData.User.Email, // use email as sub
		"email": authData.User.Email,
		"name":  authData.User.Name,
		"iss":   issuer,
		"aud":   clientID,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
	}

	// Add nonce if passed? (Not implemented here, but you could extend)

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = keyID
	signedToken, err := idToken.SignedString(privateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	resp := map[string]string{
		"access_token": signedToken,
		"id_token":     signedToken,
		"token_type":   "Bearer",
		"expires_in":   "300",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": keyID,
				"n":   n,
				"e":   e,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := fmt.Sprintf("http://%s", r.Host)
	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

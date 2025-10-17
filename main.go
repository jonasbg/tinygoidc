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
	"strings"
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

var (
	users      []User
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
)

const defaultRedirectURI = "http://localhost:5173/api/callback"

func loadUsers() {
	data, err := os.ReadFile("users.yaml")
	if err != nil {
		log.Fatalf("Failed to read users.yaml: %v", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse users.yaml: %v", err)
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

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/jwks.json", handleJWKS)
	http.HandleFunc("/.well-known/openid-configuration", handleDiscovery)

	log.Println("Mock OIDC server listening at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	var currentUser *User
	if cookie, err := r.Cookie("mock_user"); err == nil {
		for _, u := range users {
			if u.Sub == cookie.Value {
				currentUser = &u
				break
			}
		}
	}

	tpl := `
	<html><body>
	{{if .CurrentUser}}
		<p><strong>Logged in as:</strong> {{.CurrentUser.Name}} ({{.CurrentUser.Email}})</p>
	{{end}}
	<h1>Login as:</h1>
	<ul>
	{{range .Users}}
		<li><a href="/login?sub={{.Sub}}">{{.Name}} ({{.Email}})</a></li>
	{{end}}
	</ul></body></html>`
	t := template.Must(template.New("index").Parse(tpl))
	data := map[string]interface{}{
		"Users":       users,
		"CurrentUser": currentUser,
	}
	t.Execute(w, data)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	sub := r.URL.Query().Get("sub")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if redirectURI == "" {
		// No redirect: set dev UI cookie and go back to index
		http.SetCookie(w, &http.Cookie{
			Name:     "mock_user",
			Value:    sub,
			Path:     "/",
			HttpOnly: false,
			MaxAge:   3600,
		})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Real OIDC login flow: redirect back to client with ?code=xxx
	code := sub + "-code"
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Callback received: %v", r.URL.Query())
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.PostFormValue("code")
	clientID := r.PostFormValue("client_id")
	// clientSecret := r.PostFormValue("client_secret") // Ignored in mock

	sub := strings.TrimSuffix(code, "-code")
	var user *User
	for _, u := range users {
		if u.Sub == sub {
			user = &u
			break
		}
	}
	if user == nil {
		http.Error(w, "Invalid code", http.StatusBadRequest)
		return
	}

	now := time.Now()
	issuer := fmt.Sprintf("http://%s", r.Host)

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":   user.Sub,
		"email": user.Email,
		"name":  user.Name,
		"iss":   issuer,
		"aud":   clientID,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
	})
	idToken.Header["kid"] = keyID
	signedToken, _ := idToken.SignedString(privateKey)

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
		"authorization_endpoint":                issuer + "/login",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v2"
)

type User struct {
	Sub      string `yaml:"sub"`
	Name     string `yaml:"name"`
	Email    string `yaml:"email"`
	Initials string `yaml:"-"`
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
	users         []User
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	keyID         string
	authCodes     = map[string]AuthCodeData{}
	authCodesMux  sync.Mutex
	pageTemplates map[string]*template.Template
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
		// Compute initials for avatar display
		cfg.Users[i].Initials = initials(cfg.Users[i].Name)
	}
	users = cfg.Users
}

// initials returns 1-2 uppercase characters representing the name.
func initials(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	parts := strings.Fields(name)
	// helper to get first rune as string
	firstRune := func(s string) string {
		r := []rune(s)
		if len(r) == 0 {
			return ""
		}
		return string(r[0])
	}
	if len(parts) == 1 {
		r := []rune(parts[0])
		if len(r) >= 2 {
			return strings.ToUpper(string(r[0:2]))
		}
		return strings.ToUpper(string(r[0]))
	}
	// Use first letter of first and last name
	return strings.ToUpper(firstRune(parts[0]) + firstRune(parts[len(parts)-1]))
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

	// Parse layout + each page separately so named blocks like {{define "content"}} do not collide
	var err error
	layoutPath := filepath.Join("templates", "layout.html")
	// Collect all page files under templates, excluding layout.html
	var pageFiles []string
	err = filepath.Walk("templates", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".html") {
			// skip layout, we'll include it with each page
			if filepath.Clean(path) == filepath.Clean(layoutPath) {
				return nil
			}
			pageFiles = append(pageFiles, path)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Failed to walk templates dir: %v", err)
	}
	if len(pageFiles) == 0 {
		log.Fatalf("No page templates found in templates/ directory")
	}

	pageTemplates = make(map[string]*template.Template)
	for _, p := range pageFiles {
		t, err := template.ParseFiles(layoutPath, p)
		if err != nil {
			log.Fatalf("Failed to parse template %s: %v", p, err)
		}
		pageTemplates[filepath.Base(p)] = t
	}

	// Create Gin router
	r := gin.Default()

	// We execute page-specific templates directly to avoid define-name collisions

	// Serve static assets from /static
	r.Static("/static", "static")

	r.GET("/", func(c *gin.Context) { handleIndex(c) })
	r.GET("/authorize", func(c *gin.Context) { handleAuthorizeGet(c) })
	r.POST("/authorize", func(c *gin.Context) { handleAuthorizePost(c) })
	r.POST("/token", func(c *gin.Context) { handleToken(c) })
	r.GET("/login", func(c *gin.Context) { handleLoginRedirect(c) })
	r.GET("/jwks.json", func(c *gin.Context) { handleJWKS(c) })
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) { handleDiscovery(c) })

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}
	addr := fmt.Sprintf("0.0.0.0:%s", port)
	log.Printf("Mock OIDC server listening at http://localhost:%s", port)
	log.Fatal(r.Run(addr))
}

func handleLoginRedirect(c *gin.Context) {
	// Redirect /login?params => /authorize?params
	u := url.URL{
		Path:     "/authorize",
		RawQuery: c.Request.URL.RawQuery,
	}
	c.Redirect(302, u.String())
}

func handleIndex(c *gin.Context) {
	// Render index using per-page template to avoid global define name collisions
	t := pageTemplates["index.html"]
	if t == nil {
		c.String(500, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(200)
	if err := t.ExecuteTemplate(c.Writer, "layout.html", gin.H{"Users": users}); err != nil {
		log.Printf("template exec error: %v", err)
	}
}

// GET /authorize shows user login form
// POST /authorize processes login, issues code and redirects
// GET /authorize - render login
func handleAuthorizeGet(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	nonce := c.Query("nonce")

	if clientID == "" || redirectURI == "" {
		c.String(400, "Missing client_id or redirect_uri")
		return
	}

	t := pageTemplates["login.html"]
	if t == nil {
		c.String(500, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(200)
	if err := t.ExecuteTemplate(c.Writer, "layout.html", gin.H{
		"Users":       users,
		"ClientID":    clientID,
		"RedirectURI": redirectURI,
		"State":       state,
		"Nonce":       nonce,
	}); err != nil {
		log.Printf("template exec error: %v", err)
	}
	_ = nonce
}

// POST /authorize - process login
func handleAuthorizePost(c *gin.Context) {
	sub := c.PostForm("sub")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	state := c.PostForm("state")

	if sub == "" || clientID == "" || redirectURI == "" {
		c.String(400, "Missing parameters")
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
		c.String(400, "Invalid user")
		return
	}

	// Generate a random auth code (base64 32 bytes)
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		c.String(500, "Failed to generate code")
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
		c.String(400, "Invalid redirect_uri")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	c.Redirect(302, u.String())
}

func handleToken(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")

	authCodesMux.Lock()
	authData, ok := authCodes[code]
	if !ok || authData.ExpiresAt.Before(time.Now()) {
		authCodesMux.Unlock()
		c.String(400, "Invalid or expired code")
		return
	}
	// Optional: check clientID matches stored clientID
	if clientID != authData.ClientID {
		authCodesMux.Unlock()
		c.String(400, "Invalid client_id for code")
		return
	}
	delete(authCodes, code) // one-time use
	authCodesMux.Unlock()

	now := time.Now()
	issuer := fmt.Sprintf("http://%s", c.Request.Host)

	claims := jwt.MapClaims{
		"sub":   authData.User.Email, // use email as sub
		"email": authData.User.Email,
		"name":  authData.User.Name,
		"iss":   issuer,
		"aud":   clientID,
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
	}

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	idToken.Header["kid"] = keyID
	signedToken, err := idToken.SignedString(privateKey)
	if err != nil {
		c.String(500, "Failed to sign token")
		return
	}

	resp := map[string]string{
		"access_token": signedToken,
		"id_token":     signedToken,
		"token_type":   "Bearer",
		"expires_in":   "300",
	}
	c.JSON(200, resp)
}

func handleJWKS(c *gin.Context) {
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
	c.JSON(200, jwks)
}

func handleDiscovery(c *gin.Context) {
	issuer := fmt.Sprintf("http://%s", c.Request.Host)
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
	c.JSON(200, config)
}

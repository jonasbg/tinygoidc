package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"tinygoidc/internal/config"
	"tinygoidc/internal/oidc"
	"tinygoidc/internal/templates"
)

type Server struct {
	Engine    *gin.Engine
	Templates map[string]*template.Template
	Users     []config.User
	Keys      *oidc.KeySet
	authCodes map[string]authCodeData
	authMux   sync.Mutex
}

type authCodeData struct {
	User                config.User
	ClientID            string
	ExpiresAt           time.Time
	CodeChallenge       string
	CodeChallengeMethod string
}

func New(users []config.User, keys *oidc.KeySet) *Server {
	// load templates from embedded FS
	t := templates.LoadTemplates()
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	s := &Server{Engine: r, Templates: t, Users: users, Keys: keys, authCodes: map[string]authCodeData{}}

	r.Use(func(c *gin.Context) {
		c.Next()
		for _, err := range c.Errors {
			if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
				// suppress logging for client disconnects
				c.Errors = nil
				break
			}
		}
	})

	// static handler: serve embedded assets first, then try several on-disk locations for dev
	r.GET("/static/*any", func(c *gin.Context) {
		path := c.Param("any")
		if path == "" || path == "/" {
			c.String(404, "")
			return
		}
		clean := strings.TrimPrefix(path, "/")

		// try embedded FS (assets/static/clean) first
		if f, err := templates.TemplatesFS.Open("assets/static/" + clean); err == nil {
			defer f.Close()
			data, _ := io.ReadAll(f)
			// prefer extension-based MIME type (css should be text/css)
			ext := filepath.Ext(clean)
			contentType := ""
			if ext != "" {
				contentType = mime.TypeByExtension(ext)
			}
			if contentType == "" {
				contentType = http.DetectContentType(data)
			}
			c.Data(200, contentType, data)
			return
		}

		// fallback to on-disk locations (dev): check common candidate paths
		candidates := []string{
			"internal/templates/assets/static/" + clean,
		}
		for _, p := range candidates {
			if df, derr := os.Open(p); derr == nil {
				defer df.Close()
				data, _ := io.ReadAll(df)
				ext := filepath.Ext(p)
				contentType := ""
				if ext != "" {
					contentType = mime.TypeByExtension(ext)
				}
				if contentType == "" {
					contentType = http.DetectContentType(data)
				}
				c.Data(200, contentType, data)
				return
			}
		}

		c.Status(404)
	})

	// routes
	r.GET("/", s.handleIndex)
	r.GET("/authorize", s.handleAuthorizeGet)
	r.POST("/authorize", s.handleAuthorizePost)
	r.POST("/token", s.handleToken)
	r.GET("/login", s.handleLoginRedirect)
	r.GET("/jwks.json", s.handleJWKS)
	r.GET("/.well-known/openid-configuration", s.handleDiscovery)

	return s
}

// Handler implementations are intentionally compacted and reference Server state directly.
// The full implementations follow previous behavior and use jwt via Keys.

func (s *Server) handleLoginRedirect(c *gin.Context) {
	u := url.URL{Path: "/authorize", RawQuery: c.Request.URL.RawQuery}
	c.Redirect(302, u.String())
}

func (s *Server) handleIndex(c *gin.Context) {
	t := s.Templates["index.html"]
	if t == nil {
		c.String(500, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(200)
	t.ExecuteTemplate(c.Writer, "layout.html", gin.H{"Users": s.Users})
}

func (s *Server) handleAuthorizeGet(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	if clientID == "" || redirectURI == "" {
		c.String(400, "Missing client_id or redirect_uri")
		return
	}
	t := s.Templates["login.html"]
	if t == nil {
		c.String(500, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(200)
	t.ExecuteTemplate(c.Writer, "layout.html", gin.H{
		"Users":               s.Users,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"State":               state,
		"Nonce":               nonce,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	})
}

func (s *Server) handleAuthorizePost(c *gin.Context) {
	sub := c.PostForm("sub")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	state := c.PostForm("state")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")
	if sub == "" || clientID == "" || redirectURI == "" {
		c.String(400, "Missing parameters")
		return
	}
	var user *config.User
	for _, u := range s.Users {
		if u.Email == sub {
			user = &u
			break
		}
	}
	if user == nil {
		c.String(400, "Invalid user")
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	code := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
	s.authMux.Lock()
	s.authCodes[code] = authCodeData{User: *user, ClientID: clientID, ExpiresAt: time.Now().Add(5 * time.Minute), CodeChallenge: codeChallenge, CodeChallengeMethod: codeChallengeMethod}
	s.authMux.Unlock()
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

func (s *Server) handleToken(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	codeVerifier := c.PostForm("code_verifier")
	s.authMux.Lock()
	auth, ok := s.authCodes[code]
	if !ok || auth.ExpiresAt.Before(time.Now()) {
		s.authMux.Unlock()
		c.String(400, "Invalid or expired code")
		return
	}
	if clientID != auth.ClientID {
		s.authMux.Unlock()
		c.String(400, "Invalid client_id for code")
		return
	}
	delete(s.authCodes, code)
	s.authMux.Unlock()
	if auth.CodeChallenge != "" {
		if codeVerifier == "" {
			c.String(400, "Missing code_verifier for PKCE-protected code")
			return
		}
		method := stringsToUpper(auth.CodeChallengeMethod)
		switch method {
		case "S256":
			h := sha256.Sum256([]byte(codeVerifier))
			computed := base64.RawURLEncoding.EncodeToString(h[:])
			if computed != auth.CodeChallenge {
				c.String(400, "Invalid code_verifier")
				return
			}
		case "", "PLAIN":
			if codeVerifier != auth.CodeChallenge {
				c.String(400, "Invalid code_verifier")
				return
			}
		default:
			c.String(400, "Unsupported code_challenge_method")
			return
		}
	}
	issuer := fmt.Sprintf("http://%s", c.Request.Host)
	claims := jwt.MapClaims{"sub": auth.User.Email, "email": auth.User.Email, "name": auth.User.Name, "iss": issuer, "aud": clientID}
	token, err := s.Keys.SignIDToken(claims)
	if err != nil {
		c.String(500, "Failed to sign token")
		return
	}
	resp := map[string]string{"access_token": token, "id_token": token, "token_type": "Bearer", "expires_in": "300"}
	c.JSON(200, resp)
}

func (s *Server) handleJWKS(c *gin.Context) {
	c.JSON(200, s.Keys.JWKS())
}

func (s *Server) handleDiscovery(c *gin.Context) {
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
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	c.JSON(200, config)
}

// helper small wrappers to avoid extra imports in this patch
func stringsToUpper(s string) string { return strings.ToUpper(s) }

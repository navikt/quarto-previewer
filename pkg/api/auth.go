package api

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	tokenLength   = 32
	sessionLength = 7 * time.Hour
)

type OAuth2 interface {
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type Session struct {
	Token   string
	Email   string   `json:"preferred_username"`
	Name    string   `json:"name"`
	Ident   string   `json:"NAVIdent"`
	Groups  []string `json:"groups"`
	Created time.Time
	Expires time.Time
}

type CookieSettings struct {
	Name     string `yaml:"name"`
	MaxAge   int    `yaml:"max_age"`
	Path     string `yaml:"path"`
	Domain   string `yaml:"domain"`
	SameSite string `yaml:"same_site"`
	Secure   bool   `yaml:"secure"`
	HttpOnly bool   `yaml:"http_only"`
}

type Cookies struct {
	Redirect   CookieSettings `yaml:"redirect"`
	OauthState CookieSettings `yaml:"oauth_state"`
	Session    CookieSettings `yaml:"session"`
}

func (c CookieSettings) GetSameSite() http.SameSite {
	switch c.SameSite {
	case "Strict":
		return http.SameSiteStrictMode
	case "Lax":
		return http.SameSiteLaxMode
	case "None":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

type HTTP struct {
	oauth2Config OAuth2
	callbackURL  string
	loginPage    string
	cookies      Cookies
	log          *slog.Logger
	hmacKey      string
	Sessions     map[string]Session
}

func NewHTTP(oauth2Config OAuth2, callbackURL string, loginPage string, hmacKey string, log *slog.Logger) HTTP {
	cookies := Cookies{
		Redirect: CookieSettings{
			Name:     "redirecturi",
			MaxAge:   3600,
			Path:     "/",
			Domain:   "localhost:8080",
			SameSite: "Lax",
			Secure:   true,
			HttpOnly: false,
		},
		OauthState: CookieSettings{
			Name:     "oauthstate",
			MaxAge:   60,
			Path:     "/",
			Domain:   "localhost:8080",
			SameSite: "Lax",
			Secure:   true,
			HttpOnly: false,
		},
		Session: CookieSettings{
			Name:     "session",
			MaxAge:   3600,
			Path:     "/",
			Domain:   "localhost:8080",
			SameSite: "Lax",
			Secure:   true,
			HttpOnly: false,
		},
	}

	return HTTP{
		oauth2Config: oauth2Config,
		callbackURL:  callbackURL,
		loginPage:    loginPage,
		cookies:      cookies,
		log:          log,
		hmacKey:      hmacKey,
		Sessions:     map[string]Session{},
	}
}

func createHMAC(m string, k string) string {
	h := hmac.New(sha256.New, []byte(k))
	h.Write([]byte(m))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (h HTTP) deleteCookie(w http.ResponseWriter, name, path, domain string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		Domain:   domain,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		HttpOnly: true,
	})
}

func (h HTTP) Logout(w http.ResponseWriter, r *http.Request) {
	h.deleteCookie(w, h.cookies.Session.Name, h.cookies.Session.Path, h.cookies.Session.Domain)
	http.Redirect(w, r, h.loginPage, http.StatusFound)
}

func generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (h HTTP) Login(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookies.Redirect.Name,
		Value:    r.URL.Query().Get("redirect_url"),
		Path:     h.cookies.Redirect.Path,
		Domain:   h.cookies.Redirect.Domain,
		MaxAge:   h.cookies.Redirect.MaxAge,
		SameSite: h.cookies.Redirect.GetSameSite(),
		Secure:   h.cookies.Redirect.Secure,
		HttpOnly: h.cookies.Redirect.HttpOnly,
	})

	oauthState := uuid.New().String()
	stateHMAC := createHMAC(oauthState, h.hmacKey)
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookies.OauthState.Name,
		Value:    stateHMAC,
		Path:     h.cookies.OauthState.Path,
		Domain:   h.cookies.OauthState.Domain,
		MaxAge:   h.cookies.OauthState.MaxAge,
		SameSite: h.cookies.OauthState.GetSameSite(),
		Secure:   h.cookies.OauthState.Secure,
		HttpOnly: h.cookies.OauthState.HttpOnly,
	})

	consentUrl := h.oauth2Config.AuthCodeURL(oauthState)
	http.Redirect(w, r, consentUrl, http.StatusFound)
}

func (h HTTP) Callback(w http.ResponseWriter, r *http.Request) {
	redirectPath := "/"
	cookie, err := r.Cookie(h.cookies.Redirect.Name)
	if err == nil {
		redirectPath = cookie.Value
	}

	h.deleteCookie(w, h.cookies.Redirect.Name, h.cookies.Redirect.Path, h.cookies.Redirect.Domain)

	code := r.URL.Query().Get("code")
	if len(code) == 0 {
		http.Redirect(w, r, h.loginPage+"?error=unauthenticated", http.StatusFound)
		return
	}

	oauthCookie, err := r.Cookie(h.cookies.OauthState.Name)
	if err != nil {
		h.log.Error("missing oauth state cookie")
		http.Redirect(w, r, h.loginPage+"?error=invalid-state", http.StatusFound)
		return
	}

	h.deleteCookie(w, h.cookies.OauthState.Name, h.cookies.OauthState.Path, h.cookies.OauthState.Domain)

	state := r.URL.Query().Get("state")
	stateHMAC := createHMAC(state, h.hmacKey)
	if stateHMAC != oauthCookie.Value {
		h.log.Error("incoming state does not match local state")
		http.Redirect(w, r, h.loginPage+"?error=invalid-state", http.StatusFound)
		return
	}

	tokens, err := h.oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		h.log.Error("exchanging authorization code for tokens")
		message := "Internal error: oauth2"
		if strings.HasPrefix(r.Host, "localhost") {
			message = "oauth2 error, try:\n$gcloud auth login --update-adc\n$make env\nbefore running backend"
		}
		http.Error(w, message, http.StatusForbidden)
		return
	}

	rawIDToken, ok := tokens.Extra("id_token").(string)
	if !ok {
		h.log.Error("missing id_token")
		http.Redirect(w, r, h.loginPage+"?error=unauthenticated", http.StatusFound)
		return
	}

	// Parse and verify ID Token payload.
	_, err = h.oauth2Config.Verify(r.Context(), rawIDToken)
	if err != nil {
		h.log.Error("invalid id_token")
		http.Redirect(w, r, h.loginPage+"?error=unauthenticated", http.StatusFound)
		return
	}

	session := &Session{
		Token:   generateSecureToken(tokenLength),
		Expires: time.Now().Add(sessionLength),
	}

	b, err := base64.RawStdEncoding.DecodeString(strings.Split(tokens.AccessToken, ".")[1])
	if err != nil {
		h.log.Error("decoding access token")
		http.Redirect(w, r, h.loginPage+"?error=unauthenticated", http.StatusFound)
		return
	}

	if err := json.Unmarshal(b, session); err != nil {
		h.log.Error("unmarshalling token")
		http.Redirect(w, r, h.loginPage+"?error=unauthenticated", http.StatusFound)
		return
	}

	h.Sessions[session.Token] = *session
	http.SetCookie(w, &http.Cookie{
		Name:     h.cookies.Session.Name,
		Value:    session.Token,
		Path:     h.cookies.Session.Path,
		Domain:   h.cookies.Session.Domain,
		MaxAge:   h.cookies.Session.MaxAge,
		SameSite: h.cookies.Session.GetSameSite(),
		Secure:   h.cookies.Session.Secure,
		HttpOnly: h.cookies.Session.HttpOnly,
	})

	http.Redirect(w, r, h.loginPage+redirectPath, http.StatusFound)
}

func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlParts := strings.Split(chi.URLParam(r, "*"), "/")
		if len(urlParts) < 3 {
			next.ServeHTTP(w, r)
			return
		}

		quartoID := strings.Split(chi.URLParam(r, "*"), "/")[:3]

		intended_audience, err := a.gcsClient.GetObjectWithData(r.Context(), a.bucket, fmt.Sprintf("%s/%s", strings.Join(quartoID, "/"), "intended_audience.json"))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Du har ikke lov til å se denne datafortellingen."))
			return
		}

		allowed := []string{}
		err = json.Unmarshal(intended_audience.Data, &allowed)
		if err != nil {
			a.logger.Error("unmarshalling intended_audience", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// If the intended audience contains "all", allow access to everyone
		if contains(allowed, "all") {
			next.ServeHTTP(w, r)
			return
		}

		// Restrict access based on groups and idents in intended audience
		sessionToken, err := r.Cookie("session")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				http.Redirect(w, r, fmt.Sprintf("/login?redirect_url=%s", strings.Join(quartoID, "/")), http.StatusSeeOther)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		session, ok := a.authAPI.Sessions[sessionToken.Value]
		if !ok {
			http.Redirect(w, r, fmt.Sprintf("/login?redirect_url=%s", strings.Join(quartoID, "/")), http.StatusSeeOther)
			return
		}

		if isAllowedToView(allowed, session.Ident, session.Groups) {
			next.ServeHTTP(w, r)
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Du har ikke lov til å se denne datafortellingen."))
	})
}

func isAllowedToView(allowed []string, ident string, groups []string) bool {
	if len(allowed) == 0 {
		return false
	}

	for _, id := range allowed {
		if strings.ToLower(id) == strings.ToLower(ident) {
			return true
		}
		if contains(groups, id) {
			return true
		}
	}

	return false
}

func contains(list []string, elem string) bool {
	for _, e := range list {
		if e == elem {
			return true
		}
	}

	return false
}

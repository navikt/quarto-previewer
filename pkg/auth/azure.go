package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Session struct {
	Token       string
	AccessToken string
	Email       string `json:"preferred_username"`
	Name        string `json:"name"`
	Ident       string
	Created     time.Time
	Expires     time.Time
}

type Azure struct {
	oauth2.Config

	clientID     string
	clientSecret string
	clientTenant string
	redirectURL  string

	sessions map[string]Session
	provider *oidc.Provider
}

func NewAzure(clientID, clientSecret, clientTenant, redirectURL string) *Azure {
	provider, err := oidc.NewProvider(context.Background(), fmt.Sprintf("https://login.microsoftonline.com/%v/v2.0", clientTenant))
	if err != nil {
		panic(err)
	}

	a := &Azure{
		clientID:     clientID,
		clientSecret: clientSecret,
		clientTenant: clientTenant,
		redirectURL:  redirectURL,
		provider:     provider,
	}
	a.setupOAuth2()
	return a
}

func (a *Azure) setupOAuth2() {
	a.Config = oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		RedirectURL:  a.redirectURL,
		Scopes:       []string{"openid", fmt.Sprintf("%s/.default", a.clientID)},
	}
}

func (a *Azure) KeyDiscoveryURL() string {
	return fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", a.clientTenant)
}

func (a *Azure) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return a.provider.Verifier(&oidc.Config{ClientID: a.clientID}).Verify(ctx, rawIDToken)
}

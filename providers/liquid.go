package providers

import (
	"context"
	"errors"
	"net/url"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

/* LiquidProvider type has a pointer to a ProviderData type, which stores
the login, redeem and profile urls as well as the "read" scope. The scheme
(which is http or https) and host are taken from the env variables. The
provider is very similar to the DigitalOcean provider. */

type LiquidProvider struct {
	*ProviderData
}

var _ Provider = (*LiquidProvider)(nil)

var (
	LiquidScheme = os.Getenv("LIQUID_HTTP_PROTOCOL")
	LiquidHost   = os.Getenv("LIQUID_DOMAIN")
)

const (
	LiquidProviderName = "Liquid"
	LiquidDefaultScope = "read"
)

var (
	LiquidDefaultLoginURL = &url.URL{
		Scheme: LiquidScheme,
		Host:   LiquidHost,
		Path:   "/o/authorize",
	}

	LiquidDefaultRedeemURL = &url.URL{
		Scheme: LiquidScheme,
		Host:   LiquidHost,
		Path:   "/o/token",
	}

	LiquidDefaultProfileURL = &url.URL{
		Scheme: LiquidScheme,
		Host:   LiquidHost,
		Path:   "/accounts/profile",
	}
)

// NewLiquidProvider initiates a new LiquidProvider
func NewLiquidProvider(p *ProviderData) *LiquidProvider {
	p.setProviderDefaults(providerDefaults{
		name:      LiquidProviderName,
		loginURL:  LiquidDefaultLoginURL,
		redeemURL: LiquidDefaultRedeemURL,
		scope:     LiquidDefaultScope,
	})
	return &LiquidProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *LiquidProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("email").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// GetUserName returns the Account UserName
func (p *LiquidProvider) GetUserName(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", err
	}

	name, err := json.GetPath("name").String()
	if err != nil {
		return "", err
	}

	// the liquidHeader is true only for the hypothesys app

	var liquidHeader bool
	_, liquidHeader = os.LookupEnv("LIQUID_ENABLE_HYPOTHESIS_HEADERS")

	if liquidHeader {
		name = "acct:" + name + "@" + os.Getenv("LIQUID_DOMAIN")
	}

	return name, nil
}

// ValidateSessionState validates the AccessToken
func (p *LiquidProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

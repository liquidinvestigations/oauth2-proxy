package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
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

// Instead of implementing GetEmailAddress and GetUserName (each with their own GET request...)
// we just copy/paste the Redeem method from provider_default and set all the SessionData fields
// there.
func (p *LiquidProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		err = p.populateSession(ctx, s)
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(result.Body()))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		created := time.Now()
		s = &sessions.SessionState{AccessToken: a, CreatedAt: &created}
		err = p.populateSession(ctx, s)
	} else {
		err = fmt.Errorf("no access token found %s", result.Body())
	}
	return
}

// This sets up SessionState with the user data from our profile ID.
// The translation might be prettier with more annotated types,
// see the gitlab implementation.
func (p *LiquidProvider) populateSession(ctx context.Context, s *sessions.SessionState) error {
	if s.AccessToken == "" {
		return errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil { return err }

	s.User, err = json.GetPath("id").String()
	if err != nil { return err }
	log.Printf("LOGGING IN %s!\n", s.User)

	// hypothesis user header hack
	var liquidHeader bool
	_, liquidHeader = os.LookupEnv("LIQUID_ENABLE_HYPOTHESIS_HEADERS")
	if liquidHeader {
		s.User = "acct:" + s.User + "@" + os.Getenv("LIQUID_DOMAIN")
	}

	s.Email, err = json.GetPath("email").String()
	if err != nil { return err }
	log.Printf("Email %s!\n", s.Email)

	s.PreferredUsername, err = json.GetPath("name").String()
	if err != nil { return err }

	s.Groups, err = json.GetPath("roles").StringArray()
	log.Printf("Groups %v!\n", s.Groups)
	if err != nil { return err }

	return nil
}

// ValidateSessionState validates the AccessToken
func (p *LiquidProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

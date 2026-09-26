package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

type claims struct {
	Active    bool            `json:"active"`
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	ClientID  string          `json:"client_id"`
	Audience  json.RawMessage `json:"aud"`
	Scope     string          `json:"scope"`
	Expires   int64           `json:"exp"`
	NotBefore int64           `json:"nbf"`
	TokenType string          `json:"token_type"`
}

// authenticate never returns token contents, upstream bodies or transport URLs.
func (g *Gateway) authenticate(ctx context.Context, r *http.Request) (claims, error) {
	var c claims
	if len(r.Header.Values("Authorization")) != 1 {
		return c, fmt.Errorf("invalid token")
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 8192 {
		return c, fmt.Errorf("invalid token")
	}
	form := url.Values{"token": {parts[1]}, "token_type_hint": {"access_token"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, g.config.IntrospectionURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	credential := g.introspectionToken
	if g.config.IntrospectionAuthHeader == "Authorization" {
		credential = "Bearer " + credential
	}
	req.Header.Set(g.config.IntrospectionAuthHeader, credential)
	resp, err := g.authClient.Do(req)
	if err != nil {
		return c, fmt.Errorf("authentication unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c, fmt.Errorf("authentication unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || json.Unmarshal(body, &c) != nil {
		return claims{}, fmt.Errorf("authentication unavailable")
	}
	var audiences []string
	var audience string
	if json.Unmarshal(c.Audience, &audience) == nil {
		audiences = []string{audience}
	} else if json.Unmarshal(c.Audience, &audiences) != nil {
		return c, fmt.Errorf("invalid token")
	}
	now := time.Now().Unix()
	if !c.Active || c.Expires <= now || c.NotBefore > now || c.Issuer != g.config.Issuer || c.Subject != g.config.Subject || c.ClientID != g.config.ClientID || !slices.Contains(audiences, g.config.Resource) || !slices.Contains(strings.Fields(c.Scope), g.config.Scope) || !strings.EqualFold(c.TokenType, "Bearer") {
		return c, fmt.Errorf("invalid token")
	}
	return c, nil
}

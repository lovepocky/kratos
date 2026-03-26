// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
	"github.com/ory/x/httpx"
)

const (
	wechatMPCode2SessionURL = "https://api.weixin.qq.com/sns/jscode2session"
)

type ProviderWechatMP struct {
	config            *Configuration
	reg               Dependencies
	wechatProviderSub string
}

var _ OAuth2Provider = (*ProviderWechatMP)(nil)

func NewProviderWechatMP(config *Configuration, reg Dependencies) Provider {
	providerSub := strings.ToLower(strings.TrimSpace(os.Getenv("WECHAT_PROVIDER_SUB")))
	if providerSub == "" {
		providerSub = "unionid"
	}

	if providerSub != "unionid" && providerSub != "openid" {
		reg.Logger().
			WithField("provider", config.ID).
			WithField("WECHAT_PROVIDER_SUB", providerSub).
			Warn("Invalid WECHAT_PROVIDER_SUB, fallback to unionid")
		providerSub = "unionid"
	}

	return &ProviderWechatMP{
		config:            config,
		reg:               reg,
		wechatProviderSub: providerSub,
	}
}

func (g *ProviderWechatMP) Config() *Configuration {
	return g.config
}

func (g *ProviderWechatMP) oauth2(ctx context.Context) *oauth2.Config {
	endpoint := oauth2.Endpoint{
		// WeChat Mini Program login does not use browser OAuth redirect auth URL,
		// but oauth2.Config requires this field to be populated.
		AuthURL:  "https://open.weixin.qq.com/connect/oauth2/authorize",
		TokenURL: wechatMPCode2SessionURL,
	}

	return &oauth2.Config{
		ClientID:     g.config.ClientID,
		ClientSecret: g.config.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       g.config.Scope,
		RedirectURL:  g.config.Redir(g.reg.Config().OIDCRedirectURIBase(ctx)),
	}
}

func (g *ProviderWechatMP) AuthCodeURLOptions(_ ider) []oauth2.AuthCodeOption {
	return nil
}

func (g *ProviderWechatMP) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	return g.oauth2(ctx), nil
}

func (g *ProviderWechatMP) Exchange(ctx context.Context, code string, _ ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	conf, err := g.OAuth2(ctx)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	u, err := url.Parse(conf.Endpoint.TokenURL)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	q := u.Query()
	q.Set("appid", conf.ClientID)
	q.Set("secret", conf.ClientSecret)
	q.Set("js_code", code)
	q.Set("grant_type", "authorization_code")
	u.RawQuery = q.Encode()

	client := g.reg.HTTPClient(ctx, httpx.ResilientClientDisallowInternalIPs())
	req, err := retryablehttp.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	defer resp.Body.Close()

	if err := logUpstreamError(g.reg.Logger(), resp); err != nil {
		return nil, err
	}

	var s struct {
		ErrCode    int    `json:"errcode"`
		ErrMsg     string `json:"errmsg"`
		OpenID     string `json:"openid"`
		UnionID    string `json:"unionid"`
		SessionKey string `json:"session_key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	if s.ErrCode != 0 {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("wechat jscode2session failed: errcode=%d errmsg=%s", s.ErrCode, s.ErrMsg))
	}

	token := (&oauth2.Token{AccessToken: s.OpenID}).WithExtra(map[string]interface{}{
		"openid":      s.OpenID,
		"unionid":     s.UnionID,
		"session_key": s.SessionKey,
	})

	return token, nil
}

func (g *ProviderWechatMP) Claims(_ context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	openid, _ := exchange.Extra("openid").(string)
	unionid, _ := exchange.Extra("unionid").(string)
	sessionKey, _ := exchange.Extra("session_key").(string)

	if openid == "" {
		openid = exchange.AccessToken
	}

	subject := openid
	if g.wechatProviderSub == "unionid" && unionid != "" {
		subject = unionid
	}

	if subject == "" {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReason("wechat mini program did not return a usable subject"))
	}

	nickname := strings.TrimSpace(query.Get("nickname"))
	name := strings.TrimSpace(query.Get("name"))
	if name == "" {
		name = nickname
	}
	if name == "" {
		name = subject
	}

	picture := strings.TrimSpace(query.Get("picture"))
	if picture == "" {
		picture = strings.TrimSpace(query.Get("avatar"))
	}
	if picture == "" {
		picture = strings.TrimSpace(query.Get("avatar_url"))
	}

	rawClaims := map[string]interface{}{
		"openid":      openid,
		"unionid":     unionid,
		"session_key": sessionKey,
	}

	return &Claims{
		Issuer:    wechatMPCode2SessionURL,
		Subject:   subject,
		Nickname:  nickname,
		Name:      name,
		Picture:   picture,
		RawClaims: rawClaims,
	}, nil
}

func (g *ProviderWechatMP) AuthCodeURL(c *oauth2.Config, state string, _ ...oauth2.AuthCodeOption) string {
	u, err := url.Parse(c.RedirectURL)
	if err != nil {
		return fmt.Sprintf("%s?state=%s", c.RedirectURL, url.QueryEscape(state))
	}

	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

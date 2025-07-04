// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/x/httpx"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/ory/herodot"
)

type ProviderWechat struct {
	config            *Configuration
	reg               Dependencies
	wechatProviderSub string
}

var _ OAuth2Provider = (*ProviderWechat)(nil)

func NewProviderWechat(
	config *Configuration,
	reg Dependencies,
) Provider {
	// 獲取 WECHAT_PROVIDER_SUB 環境變量
	wechatProviderSub, found := os.LookupEnv("WECHAT_PROVIDER_SUB")

	// 定義預設值
	defaultValue := "unionid"

	// 根據獲取到的值來判斷
	if found {
		// 如果環境變量存在，檢查其值
		if wechatProviderSub == "unionid" || wechatProviderSub == "openid" {
			// 如果是 unionid 或 openid，則使用該值
			fmt.Printf("WECHAT_PROVIDER_SUB 環境變量已設置為: %s\n", wechatProviderSub)
		} else {
			// 如果存在但值不是 unionid 或 openid，則使用預設值並發出警告
			fmt.Printf("WECHAT_PROVIDER_SUB 環境變量的值 '%s' 無效，將使用預設值: %s\n", wechatProviderSub, defaultValue)
			wechatProviderSub = defaultValue
		}
	} else {
		// 如果環境變量不存在，則使用預設值
		fmt.Printf("WECHAT_PROVIDER_SUB 環境變量未設置，將使用預設值: %s\n", defaultValue)
		wechatProviderSub = defaultValue
	}

	fmt.Printf("最終使用的 WECHAT_PROVIDER_SUB: %s\n", wechatProviderSub)

	return &ProviderWechat{
		config:            config,
		reg:               reg,
		wechatProviderSub: wechatProviderSub,
	}
}

func (g *ProviderWechat) Config() *Configuration {
	return g.config
}

func (g *ProviderWechat) oauth2(ctx context.Context) *oauth2.Config {
	endpoint := oauth2.Endpoint{
		AuthURL:  "https://open.weixin.qq.com/connect/qrconnect",
		TokenURL: "https://api.weixin.qq.com/sns/oauth2/access_token",
	}

	return &oauth2.Config{
		ClientID:     g.config.ClientID,
		ClientSecret: g.config.ClientSecret,
		Endpoint:     endpoint,
		// DingTalk only allow to set scopes: openid or openid corpid
		Scopes:      g.config.Scope,
		RedirectURL: g.config.Redir(g.reg.Config().OIDCRedirectURIBase(ctx)),
	}
}

func (g *ProviderWechat) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("prompt", "consent"),
	}
}

func (g *ProviderWechat) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	return g.oauth2(ctx), nil
}

func (g *ProviderWechat) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	conf, err := g.OAuth2(ctx)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	pTokenParams := &struct {
		ClientId     string `json:"appid"`
		ClientSecret string `json:"secret"`
		Code         string `json:"code"`
		GrantType    string `json:"grantType"`
	}{conf.ClientID, conf.ClientSecret, code, "authorization_code"}
	bs, err := json.Marshal(pTokenParams)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	r := strings.NewReader(string(bs))
	client := g.reg.HTTPClient(ctx, httpx.ResilientClientDisallowInternalIPs())

	// create request
	u, err := url.Parse(conf.Endpoint.TokenURL)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	// 3. 获取 url.Values 对象
	q := u.Query() // 获取现有的查询参数，如果没有则返回一个空的 Values 对象

	// 4. 添加查询参数
	q.Add("appid", pTokenParams.ClientId)
	q.Add("secret", pTokenParams.ClientSecret)
	q.Add("code", pTokenParams.Code)
	// 如果参数名可能重复（例如多个 id），继续使用 Add()
	q.Add("grant_type", pTokenParams.GrantType)

	// 5. 将 url.Values 编码为字符串并设置回 URL
	u.RawQuery = q.Encode()

	req, err := retryablehttp.NewRequest("POST", u.String(), r)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		// g.reg.Logger().WithError(err).WithField("http_request", req).Debug("HTTP request details")
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	defer resp.Body.Close()

	if err := logUpstreamError(g.reg.Logger(), resp); err != nil {
		return nil, err
	}

	var dToken struct {
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		AccessToken string `json:"access_token"` // Interface call credentials
		ExpiresIn   int64  `json:"expires_in"`   // access_token interface call credential timeout time, unit (seconds)
		OpenId      string `json:"openid"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&dToken); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	if dToken.ErrCode != 0 {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("dToken.ErrCode = %d, dToken.ErrMsg = %s", dToken.ErrCode, dToken.ErrMsg))
	}

	token := &oauth2.Token{
		AccessToken: dToken.AccessToken,
		Expiry:      time.Unix(time.Now().Unix()+int64(dToken.ExpiresIn), 0),
	}
	token.WithExtra(dToken)
	return token, nil
}

func (g *ProviderWechat) Claims(ctx context.Context, exchange *oauth2.Token, _ url.Values) (*Claims, error) {
	userInfoURL := "https://api.weixin.qq.com/sns/userinfo"
	accessToken := exchange.AccessToken
	openid := exchange.Extra("OpenId")
	g.reg.Logger().Debugf("openId = %s, accessToken = %s", openid, accessToken)

	// create request
	u, err := url.Parse(userInfoURL)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	// 3. 获取 url.Values 对象
	q := u.Query() // 获取现有的查询参数，如果没有则返回一个空的 Values 对象

	// 4. 添加查询参数
	q.Add("access_token", accessToken)
	q.Add("openid", fmt.Sprintf("%s", openid))

	// 5. 将 url.Values 编码为字符串并设置回 URL
	u.RawQuery = q.Encode()

	client := g.reg.HTTPClient(ctx, httpx.ResilientClientDisallowInternalIPs())
	req, err := retryablehttp.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	// req.Header.Add("x-acs-dingtalk-access-token", accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	defer resp.Body.Close()

	/**
	{
		"openid": "OPENID",
		"nickname": "NICKNAME",
		"sex": 1,
		"province": "PROVINCE",
		"city": "CITY",
		"country": "COUNTRY",
		"headimgurl": "http://thirdwx.qlogo.cn/mmopen/g3MonKZtNHxalzgejqxIBHA4icMtfazbXhlHnLd",
		"privilege": [],
		"unionid": "UNIONID"
	}
	*/
	var respBody struct {
		ErrCode    int    `json:"errcode"`
		ErrMsg     string `json:"errmsg"`
		Nickname   string `json:"nickname"`
		Sex        int64  `json:"sex"`
		OpenId     string `json:"openid"`
		Province   string `json:"province"`
		City       string `json:"city"`
		Country    string `json:"country"`
		Headimgurl string `json:"headimgurl"`
		Unionid    string `json:"unionid"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}

	if respBody.ErrCode != 0 {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("ErrCode = %d, ErrMsg = %s", respBody.ErrCode, respBody.ErrMsg))
	}

	if err := logUpstreamError(g.reg.Logger(), resp); err != nil {
		return nil, err
	}

	// if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
	// 	return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	// }

	// if user.ErrMsg != "" {
	// 	return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("userResp.ErrCode = %s, userResp.ErrMsg = %s", user.ErrCode, user.ErrMsg))
	// }

	user := respBody

	var userMap2 map[string]interface{}
	userBytes, err := json.Marshal(user) // 將 struct 序列化為 JSON 字節
	if err != nil {
		fmt.Println("Error marshalling user:", err)
	}
	err = json.Unmarshal(userBytes, &userMap2) // 將 JSON 字節反序列化為 map
	if err != nil {
		fmt.Println("Error unmarshalling to map:", err)
	}

	var finalID string // 宣告一個變數來儲存結果

	if g.wechatProviderSub == "openid" {
		finalID = user.OpenId
	} else {
		finalID = user.Unionid
	}

	return &Claims{
		Issuer:   userInfoURL,
		Subject:  finalID,
		Nickname: user.Nickname,
		Name:     user.Nickname,
		Picture:  user.Headimgurl,
		// Email:               "",
		// EmailVerified:       false,
		// PhoneNumber:         "+" + user.StateCode + user.Mobile,
		// PhoneNumberVerified: user.Mobile != "",
		RawClaims: userMap2,
	}, nil
}

func (g *ProviderWechat) AuthCodeURL(c *oauth2.Config, state string, opts ...oauth2.AuthCodeOption) string {
	g.reg.Logger().Debug("AuthCodeURL")
	return strings.Replace(c.AuthCodeURL(state, opts...), "client_id", "appid", 1)
}

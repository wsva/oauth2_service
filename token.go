package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	wl_net "github.com/wsva/lib_go/net"
	"github.com/wsva/oauth2_service/db"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(account_id, ip string, key ed25519.PrivateKey) (string, string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   account_id,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(300 * time.Second)),
		NotBefore: jwt.NewNumericDate(time.Now()),
	}

	jwtToken := jwt.Token{
		Method: jwt.SigningMethodEdDSA,
		Header: map[string]any{
			"typ":    "JWT",
			"alg":    "EdDSA",
			"ip":     ip,
			"random": rand.Int(), // to ensure every token is different
		},
		Claims: claims,
	}

	access, err := jwtToken.SignedString(key)
	if err != nil {
		return "", "", err
	}

	refresh := uuid.NewSHA1(uuid.Must(uuid.NewRandom()), []byte(access)).String()
	refresh = base64.URLEncoding.EncodeToString([]byte(refresh))
	refresh = strings.ToUpper(strings.TrimRight(refresh, "="))

	return access, refresh, nil
}

func VerifyToken(signingString string, sig []byte, key ed25519.PublicKey) bool {
	return ed25519.Verify(key, []byte(signingString), sig)
}

/*
HttpOnly:
设置为 true 时，JavaScript 无法通过 document.cookie 访问这个 Cookie
可以防止 XSS 攻击窃取用户的敏感 Cookie（如 session_id、access_token）
推荐用法：对敏感 cookie（如认证 token、session）必须设置

Secure:
设置为 true 时，只在 HTTPS 请求中发送此 Cookie
如果是 HTTP 请求，浏览器不会带这个 Cookie
作用是防止敏感信息在明文传输中被劫持
推荐用法：生产环境中，只要你在使用 HTTPS，就应该加上

SameSite:
控制 Cookie 是否可以被第三方网站请求中携带，防止 CSRF 攻击（跨站请求伪造）
SameSiteLaxMode
普通 GET 请求可携带 Cookie（如点击跳转），POST、PUT 等通常不能
推荐用于登录态 Cookie
*/
func SetCookieToken(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
		Expires:  time.Now().Add(7 * 24 * time.Hour), // longer expiration
	})
}

func DeleteCookieToken(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // this deletes the cookie
	})
}

func ParseTokenFromHeader(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	if len(token) > 6 && strings.ToUpper(token[0:7]) == "BEARER " {
		return token[7:], nil
	}
	return token, nil
}

// access_token, refresh_token
func ParseTokenFromCookie(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", errors.New("no token found in cookie")
	}
	//cookie.Expires 输出一下即可知道，不能正确获取到
	/* if cookie.Expires.Before(time.Now()) {
		return "", errors.New("token has expired")
	} */
	return cookie.Value, nil
}

// parse cookie first
func ParseTokenFromRequest(r *http.Request) (string, error) {
	token, err := ParseTokenFromCookie(r, "access_token")
	if err == nil {
		return token, nil
	} else {
		fmt.Println(err)
	}
	token, err = ParseTokenFromHeader(r)
	if err == nil {
		return token, nil
	} else {
		fmt.Println(err)
	}
	return "", errors.New("no token found")
}

type AuthInfo struct {
	Authorized  bool
	AccessToken string
	AccountID   string
	RealName    string
}

func CheckAuthorization(r *http.Request) *AuthInfo {
	ip := wl_net.GetIPFromRequest(r).String()
	tokenString, err := ParseTokenFromRequest(r)
	if err == nil {
		account_id, realname, err := db.DBCheckToken(tokenString, ip, &cc.DB)
		if err == nil {
			return &AuthInfo{
				Authorized:  true,
				AccessToken: tokenString,
				AccountID:   account_id,
				RealName:    realname,
			}
		}
	}
	return &AuthInfo{
		Authorized: false,
	}
}

package main

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wsva/auth_service/db"
	wl_net "github.com/wsva/lib_go/net"
	wl_uuid "github.com/wsva/lib_go/uuid"
	wl_int "github.com/wsva/lib_go_integration"

	"github.com/golang-jwt/jwt/v5"
)

func NewClaims(sub, aud string) jwt.Claims {
	return &jwt.RegisteredClaims{
		Issuer:    "auth_service",
		Subject:   sub,
		Audience:  jwt.ClaimStrings{aud},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        wl_uuid.New(),
	}
}

func GenerateToken(key *rsa.PrivateKey, claims jwt.Claims) (string, string, error) {
	jwtToken := jwt.Token{
		Method: &jwt.SigningMethodRSA{Name: "RS256", Hash: crypto.SHA256},
		Header: map[string]any{
			"typ": "JWT",
			"alg": "RS256", // Auth.js needs RS256
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

type AuthInfo struct {
	Authorized bool
	Name       string
	Email      string
	Token      *db.Token
}

func CheckAuthorization(r *http.Request, check_ip bool) *AuthInfo {
	tokenString, err := wl_int.ParseTokenFromRequest(r)
	if err != nil {
		return &AuthInfo{Authorized: false}
	}
	dt, name, err := VerifyAccessToken(tokenString)
	if err != nil {
		return &AuthInfo{Authorized: false}
	}
	if check_ip && dt.IP != wl_net.GetIPFromRequest(r).String() {
		return &AuthInfo{Authorized: false}
	}
	return &AuthInfo{
		Authorized: true,
		Name:       name,
		Email:      dt.AccountID,
		Token:      dt,
	}
}

func VerifyAccessToken(access_token string) (*db.Token, string, error) {
	token, err := jwt.Parse(access_token, func(t *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, "", err
	}
	if !token.Valid {
		return nil, "", errors.New("invalid token")
	}
	dt := &db.Token{AccessToken: access_token}
	return dt.DBQuery(&cc.DB)
}

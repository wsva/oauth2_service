package main

import (
	"crypto/ed25519"
	"encoding/base64"
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

func GenerateToken(key ed25519.PrivateKey, claims jwt.Claims) (string, string, error) {
	jwtToken := jwt.Token{
		Method: &jwt.SigningMethodEd25519{},
		Header: map[string]any{
			"typ": "JWT",
			"alg": "EdDSA",
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

type AuthInfo struct {
	Authorized  bool
	AccessToken string
	AccountID   string
	RealName    string
}

func CheckAuthorization(r *http.Request) *AuthInfo {
	ip := wl_net.GetIPFromRequest(r).String()
	tokenString, err := wl_int.ParseTokenFromRequest(r)
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

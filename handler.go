package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	wl_http "github.com/wsva/lib_go/http"
	wl_net "github.com/wsva/lib_go/net"
	wl_int "github.com/wsva/lib_go_integration"
	"golang.org/x/crypto/bcrypt"

	"github.com/wsva/auth_service/db"
)

func handleSignUp(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	req, err := wl_http.ParseRequest(r, 1024)
	if err != nil {
		wl_http.RespondError(w, "read error")
		return
	}

	var account db.Account
	err = json.Unmarshal(req.Data, &account)
	if err != nil {
		wl_http.RespondError(w, "unmarshal error")
		return
	}

	hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(account.Passwd), 10)
	if err != nil {
		wl_http.RespondError(w, "hash error")
		return
	}

	account.Passwd = string(hashedPasswd)
	account.MenuRole = "guest"
	account.Valid = "Y"

	err = account.DBInsert(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}

	wl_http.RespondSuccess(w)
}

func handleSignIn(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	realip := wl_net.GetIPFromRequest(r).String()
	if loginAudit.Abnormal("", realip) {
		loginAudit.AddFailed("", realip)
		wl_http.RespondError(w, "audit error")
		return
	}

	req, err := wl_http.ParseRequest(r, 1024)
	if err != nil {
		loginAudit.AddFailed("", realip)
		wl_http.RespondError(w, "read error")
		return
	}

	// use ID and Passwd only
	var account db.Account
	err = json.Unmarshal(req.Data, &account)
	if err != nil {
		loginAudit.AddFailed("", realip)
		wl_http.RespondError(w, "unmarshal error")
		return
	}

	if loginAudit.Abnormal(account.ID, realip) {
		loginAudit.AddFailed(account.ID, realip)
		wl_http.RespondError(w, "audit error")
		return
	}

	err = account.Verify(&cc.DB)
	if err != nil {
		loginAudit.AddFailed(account.ID, realip)
		wl_http.RespondError(w, err)
		return
	}
	if loginAudit.Abnormal(account.ID, realip) {
		loginAudit.AddFailed(account.ID, realip)
		wl_http.RespondError(w, "audit error")
		return
	}

	claims := NewClaims(account.ID, "auth_service")
	accessToken, refreshToken, err := GenerateToken(privateKey, claims)
	if loginAudit.Abnormal(account.ID, realip) {
		wl_http.RespondError(w, "token error")
		return
	}

	token := db.Token{
		Token:     accessToken,
		AccoundID: account.ID,
		IP:        wl_net.GetIPFromRequest(r).String(),
		LoginAt:   time.Now(),
		ExpireAt:  time.Now().Add(7 * 24 * time.Hour),
	}
	err = token.DBInsert(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}

	wl_int.SetCookieToken(w, "access_token", accessToken, int(7*24*time.Hour/time.Second))
	wl_int.SetCookieToken(w, "refresh_token", refreshToken, int(7*24*time.Hour/time.Second))

	wl_http.RespondJSON(w, wl_http.Response{
		Success: true,
		Data: wl_http.ResponseData{
			List: []string{
				accessToken, account.ID, account.RealName, refreshToken,
			},
		},
	})
}

func handleToken(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	code := r.FormValue("code")
	code_verifier := r.FormValue("code_verifier")
	//grant_type := r.FormValue("grant_type")
	//redirect_uri := r.FormValue("redirect_uri")

	codeObj, ok := codeMap.VerifyChallenge(code, code_verifier)
	if !ok {
		wl_http.RespondError(w, "code error")
		return
	}

	claims := NewClaims(codeObj.AccountID, codeObj.ClientID)
	accessToken, refreshToken, err := GenerateToken(privateKey, claims)
	if err != nil {
		wl_http.RespondError(w, err)
		return
	}

	token := db.Token{
		Token:     accessToken,
		AccoundID: codeObj.AccountID,
		IP:        wl_net.GetIPFromRequest(r).String(),
		LoginAt:   time.Now(),
		ExpireAt:  time.Now().Add(7 * 24 * time.Hour),
	}
	err = token.DBInsert(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}

	wl_http.RespondJSON(w, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"refresh_token": refreshToken,
		"expires_in":    7 * 24 * time.Hour / time.Second,
		"scope":         codeObj.Scope,
		"id_token":      accessToken,
	})
}

/*
response_type=code
code_challenge_method=S256
*/
func handleAuthorize(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	scope := r.FormValue("scope")
	client_id := r.FormValue("client_id")
	state := r.FormValue("state")
	code_challenge := r.FormValue("code_challenge")
	redirect_uri := r.FormValue("redirect_uri")

	ai := CheckAuthorization(r)
	if ai.Authorized {
		code := codeMap.NewCode(scope, client_id, ai.AccountID, code_challenge)
		http.Redirect(w, r, fmt.Sprintf("%s?code=%s&state=%v", redirect_uri, code, state), http.StatusFound)
		return
	}
	redirectURL := "/login?return_to=" + url.QueryEscape(r.URL.String())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func handleRevoke(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ai := CheckAuthorization(r)
	if !ai.Authorized {
		wl_http.RespondError(w, "unauthorized")
		return
	}
	err := (&db.Token{Token: ai.AccessToken}).DBDelete(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "revoke error")
		return
	}
	wl_http.RespondSuccess(w)

	/*
		req, err := wl_http.ParseRequest(r, 1024)
		if err != nil {
			wl_http.RespondError(w, "read error")
			return
		}

		var token db.Token
		err = json.Unmarshal(req.Data, &token)
		if err != nil {
			wl_http.RespondError(w, "unmarshal error")
			return
		}
	*/
}

func handleUserInfo(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ai := CheckAuthorization(r)
	if !ai.Authorized {
		w.WriteHeader(http.StatusUnauthorized)
		wl_http.RespondJSON(w, map[string]any{
			"error":             "invalid_token",
			"error_description": "Access token is missing or invalid",
		})
		return
	}

	account := db.Account{ID: ai.AccountID}
	err := account.DBQuery(&cc.DB)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		wl_http.RespondJSON(w, map[string]any{
			"error":             "internal_server_error",
			"error_description": "Query database error",
		})
		return
	}

	wl_http.RespondJSON(w, wl_int.UserInfo{
		Name:  account.RealName,
		Email: account.ID,
	})
}

func handleIntrospect(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	access_token := r.FormValue("token")
	token, err := jwt.Parse(access_token, func(t *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err == nil && token.Valid {
		wl_http.RespondJSON(w, wl_int.IntrospectResponse{Active: true})
		return
	}
	if err != nil {
		fmt.Println(err)
	}
	wl_http.RespondJSON(w, wl_int.IntrospectResponse{Active: false})
}

func handleJwks(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	wl_http.RespondJSON(w, map[string]any{
		"keys": []map[string]any{
			{
				"kty": "OKP",     // Octet Key Pair
				"crv": "Ed25519", // Curve name
				"x":   base64.RawURLEncoding.EncodeToString(publicKey),
			},
		},
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	tokenString, err := wl_int.ParseTokenFromRequest(r)
	if err == nil {
		(&db.Token{Token: tokenString}).DBDelete(&cc.DB)
	}

	wl_int.DeleteCookieToken(w, "access_token")
	wl_int.DeleteCookieToken(w, "refresh_token")

	wl_http.RespondSuccess(w)
}

func handleAccountUpdate(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !CheckAuthorization(r).Authorized {
		wl_http.RespondError(w, "unauthorized")
		return
	}

	req, err := wl_http.ParseRequest(r, 1024)
	if err != nil {
		wl_http.RespondError(w, err)
		return
	}
	var account db.Account
	err = json.Unmarshal(req.Data, &account)
	if err != nil {
		wl_http.RespondError(w, err)
		return
	}

	if account.Passwd != "" {
		hashedPasswd, err := bcrypt.GenerateFromPassword([]byte(account.Passwd), 10)
		if err != nil {
			wl_http.RespondError(w, "hash error")
			return
		}
		account.Passwd = string(hashedPasswd)
	}

	if account.MenuRole == "" {
		account.MenuRole = "guest"
	}
	if account.Valid == "" {
		account.Valid = "Y"
	}

	err = account.DBUpdate(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, err)
		return
	}
	wl_http.RespondSuccess(w)
}

// login page in browser
func handleLogin(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if CheckAuthorization(r).Authorized {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.ServeFile(w, r, filepath.Join(Basepath, "template/html/login.html"))
}

func handleRegister(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if CheckAuthorization(r).Authorized {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	http.ServeFile(w, r, filepath.Join(Basepath, "template/html/register.html"))
}

func handleDashboard(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if CheckAuthorization(r).Authorized {
		http.ServeFile(w, r, filepath.Join(Basepath, "template/html/dashboard.html"))
		return
	}
	// redirect to /login
	redirectURL := "/login?return_to=" + url.QueryEscape(r.URL.String())
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func handleAccountAll(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !CheckAuthorization(r).Authorized {
		wl_http.RespondError(w, "unauthorized")
		return
	}

	list, err := db.QueryAccountAll(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}
	resp := wl_http.Response{
		Success: true,
		Data: wl_http.ResponseData{
			List: list,
		},
	}
	resp.DoResponse(w)
}

func handleMenuAll(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ai := CheckAuthorization(r)
	if !ai.Authorized {
		wl_http.RespondError(w, "unauthorized")
		return
	}

	menuList, err := db.QueryMenuAll(&cc.DB, ai.AccountID)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}
	resp := wl_http.Response{
		Success: true,
		Data: wl_http.ResponseData{
			List: menuList,
		},
	}
	resp.DoResponse(w)
}

func handleCheckMenuAccess(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ai := CheckAuthorization(r)
	if !ai.Authorized {
		wl_http.RespondError(w, "unauthorized")
		return
	}

	req, err := wl_http.ParseRequest(r, 1024)
	if err != nil {
		wl_http.RespondError(w, "read error")
		return
	}
	var msg struct {
		MenuURL string `json:"menu_url"`
	}
	err = json.Unmarshal(req.Data, &msg)
	if err != nil {
		wl_http.RespondError(w, "read error")
		return
	}

	reg := regexp.MustCompile(`/$`)
	msg.MenuURL = reg.ReplaceAllString(msg.MenuURL, "")

	err = db.CheckMenuAccess(&cc.DB, ai.AccountID, msg.MenuURL)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}
	wl_http.RespondSuccess(w)
}

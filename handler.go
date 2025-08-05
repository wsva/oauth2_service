package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	wl_http "github.com/wsva/lib_go/http"
	wl_net "github.com/wsva/lib_go/net"
	"golang.org/x/crypto/bcrypt"

	"github.com/wsva/oauth2_service/db"
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

	ip := wl_net.GetIPFromRequest(r).String()
	accessToken, refreshToken, err := GenerateToken(account.ID, ip, privateKey)
	if loginAudit.Abnormal(account.ID, realip) {
		wl_http.RespondError(w, "token error")
		return
	}

	token := db.Token{
		Token:     accessToken,
		AccoundID: account.ID,
		IP:        ip,
		LoginAt:   time.Now(),
		ExpireAt:  time.Now().Add(7 * 24 * time.Hour),
	}
	err = token.DBInsert(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}

	SetCookieToken(w, "access_token", accessToken)
	SetCookieToken(w, "refresh_token", refreshToken)

	wl_http.RespondAny(w, wl_http.Response{
		Success: true,
		Data: wl_http.ResponseData{
			List: []string{
				accessToken, account.ID, account.RealName, refreshToken,
			},
		},
	})
}

func handleToken(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	req, err := wl_http.ParseRequest(r, 1024)
	if err != nil {
		wl_http.RespondError(w, "read error")
		return
	}

	var obj struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
	}
	err = json.Unmarshal(req.Data, &obj)
	if err != nil {
		wl_http.RespondError(w, "unmarshal error")
		return
	}

	account_id, ok := codeMap.VerifyChallenge(obj.Code, obj.Verifier)
	if !ok {
		wl_http.RespondError(w, "code error")
		return
	}

	ip := wl_net.GetIPFromRequest(r).String()
	accessToken, refreshToken, err := GenerateToken(account_id, ip, privateKey)
	if err != nil {
		wl_http.RespondError(w, err)
		return
	}

	token := db.Token{
		Token:     accessToken,
		AccoundID: account_id,
		IP:        ip,
		LoginAt:   time.Now(),
		ExpireAt:  time.Now().Add(7 * 24 * time.Hour),
	}
	err = token.DBInsert(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}

	wl_http.RespondAny(w, wl_http.Response{
		Success: true,
		Data: wl_http.ResponseData{
			List: []map[string]any{
				{
					"access_token":  accessToken,
					"refresh_token": refreshToken,
					"max_age":       7 * 24 * time.Hour / time.Second,
				},
			},
		},
	})
}

func handleAuthorize(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	query := r.URL.Query()
	challenge := query.Get("code_challenge")
	redirectUri := query.Get("redirect_uri")
	if challenge == "" {
		wl_http.RespondError(w, "missing code_challenge")
		return
	}
	if redirectUri == "" {
		wl_http.RespondError(w, "missing redirect_uri")
		return
	}

	ai := CheckAuthorization(r)
	if ai.Authorized {
		code := codeMap.NewCode(ai.AccountID, challenge)
		http.Redirect(w, r, fmt.Sprintf("%s?code=%s", redirectUri, code), http.StatusFound)
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
		wl_http.RespondError(w, "unauthorized")
		return
	}

	account := db.Account{ID: ai.AccountID}
	err := account.DBQuery(&cc.DB)
	if err != nil {
		wl_http.RespondError(w, "database error")
		return
	}

	wl_http.RespondAny(w, wl_http.Response{
		Success: true,
		Data: wl_http.ResponseData{
			List: []db.Account{account},
		},
	})
}

func handleIntrospect(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	ai := CheckAuthorization(r)
	if ai.Authorized {
		wl_http.RespondAny(w, map[string]any{
			"active": true,
			"sub":    ai.AccountID,
		})
		return
	}
	wl_http.RespondAny(w, map[string]any{"active": false})

	/*
		token, err := jwt.Parse(ai.AccessToken, func(t *jwt.Token) (any, error) {
			return publicKey, nil
		})
		if err != nil || !token.Valid {
			wl_http.RespondAny(w, map[string]any{"active": false})
			return
		}

		claims := token.Claims.(jwt.RegisteredClaims)
		wl_http.RespondAny(w, map[string]any{
			"active": true,
			"sub":    claims.Subject,
		})
	*/
}

func handleJwks(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	wl_http.RespondAny(w, map[string]any{
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
	tokenString, err := ParseTokenFromRequest(r)
	if err == nil {
		(&db.Token{Token: tokenString}).DBDelete(&cc.DB)
	}

	DeleteCookieToken(w, "access_token")
	DeleteCookieToken(w, "refresh_token")

	wl_http.RespondSuccess(w)
}

func handleUpdate(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
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

/*
func handleGetMenu(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	menuList, err := queryMenuFromDatabase(r)
	if err != nil {
		wl_http.RespondError(w, err)
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

func handleGetAll(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.Method == "GET" {
		list, err := queryAllAccountsFromDatabase()
		if err != nil {
			wl_http.RespondError(w, err)
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
}

func handleCheckLogin(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	token, err := ParseTokenFromRequest(r)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _, err = checkTokenInDatabase(token)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleCheckMenuAccess(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	req, err := wl_http.ParseRequest(r, 1024)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var msg struct {
		AccountID string `json:"account"`
		MenuURL   string `json:"menu_url"`
	}
	err = json.Unmarshal(req.Data, &msg)
	if err != nil {
		fmt.Println(err, req.Data)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	reg := regexp.MustCompile(`/$`)
	msg.MenuURL = reg.ReplaceAllString(msg.MenuURL, "")

	err = checkMenuAccessFromDatabase(msg.AccountID, msg.MenuURL)
	if err != nil {
		fmt.Println(msg.AccountID, msg.MenuURL, err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleCheckAndRefreshToken(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if r.Method == "POST" {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
		if err != nil {
			io.WriteString(w, err.Error())
			return
		}
		_, _, err = checkTokenInDatabase(string(body))
		if err != nil {
			io.WriteString(w, err.Error())
			return
		}
		refreshTokenInDatabase(string(body))
		io.WriteString(w, wl_int.SUCCESS)
	}
}

func handleCheckToken(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	token, err := ParseTokenFromRequest(r)
	if err != nil {
		fmt.Println("check token error: ", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _, err = checkTokenInDatabase(token)
	if err != nil {
		fmt.Println("check token error: ", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	refreshTokenInDatabase(token)
	next(w, r)
}
*/

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	wl_uuid "github.com/wsva/lib_go/uuid"
)

type Code struct {
	Scope     string
	ClientID  string
	AccountID string
	Challenge string
	Code      string
	ExpireAt  time.Time
}

type CodeMap struct {
	Map map[string]*Code
}

func (c *CodeMap) NewCode(scope, client_id, account_id, challenge string) string {
	if c.Map == nil {
		c.Map = make(map[string]*Code)
	}
	codeObj := &Code{
		ClientID:  client_id,
		AccountID: account_id,
		Challenge: challenge,
		Code:      wl_uuid.New(),
		ExpireAt:  time.Now().Add(3 * time.Minute),
	}
	c.Map[codeObj.Code] = codeObj
	return codeObj.Code
}

func (c *CodeMap) VerifyChallenge(code, verifier string) (*Code, bool) {
	if c.Map == nil {
		c.Map = make(map[string]*Code)
	}
	codeObj, ok := c.Map[code]
	if !ok {
		return nil, false
	}

	defer delete(c.Map, code)

	if codeObj.ExpireAt.Before(time.Now()) {
		return nil, false
	}

	s256 := sha256.Sum256([]byte(verifier))
	// trim padding, but why?
	challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
	if challenge == strings.TrimRight(codeObj.Challenge, "=") {
		return codeObj, true
	}
	return nil, false
}

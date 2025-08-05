package main

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	wl_uuid "github.com/wsva/lib_go/uuid"
)

type Code struct {
	Code      string
	Challenge string
	ExpireAt  time.Time

	AccountID string
}

type CodeMap struct {
	Map map[string]*Code
}

func (c *CodeMap) NewCode(account_id, challenge string) string {
	if c.Map == nil {
		c.Map = make(map[string]*Code)
	}
	codeObj := &Code{
		Code:      wl_uuid.New(),
		Challenge: challenge,
		ExpireAt:  time.Now().Add(3 * time.Minute),
		AccountID: account_id,
	}
	c.Map[codeObj.Code] = codeObj
	return codeObj.Code
}

func (c *CodeMap) VerifyChallenge(code, verifier string) (string, bool) {
	if c.Map == nil {
		c.Map = make(map[string]*Code)
	}
	codeObj, ok := c.Map[code]
	if !ok {
		return "", false
	}

	defer delete(c.Map, code)

	if codeObj.ExpireAt.Before(time.Now()) {
		return "", false
	}

	s256 := sha256.Sum256([]byte(verifier))
	// trim padding, but why?
	challenge := strings.TrimRight(base64.URLEncoding.EncodeToString(s256[:]), "=")
	if challenge == strings.TrimRight(codeObj.Challenge, "=") {
		return codeObj.AccountID, true
	}
	return "", false
}

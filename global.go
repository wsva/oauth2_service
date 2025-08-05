package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"

	wl_fs "github.com/wsva/lib_go/fs"
	wl_http "github.com/wsva/lib_go/http"
	wl_int "github.com/wsva/lib_go_integration"
)

const (
	AESKey = "key"
	AESIV  = "iv"
)

type MainConfig struct {
	ListenList []wl_http.ListenInfo `json:"ListenList"`
}

var (
	Basepath       = ""
	MainConfigFile = path.Join(wl_int.DirConfig, "auth_service_config.json")
	CACrtFile      = path.Join(wl_int.DirPKI, wl_int.CACrtFile)
	ServerCrtFile  = path.Join(wl_int.DirPKI, wl_int.ServerCrtFile)
	ServerKeyFile  = path.Join(wl_int.DirPKI, wl_int.ServerKeyFile)
	Ed25519KeyFile = path.Join("key", "ed25519.key")
	Ed25519PubFile = path.Join("key", "ed25519.pub")
)

var mainConfig MainConfig
var cc *wl_int.CommonConfig

var loginAudit *LoginAudit

var (
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
)

var codeMap *CodeMap

func initGlobals() error {
	basepath, err := wl_fs.GetExecutableFullpath()
	if err != nil {
		return err
	}
	Basepath = basepath
	MainConfigFile = path.Join(basepath, MainConfigFile)

	ServerCrtFile = path.Join(basepath, ServerCrtFile)
	ServerKeyFile = path.Join(basepath, ServerKeyFile)

	contentBytes, err := os.ReadFile(MainConfigFile)
	if err != nil {
		return err
	}
	err = json.Unmarshal(contentBytes, &mainConfig)
	if err != nil {
		return err
	}
	cc, err = wl_int.LoadCommonConfig(basepath, AESKey, AESIV)
	if err != nil {
		return err
	}

	loginAudit = &LoginAudit{
		AccountMap: make(map[string]map[int64]int),
		IPMap:      make(map[string]map[int64]int),
	}

	privateKey, err = LoadPrivateKey(path.Join(Basepath, Ed25519KeyFile))
	if err != nil {
		return err
	}
	publicKey, err = LoadPublicKey(path.Join(Basepath, Ed25519PubFile))
	if err != nil {
		return err
	}

	codeMap = &CodeMap{
		Map: make(map[string]*Code),
	}

	return nil
}

func LoadPrivateKey(filePath string) (ed25519.PrivateKey, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v does not exist", filePath)
	}

	block, _ := pem.Decode(contentBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if pkey, ok := parsedKey.(ed25519.PrivateKey); ok {
		return pkey, nil
	}
	return nil, errors.New("invalid key")
}

func LoadPublicKey(filePath string) (ed25519.PublicKey, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v does not exist", filePath)
	}

	block, _ := pem.Decode(contentBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if pkey, ok := parsedKey.(ed25519.PublicKey); ok {
		return pkey, nil
	}
	return nil, errors.New("invalid key")
}

package main

import (
	"crypto/rsa"
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
	RSAKeyFile     = path.Join("key", "rsa.key")
	RSAPubFile     = path.Join("key", "rsa.pub")
)

var mainConfig MainConfig
var cc *wl_int.CommonConfig

var loginAudit *LoginAudit

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
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

	privateKey, err = LoadPrivateKey(path.Join(Basepath, RSAKeyFile))
	if err != nil {
		return err
	}
	publicKey, err = LoadPublicKey(path.Join(Basepath, RSAPubFile))
	if err != nil {
		return err
	}

	codeMap = &CodeMap{
		Map: make(map[string]*Code),
	}

	return nil
}

func LoadPrivateKey(filePath string) (*rsa.PrivateKey, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v does not exist", filePath)
	}

	block, _ := pem.Decode(contentBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	if pkey, ok := parsedKey.(*rsa.PrivateKey); ok {
		return pkey, nil
	}
	return nil, errors.New("invalid key")
}

func LoadPublicKey(filePath string) (*rsa.PublicKey, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v does not exist", filePath)
	}

	block, _ := pem.Decode(contentBytes)
	if block == nil {
		return nil, errors.New("invalid key")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			if parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				return nil, err
			}
		}
	}

	if pkey, ok := parsedKey.(*rsa.PublicKey); ok {
		return pkey, nil
	}
	return nil, errors.New("invalid key")
}

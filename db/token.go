package db

import (
	"database/sql"
	"errors"
	"fmt"

	wl_db "github.com/wsva/lib_go_db"
)

type Token struct {
	AccessToken  string `json:"AccessToken,omitempty"`
	RefreshToken string `json:"RefreshToken,omitempty"`
	ClientID     string `json:"ClientID,omitempty"`
	AccountID    string `json:"AccountID,omitempty"`
	IP           string `json:"IP,omitempty"`
}

func (t *Token) DBInsert(db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypePostgreSQL:
		query := "INSERT INTO sys_token VALUES ($1, $2, $3, $4, $5)"
		_, err := db.Exec(query, t.AccessToken, t.RefreshToken, t.ClientID, t.AccountID, t.IP)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

func (t *Token) DBDelete(db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeMySQL, wl_db.DBTypeOracle, wl_db.DBTypePostgreSQL:
		query := "delete from sys_token where access_token=$1"
		_, err := db.Exec(query, t.AccessToken)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

// return token, realname, error
func (t *Token) DBQuery(db *wl_db.DB) (*Token, string, error) {
	var row *sql.Row
	var err error
	switch db.Type {
	case wl_db.DBTypeMySQL, wl_db.DBTypeOracle, wl_db.DBTypePostgreSQL:
		query := "select t.refresh_token, t.client_id, t.account_id, t.ip, a.realname " +
			"from sys_token t, sys_account a " +
			"where t.account_id=a.account_id and t.access_token=$1"
		row, err = db.QueryRow(query, t.AccessToken)
	default:
		return nil, "", fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return nil, "", err
	}
	var f1, f2, f3, f4, f5 sql.NullString
	err = row.Scan(&f1, &f2, &f3, &f4, &f5)
	if err != nil {
		return nil, "", errors.New("token revoked")
	}
	t.RefreshToken = f1.String
	t.ClientID = f2.String
	t.AccountID = f3.String
	t.IP = f4.String
	return t, f5.String, nil
}

package db

import (
	"database/sql"
	"errors"
	"fmt"

	wl_db "github.com/wsva/lib_go_db"
	"golang.org/x/crypto/bcrypt"
)

type Account struct {
	ID          string `json:"ID,omitempty"`
	Username    string `json:"Username,omitempty"`
	RealName    string `json:"RealName,omitempty"`
	PhoneNumber string `json:"PhoneNumber,omitempty"`
	Passwd      string `json:"Passwd,omitempty"`
	MenuRole    string `json:"MenuRole,omitempty"`
	Valid       string `json:"Valid,omitempty"`
}

func (a *Account) DBInsert(db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		query := "insert into sys_account values ($1, $2, $3, $4, $5, $6, $7)"
		_, err := db.Exec(query, a.ID, a.Username, a.RealName, a.PhoneNumber, a.Passwd, "guest", a.Valid)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

// will set ID, RealName
func (a *Account) Verify(db *wl_db.DB) error {
	var row *sql.Row
	var err error
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		query := "select account_id, realname, passwd from sys_account " +
			"where account_id=$1 and valid='Y'"
		row, err = db.QueryRow(query, a.ID)
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return err
	}
	var f1, f2, f3 sql.NullString
	err = row.Scan(&f1, &f2, &f3)
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword([]byte(f3.String), []byte(a.Passwd))
	if err != nil {
		return errors.New("verify password failed")
	}
	a.ID = f1.String
	a.RealName = f2.String
	return nil
}

// will set Username, RealName, PhoneNumber
func (a *Account) DBQuery(db *wl_db.DB) error {
	var row *sql.Row
	var err error
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		query := "select a.username, a.realname, a.phonenumber " +
			"from sys_account a " +
			"where a.account_id=$1 and a.valid='Y'"
		row, err = db.QueryRow(query, a.ID)
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return err
	}
	var f1, f2, f3 sql.NullString
	err = row.Scan(&f1, &f2, &f3)
	if err != nil {
		return err
	}
	a.Username = f1.String
	a.RealName = f2.String
	a.PhoneNumber = f3.String
	return nil
}

func (a *Account) DBUpdate(db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		query := "update sys_account set " +
			"username=$1, realname=$2, phonenumber=$3, valid=$4 " +
			"where account_id=$5"
		_, err := db.Exec(query, a.Username, a.RealName, a.PhoneNumber, a.Valid, a.ID)
		if err != nil {
			return err
		}
		if a.Passwd != "" {
			query := "update sys_account set passwd=$1 where account_id=$2"
			_, err := db.Exec(query, a.Passwd, a.ID)
			return err
		}
		return nil
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

func QueryAccountAll(db *wl_db.DB) ([]Account, error) {
	var rows *sql.Rows
	var err error
	var result []Account
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		query := fmt.Sprint("select a.account_id, a.username, " +
			"a.realname, a.phonenumber, a.valid " +
			"from sys_account a")
		rows, err = db.Query(query)
	default:
		return nil, fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f1, f2, f3, f4, f5 sql.NullString
		err = rows.Scan(&f1, &f2, &f3, &f4, &f5)
		if err != nil {
			return nil, err
		}
		res := Account{
			ID:          f1.String,
			Username:    f2.String,
			RealName:    f3.String,
			PhoneNumber: f4.String,
			Valid:       f5.String,
		}
		result = append(result, res)
	}
	rows.Close()
	return result, nil
}

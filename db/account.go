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
		sqltext := fmt.Sprintf("insert into sys_account values "+
			"('%v', '%v', '%v', '%v', '%v', '%v', '%v')",
			sqlsafe(a.ID), sqlsafe(a.Username), sqlsafe(a.RealName), sqlsafe(a.PhoneNumber),
			sqlsafe(a.Passwd), "guest", sqlsafe(a.Valid))
		_, err := db.Exec(sqltext)
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
		sqltext := fmt.Sprintf("select account_id, realname, passwd from sys_account "+
			"where account_id='%v' and valid='Y'",
			sqlsafe(a.ID))
		fmt.Println(sqltext)
		row, err = db.QueryRow(sqltext)
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
		sqltext := fmt.Sprintf("select a.username, a.realname, a.phonenumber "+
			"from sys_account a "+
			"where a.account_id='%v' and a.valid='Y'",
			sqlsafe(a.ID))
		row, err = db.QueryRow(sqltext)
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
		sqltext := fmt.Sprintf("update sys_account set "+
			"username='%v', realname='%v', phonenumber='%v', valid='%v' "+
			"where account_id='%v'",
			sqlsafe(a.Username), sqlsafe(a.RealName),
			sqlsafe(a.PhoneNumber), sqlsafe(a.Valid), sqlsafe(a.ID))
		_, err := db.Exec(sqltext)
		if err != nil {
			return err
		}
		if a.Passwd != "" {
			sqltext := fmt.Sprintf("update sys_account set "+
				"Passwd='%v' where Account_ID='%v'",
				sqlsafe(a.Passwd), sqlsafe(a.ID))
			_, err := db.Exec(sqltext)
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
		sqltext := fmt.Sprint("select a.account_id, a.username, " +
			"a.realname, a.phonenumber, a.valid " +
			"from sys_account a")
		rows, err = db.Query(sqltext)
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

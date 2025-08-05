package db

import (
	"database/sql"
	"fmt"
	"time"

	wl_db "github.com/wsva/lib_go_db"
)

type Token struct {
	Token     string    `json:"Token,omitempty"`
	AccoundID string    `json:"AccoundID,omitempty"`
	IP        string    `json:"IP,omitempty"`
	LoginAt   time.Time `json:"LoginAt,omitempty"`
	ExpireAt  time.Time `json:"ExpireAt,omitempty"`
}

func (t *Token) DBInsert(db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeOracle:
		sqltext := fmt.Sprintf("insert into was.sys_Token "+
			"values ('%v', '%v', '%v', sysdate, sysdate+10/1440)",
			sqlsafe(t.Token), sqlsafe(t.AccoundID), sqlsafe(t.IP))
		_, err := db.Exec(sqltext)
		return err
	case wl_db.DBTypePostgreSQL:
		query := "INSERT INTO sys_token (token, account_id, ip, login_at, expire_at) VALUES ($1, $2, $3, $4, $5)"
		_, err := db.ExecWithArgs(query, t.Token, t.AccoundID, t.IP, t.LoginAt, t.ExpireAt)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

func (t *Token) DBDelete(db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeMySQL, wl_db.DBTypeOracle, wl_db.DBTypePostgreSQL:
		sqltext := fmt.Sprintf("delete from sys_token where token='%v'",
			sqlsafe(t.Token))
		_, err := db.Exec(sqltext)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

// return account_id, realname
func DBCheckToken(token, ip string, db *wl_db.DB) (string, string, error) {
	var row *sql.Row
	var err error
	switch db.Type {
	case wl_db.DBTypeMySQL, wl_db.DBTypeOracle:
		sqltext := fmt.Sprintf("select t.Account_ID, a.RealName "+
			"from was.sys_Token t, was.sys_Account a "+
			"where t.Account_ID=a.Account_ID and "+
			"t.Token='%v' and t.Expire_At>sysdate",
			sqlsafe(token))
		row, err = db.QueryRow(sqltext)
	case wl_db.DBTypePostgreSQL:
		sqltext := fmt.Sprintf("select t.account_id, a.realname "+
			"from sys_token t, sys_account a "+
			"where t.account_id=a.account_id "+
			"and t.token='%v' and t.ip='%v' and t.expire_at>NOW()",
			sqlsafe(token), sqlsafe(ip))
		row, err = db.QueryRow(sqltext)
	default:
		return "", "", fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return "", "", err
	}
	var f1, f2 sql.NullString
	err = row.Scan(&f1, &f2)
	if err != nil {
		return "", "", err
	}
	return f1.String, f2.String, nil
}

func refreshTokenInDatabase(token string, db *wl_db.DB) error {
	switch db.Type {
	case wl_db.DBTypeMySQL:
		sqltext := fmt.Sprintf("update Integration.Token "+
			"set Expire_At=%v "+
			"where Token='%v';",
			time.Now().Add(10*time.Minute).Unix(), sqlsafe(token))
		_, err := db.Exec(sqltext)
		return err
	case wl_db.DBTypeOracle:
		sqltext := fmt.Sprintf("update was.sys_Token "+
			"set Expire_At=sysdate+10/1440 where Token='%v'",
			sqlsafe(token))
		_, err := db.Exec(sqltext)
		return err
	case wl_db.DBTypePostgreSQL:
		sqltext := fmt.Sprintf("update sys_Token "+
			"set Expire_At=NOW() + INTERVAL '10 minutes' where Token='%v'",
			sqlsafe(token))
		_, err := db.Exec(sqltext)
		return err
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
}

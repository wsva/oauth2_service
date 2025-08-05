package db

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	wl_db "github.com/wsva/lib_go_db"

	wl_int "github.com/wsva/lib_go_integration"
)

type Menu struct {
	Name string `json:"Name,omitempty"`
	URL  string `json:"URL,omitempty"`
}

type MenuGroup struct {
	Name     string `json:"Name,omitempty"`
	MenuList []Menu `json:"MenuList,omitempty"`
}

func NewMenuGroup(groupName string) *MenuGroup {
	return &MenuGroup{
		Name: groupName,
	}
}

func (m *MenuGroup) Add(menuName, menuURL string) {
	m.MenuList = append(m.MenuList, Menu{
		Name: menuName,
		URL:  menuURL,
	})
}

func checkMenuAccessFromDatabase(account, menuUrl string, db *wl_db.DB) error {
	var rows *sql.Rows
	var err error
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		sqltext := fmt.Sprintf("select b.menu_url "+
			"from sys_account a, sys_menu_role b "+
			"where a.menu_role=b.menu_role and a.account_id='%v' "+
			"and b.menu_url='%v'",
			sqlsafe(account), sqlsafe(menuUrl))
		rows, err = db.Query(sqltext)
	default:
		return fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return err
	}
	rowsCount := 0
	for rows.Next() {
		rowsCount++
	}
	rows.Close()
	if rowsCount > 0 {
		return nil
	}
	return errors.New("no data found")
}

func queryMenuFromDatabase(r *http.Request, db *wl_db.DB) ([]MenuGroup, error) {
	token, err := wl_int.ParseTokenFromRequest(r)
	if err != nil {
		return nil, err
	}

	var rows *sql.Rows
	var result []MenuGroup
	switch db.Type {
	case wl_db.DBTypeOracle, wl_db.DBTypeMySQL, wl_db.DBTypePostgreSQL:
		sqltext := fmt.Sprintf(`select
		m.subsystem, m.menu_name, m.menu_url 
	from
		sys_account a,
		sys_menu m,
		sys_menu_role mr, 
		sys_token t 
	where
		a.menu_role = mr.menu_role 
		and m.menu_url = mr.menu_url 
		and m.directory = 'N' 
		and m.show_menu = 'Y'
		and a.account_id = t.account_id 
		and t.token = '%v' 
	order by m.rank`, sqlsafe(token))
		rows, err = db.Query(sqltext)
	default:
		return nil, fmt.Errorf("invalid DBType %v", db.Type)
	}
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f1, f2, f3 sql.NullString
		err = rows.Scan(&f1, &f2, &f3)
		if err != nil {
			return nil, err
		}
		if len(result) == 0 {
			result = append(result, *NewMenuGroup(f1.String))
		}
		if result[len(result)-1].Name != f1.String {
			result = append(result, *NewMenuGroup(f1.String))
		}
		result[len(result)-1].Add(f2.String, f3.String)
	}
	rows.Close()
	return result, nil
}

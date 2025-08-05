package db

import (
	"strings"
)

func sqlsafe(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

package utils

import (
	"database/sql"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func InitDb() *sql.DB {
	conn, err := sql.Open("pgx", os.Getenv("DB_DSN"))
	if err != nil {
		panic(err)
	}

	err = conn.Ping()
	if err != nil {
		panic(err)
	}

	return conn
}

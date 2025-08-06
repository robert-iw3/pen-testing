package database

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

type Database struct {
	conn *sql.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	createTokenHistory := `
    CREATE TABLE IF NOT EXISTS token_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        access_token TEXT,
        refresh_token TEXT,
        expiry DATETIME,
        token_type TEXT,
        user_ip TEXT,
        user_agent TEXT,
        timestamp DATETIME
    );`
	_, err = db.Exec(createTokenHistory)
	if err != nil {
		return nil, err
	}

	createCurrentTokens := `
    CREATE TABLE IF NOT EXISTS current_tokens (
        email TEXT PRIMARY KEY,
        access_token TEXT,
        refresh_token TEXT,
        expiry DATETIME,
        token_type TEXT,
        user_ip TEXT,
        user_agent TEXT,
        capture_date DATETIME,
        last_updated DATETIME
    );`
	_, err = db.Exec(createCurrentTokens)
	if err != nil {
		return nil, err
	}

	log.Println("Database setup complete.")
	return &Database{conn: db}, nil
}

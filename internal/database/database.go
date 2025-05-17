package database

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v4/stdlib" // PostgreSQL 드라이버
	"github.com/rs/zerolog/log"
)

type Database struct {
	DB     *sql.DB
	DbType string
	uri    string
}

func NewDatabase() *Database {
	return &Database{}
}

func (d *Database) Connect(dbType, uri string) error {
	log.Info().Str("db_type", dbType).Str("uri", uri).Msg("데이터베이스에 연결합니다")
	d.DbType, d.uri = dbType, uri
	db, err := sql.Open(dbType, uri)
	if err != nil {
		return fmt.Errorf("데이터베이스 연결 실패: %w", err)
	}
	d.DB = db
	return nil
}

func (d *Database) Close() error {
	if d.DB != nil {
		return d.DB.Close()
	}
	return nil
}

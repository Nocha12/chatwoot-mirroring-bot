package database

import (
	"context"
	"embed"
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
)

var (
	//go:embed schema/*.sql
	rawUpgrades embed.FS

	upgradeTable dbutil.UpgradeTable
)

func init() {
	upgradeTable.RegisterFS(rawUpgrades)
}

func (d *Database) Init(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("데이터베이스를 초기화합니다")
	_, err := d.DB.ExecContext(ctx, `
        CREATE TABLE IF NOT EXISTS chatwoot_version (
            version INTEGER PRIMARY KEY
        )`)
	if err != nil {
		log.Error().Err(err).Msg("버전 테이블 생성 실패")
		return fmt.Errorf("버전 테이블 생성 실패: %w", err)
	}
	return nil
}

func (d *Database) Upgrade(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("데이터베이스 스키마를 업그레이드합니다")

	entries, err := rawUpgrades.ReadDir("schema")
	if err != nil {
		log.Error().Err(err).Msg("스키마 디렉터리 읽기 실패")
		return fmt.Errorf("스키마 디렉터리 읽기 실패: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			log.Info().Str("file", e.Name()).Msg("스키마 파일 실행")
			content, err := rawUpgrades.ReadFile(filepath.Join("schema", e.Name()))
			if err != nil {
				log.Error().Err(err).Str("file", e.Name()).Msg("스키마 파일 읽기 실패")
				return fmt.Errorf("스키마 파일 읽기 실패 (%s): %w", e.Name(), err)
			}
			if _, err := d.DB.ExecContext(ctx, string(content)); err != nil {
				log.Error().Err(err).Str("file", e.Name()).Msg("스키마 파일 실행 실패")
				return fmt.Errorf("스키마 파일 실행 실패 (%s): %w", e.Name(), err)
			}
		}
	}
	return nil
}

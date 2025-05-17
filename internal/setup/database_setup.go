// database_setup.go
package setup

import (
	"context"
	"fmt"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/rs/zerolog"
)

// SetupDatabase는 DbConfiguration과 로거를 받아 데이터베이스 연결 및 마이그레이션을 수행합니다.
func SetupDatabase(dbCfg *config.DbConfiguration, log zerolog.Logger) (*database.Database, error) {
	db := database.NewDatabase()
	if err := db.Connect(dbCfg.Database.Type, dbCfg.Database.URI); err != nil {
		return nil, fmt.Errorf("데이터베이스 연결 실패: %w", err)
	}
	ctx := log.WithContext(context.Background())
	if err := db.Upgrade(ctx); err != nil {
		return nil, fmt.Errorf("데이터베이스 마이그레이션 실패: %w", err)
	}
	log.Info().Msg("데이터베이스 연결 및 마이그레이션 완료")
	return db, nil
}

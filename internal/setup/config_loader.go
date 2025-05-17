// config_loader.go
package setup

import (
	"fmt"
	"os"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
)

// LoadConfigFiles는 configPath에 따라 설정을 로드합니다.
// 설정 파일에서 데이터베이스 설정을 추출하여 DbConfiguration 구조체로 변환합니다.
func LoadConfigFiles(configPath string) (*config.Configuration, *config.DbConfiguration, error) {
	if configPath == "" {
		// 설정 파일이 없는 경우에 대한 처리는 유지
		dbConfigPath := os.Getenv("DB_CONFIG_PATH")
		if dbConfigPath == "" {
			dbConfigPath = "./db_config.yaml"
		}

		dbCfg, err := config.LoadDbConfig(dbConfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("DB 설정 파일 로드 실패: %w", err)
		}
		return nil, dbCfg, nil
	}

	// 설정 파일에서 일반 설정 로드
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("설정 파일 로드 실패: %w", err)
	}

	// 설정 파일에서 데이터베이스 설정 추출
	dbCfg := &config.DbConfiguration{
		Database: cfg.Database, // 설정에서 데이터베이스 정보 복사
	}

	return cfg, dbCfg, nil
}

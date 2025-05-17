// utils/config.go - 설정 관련 유틸리티 함수
package utils

import (
	"fmt"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
)

// AppConfig는 애플리케이션 설정을 관리합니다.
type AppConfig struct {
	ConfigPath    string
	MasterKeyPath string
	DbConfig      *config.DbConfiguration
	MasterKey     []byte
	DB            *database.Database
}

// InitConfig는 설정을 초기화합니다.
func InitConfig(configPath, masterKeyPath string) (*AppConfig, error) {
	appCfg := &AppConfig{
		ConfigPath:    configPath,
		MasterKeyPath: masterKeyPath,
	}

	// DB 설정 로드
	dbCfg, err := config.LoadDbConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 로드 실패: %w", err)
	}
	appCfg.DbConfig = dbCfg

	// 마스터 키 로드
	masterKey, err := config.LoadMasterEncryptionKey(masterKeyPath)
	if err != nil {
		return nil, fmt.Errorf("마스터 키 로드 실패: %w", err)
	}
	appCfg.MasterKey = masterKey

	// DB 연결
	db := database.NewDatabase()
	
	// 데이터베이스 타입 확인 (기본값은 PostgreSQL)
	dbType := "postgres"
	if dbCfg.Database.Type != "" {
		dbType = dbCfg.Database.Type
	}
	
	// PostgreSQL 호환성을 위해 postgresql을 postgres로 변경
	if dbType == "postgresql" {
		dbType = "postgres"
	}
	
	// 데이터베이스 연결
	err = db.Connect(dbType, dbCfg.Database.URI)
	if err != nil {
		return nil, fmt.Errorf("데이터베이스 연결 실패: %w", err)
	}
	
	appCfg.DB = db

	return appCfg, nil
}

// Close는 리소스를 정리합니다.
func (c *AppConfig) Close() error {
	if c.DB != nil {
		if err := c.DB.Close(); err != nil {
			return fmt.Errorf("failed to close database: %w", err)
		}
	}
	return nil
}

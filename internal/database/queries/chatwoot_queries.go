// chatwoot_queries.go - Chatwoot 계정 설정 조회 관련 함수
package queries

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
)

// GetChatwootConfigs는 데이터베이스에서 Chatwoot 계정 설정 목록을 조회합니다.
func GetChatwootConfigs(ctx context.Context, db *database.Database) ([]ChatwootAccountConfig, error) {
	query := `
		SELECT id, config_name, base_url, chatwoot_native_account_id, 
		       inbox_id, encrypted_access_token, encryption_nonce, is_enabled
		FROM bot_chatwoot_configs
		WHERE is_enabled = true
		ORDER BY id ASC
	`

	rows, err := db.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("chatwoot 계정 설정 조회 실패: %w", err)
	}
	defer func() { 
		err := rows.Close()
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("rows.Close 에러")
		}
	}()

	var configs []ChatwootAccountConfig
	for rows.Next() {
		var config ChatwootAccountConfig
		if err := rows.Scan(
			&config.ID,
			&config.ConfigName,
			&config.BaseURL,
			&config.AccountID,
			&config.InboxID,
			&config.EncryptedAccessToken,
			&config.EncryptionNonce,
			&config.IsEnabled,
		); err != nil {
			return nil, fmt.Errorf("chatwoot 계정 설정 스캔 실패: %w", err)
		}
		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("chatwoot 계정 설정 결과 처리 중 오류: %w", err)
	}

	if len(configs) == 0 {
		return nil, errors.New("활성화된 Chatwoot 계정 설정이 없습니다")
	}

	return configs, nil
}

// GetChatwootConfigByID는 ID로 Chatwoot 계정 설정을 조회합니다.
func GetChatwootConfigByID(ctx context.Context, db *database.Database, id int) (*ChatwootAccountConfig, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_chatwoot_config").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 계정 설정 조회 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return nil, errors.New("유효하지 않은 설정 ID")
	}

	// 설정 조회
	query := `
		SELECT id, config_name, base_url, chatwoot_native_account_id, 
		       inbox_id, encrypted_access_token, encryption_nonce, is_enabled
		FROM bot_chatwoot_configs
		WHERE id = $1
	`
	var config ChatwootAccountConfig
	err := db.DB.QueryRowContext(ctx, query, id).Scan(
		&config.ID,
		&config.ConfigName,
		&config.BaseURL,
		&config.AccountID,
		&config.InboxID,
		&config.EncryptedAccessToken,
		&config.EncryptionNonce,
		&config.IsEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("chatwoot 설정 조회 실패: %w", err)
	}

	log.Debug().Msg("Chatwoot 계정 설정 조회 완료")
	return &config, nil
}

// GetChatwootConfigByName은 이름으로 Chatwoot 계정 설정을 조회합니다.
func GetChatwootConfigByName(ctx context.Context, db *database.Database, configName string) (*ChatwootAccountConfig, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_chatwoot_config_by_name").
		Str("config_name", configName).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("이름으로 Chatwoot 계정 설정 조회 시작")

	// 입력 유효성 검사
	if configName == "" {
		return nil, errors.New("설정 이름은 필수 입력 항목입니다")
	}

	// 설정 조회
	query := `
		SELECT id, config_name, base_url, chatwoot_native_account_id, 
		       inbox_id, encrypted_access_token, encryption_nonce, is_enabled
		FROM bot_chatwoot_configs
		WHERE config_name = $1
	`
	var config ChatwootAccountConfig
	err := db.DB.QueryRowContext(ctx, query, configName).Scan(
		&config.ID,
		&config.ConfigName,
		&config.BaseURL,
		&config.AccountID,
		&config.InboxID,
		&config.EncryptedAccessToken,
		&config.EncryptionNonce,
		&config.IsEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("이름으로 Chatwoot 설정 조회 실패: %w", err)
	}

	log.Debug().Msg("이름으로 Chatwoot 계정 설정 조회 완료")
	return &config, nil
}

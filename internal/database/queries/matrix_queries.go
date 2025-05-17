// matrix_queries.go - Matrix ID 설정 조회 관련 함수
package queries

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
)

// GetMatrixIdentities는 데이터베이스에서 Matrix 계정 설정 목록을 조회합니다.
func GetMatrixIdentities(ctx context.Context, db *database.Database) ([]MatrixIdentityConfig, error) {
	query := `
		SELECT id, config_name, homeserver_url, user_id, 
		       encrypted_password, password_encryption_nonce,
		       encrypted_access_token, access_token_encryption_nonce,
		       device_id, is_enabled
		FROM bot_matrix_identities
		WHERE is_enabled = true
		ORDER BY id ASC
	`

	rows, err := db.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("matrix 계정 설정 조회 실패: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("rows 닫기 실패")
		}
	}()

	var configs []MatrixIdentityConfig
	for rows.Next() {
		var config MatrixIdentityConfig
		if err := rows.Scan(
			&config.ID,
			&config.ConfigName,
			&config.HomeserverURL,
			&config.UserID,
			&config.EncryptedPassword,
			&config.PasswordNonce,
			&config.EncryptedAccessToken,
			&config.AccessTokenNonce,
			&config.DeviceID,
			&config.IsEnabled,
		); err != nil {
			return nil, fmt.Errorf("matrix 계정 설정 스캔 실패: %w", err)
		}
		configs = append(configs, config)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("matrix 계정 설정 결과 처리 중 오류: %w", err)
	}

	if len(configs) == 0 {
		return nil, errors.New("활성화된 Matrix 계정 설정이 없습니다")
	}

	return configs, nil
}

// GetMatrixIdentityByID는 ID로 Matrix ID 설정을 조회합니다.
func GetMatrixIdentityByID(ctx context.Context, db *database.Database, id int) (*MatrixIdentityConfig, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_matrix_identity").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix ID 설정 조회 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return nil, errors.New("유효하지 않은 설정 ID")
	}

	// 설정 조회
	query := `
		SELECT id, config_name, homeserver_url, user_id, 
		       encrypted_password, password_encryption_nonce,
		       encrypted_access_token, access_token_encryption_nonce,
		       device_id, is_enabled
		FROM bot_matrix_identities
		WHERE id = $1
	`
	var config MatrixIdentityConfig
	err := db.DB.QueryRowContext(ctx, query, id).Scan(
		&config.ID,
		&config.ConfigName,
		&config.HomeserverURL,
		&config.UserID,
		&config.EncryptedPassword,
		&config.PasswordNonce,
		&config.EncryptedAccessToken,
		&config.AccessTokenNonce,
		&config.DeviceID,
		&config.IsEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("matrix ID 설정 조회 실패: %w", err)
	}

	log.Debug().Msg("matrix ID 설정 조회 완료")
	return &config, nil
}

// GetMatrixIdentityByName은 이름으로 Matrix ID 설정을 조회합니다.
func GetMatrixIdentityByName(ctx context.Context, db *database.Database, configName string) (*MatrixIdentityConfig, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_matrix_identity_by_name").
		Str("config_name", configName).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("이름으로 Matrix ID 설정 조회 시작")

	// 입력 유효성 검사
	if configName == "" {
		return nil, errors.New("설정 이름은 필수 입력 항목입니다")
	}

	// 설정 조회
	query := `
		SELECT id, config_name, homeserver_url, user_id, 
		       encrypted_password, password_encryption_nonce,
		       encrypted_access_token, access_token_encryption_nonce,
		       device_id, is_enabled
		FROM bot_matrix_identities
		WHERE config_name = $1
	`
	var config MatrixIdentityConfig
	err := db.DB.QueryRowContext(ctx, query, configName).Scan(
		&config.ID,
		&config.ConfigName,
		&config.HomeserverURL,
		&config.UserID,
		&config.EncryptedPassword,
		&config.PasswordNonce,
		&config.EncryptedAccessToken,
		&config.AccessTokenNonce,
		&config.DeviceID,
		&config.IsEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("이름으로 Matrix ID 설정 조회 실패: %w", err)
	}

	log.Debug().Msg("이름으로 Matrix ID 설정 조회 완료")
	return &config, nil
}

// GetMatrixIdentityByUserID는 사용자 ID로 Matrix ID 설정을 조회합니다.
func GetMatrixIdentityByUserID(ctx context.Context, db *database.Database, userID id.UserID) (*MatrixIdentityConfig, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_matrix_identity_by_user_id").
		Str("user_id", string(userID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("사용자 ID로 Matrix ID 설정 조회 시작")

	// 입력 유효성 검사
	if userID == "" {
		return nil, errors.New("사용자 ID는 필수 입력 항목입니다")
	}

	// 설정 조회
	query := `
		SELECT id, config_name, homeserver_url, user_id, 
		       encrypted_password, password_encryption_nonce,
		       encrypted_access_token, access_token_encryption_nonce,
		       device_id, is_enabled
		FROM bot_matrix_identities
		WHERE user_id = $1
	`
	var config MatrixIdentityConfig
	err := db.DB.QueryRowContext(ctx, query, userID).Scan(
		&config.ID,
		&config.ConfigName,
		&config.HomeserverURL,
		&config.UserID,
		&config.EncryptedPassword,
		&config.PasswordNonce,
		&config.EncryptedAccessToken,
		&config.AccessTokenNonce,
		&config.DeviceID,
		&config.IsEnabled,
	)
	if err != nil {
		return nil, fmt.Errorf("사용자 ID로 Matrix ID 설정 조회 실패: %w", err)
	}

	log.Debug().Msg("사용자 ID로 Matrix ID 설정 조회 완료")
	return &config, nil
}

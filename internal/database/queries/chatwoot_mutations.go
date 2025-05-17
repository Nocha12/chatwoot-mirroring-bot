// chatwoot_mutations.go - Chatwoot 계정 설정 추가/수정/삭제 관련 함수
package queries

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/crypto"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// CreateChatwootConfig는 새로운 Chatwoot 계정 설정을 데이터베이스에 추가합니다.
// 접근 토큰은 저장 전에 마스터 키로 암호화됩니다.
func CreateChatwootConfig(
	ctx context.Context,
	db *database.Database,
	configName string,
	baseURL string,
	accountID chatwootapi.AccountID,
	inboxID chatwootapi.InboxID,
	accessToken string,
	masterKey []byte,
	isEnabled bool,
	notes string,
) (int, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "create_chatwoot_config").
		Str("config_name", configName).
		Str("base_url", baseURL).
		Int("account_id", int(accountID)).
		Int("inbox_id", int(inboxID)).
		Bool("is_enabled", isEnabled).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("새 Chatwoot 계정 설정 생성 시작")

	// 입력 유효성 검사
	if configName == "" {
		return 0, errors.New("설정 이름은 필수 입력 항목입니다")
	}
	if baseURL == "" {
		return 0, errors.New("chatwoot 기본 URL은 필수 입력 항목입니다")
	}
	if accountID <= 0 {
		return 0, errors.New("유효하지 않은 Chatwoot 계정 ID")
	}
	if inboxID <= 0 {
		return 0, errors.New("유효하지 않은 Chatwoot 인박스 ID")
	}
	if accessToken == "" {
		return 0, errors.New("접근 토큰은 필수 입력 항목입니다")
	}

	// 중복 설정 이름 검사
	checkQuery := "SELECT id FROM bot_chatwoot_configs WHERE config_name = $1 LIMIT 1"
	var existingID int
	err := db.DB.QueryRowContext(ctx, checkQuery, configName).Scan(&existingID)
	if err == nil {
		return 0, fmt.Errorf("이미 동일한 이름의 설정이 존재합니다: %s (ID: %d)", configName, existingID)
	}

	// 접근 토큰 암호화
	encryptedToken, nonce, err := crypto.EncryptData(accessToken, masterKey)
	if err != nil {
		return 0, fmt.Errorf("접근 토큰 암호화 실패: %w", err)
	}

	// 현재 시간
	now := time.Now().UTC()

	// 설정 추가
	insertQuery := `
		INSERT INTO bot_chatwoot_configs (
			config_name, base_url, chatwoot_native_account_id, inbox_id,
			encrypted_access_token, encryption_nonce, is_enabled, notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`

	var id int
	err = db.DB.QueryRowContext(
		ctx, insertQuery, configName, baseURL, accountID, inboxID,
		encryptedToken, nonce, isEnabled, notes, now, now,
	).Scan(&id)

	if err != nil {
		return 0, fmt.Errorf("chatwoot 설정 추가 실패: %w", err)
	}

	log.Info().Int("id", id).Msg("Chatwoot 계정 설정이 성공적으로 생성되었습니다")
	return id, nil
}

// UpdateChatwootConfig는 기존 Chatwoot 계정 설정을 업데이트합니다.
// 접근 토큰이 제공되면 새로 암호화하여 업데이트합니다.
func UpdateChatwootConfig(
	ctx context.Context,
	db *database.Database,
	id int,
	configName string,
	baseURL string,
	accountID chatwootapi.AccountID,
	inboxID chatwootapi.InboxID,
	accessToken string,
	masterKey []byte,
	isEnabled bool,
	notes string,
) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "update_chatwoot_config").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 계정 설정 업데이트 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return errors.New("유효하지 않은 설정 ID")
	}
	if configName == "" {
		return errors.New("설정 이름은 필수 입력 항목입니다")
	}
	if baseURL == "" {
		return errors.New("chatwoot 기본 URL은 필수 입력 항목입니다")
	}
	if accountID <= 0 {
		return errors.New("유효하지 않은 Chatwoot 계정 ID")
	}
	if inboxID <= 0 {
		return errors.New("유효하지 않은 Chatwoot 인박스 ID")
	}

	// 중복 설정 이름 검사 (자기 자신 제외)
	checkQuery := "SELECT id FROM bot_chatwoot_configs WHERE config_name = $1 AND id != $2 LIMIT 1"
	var existingID int
	err := db.DB.QueryRowContext(ctx, checkQuery, configName, id).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("이미 동일한 이름의 설정이 존재합니다: %s (ID: %d)", configName, existingID)
	}

	// 현재 시간
	now := time.Now().UTC()

	// accessToken이 제공된 경우 업데이트, 아니면 기존 값 유지
	if accessToken != "" {
		// 접근 토큰 암호화
		encryptedToken, nonce, err := crypto.EncryptData(accessToken, masterKey)
		if err != nil {
			return fmt.Errorf("접근 토큰 암호화 실패: %w", err)
		}

		// 토큰 포함 업데이트
		updateQuery := `
			UPDATE bot_chatwoot_configs
			SET config_name = $1,
				base_url = $2,
				chatwoot_native_account_id = $3,
				inbox_id = $4,
				encrypted_access_token = $5,
				encryption_nonce = $6,
				is_enabled = $7,
				notes = $8,
				updated_at = $9
			WHERE id = $10
		`
		result, err := db.DB.ExecContext(
			ctx, updateQuery, configName, baseURL, accountID, inboxID,
			encryptedToken, nonce, isEnabled, notes, now, id,
		)
		if err != nil {
			return fmt.Errorf("chatwoot 설정 업데이트 실패: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("ID %d에 해당하는 Chatwoot 설정을 찾을 수 없습니다", id)
		}
	} else {
		// 토큰 제외 업데이트
		updateQuery := `
			UPDATE bot_chatwoot_configs
			SET config_name = $1,
				base_url = $2,
				chatwoot_native_account_id = $3,
				inbox_id = $4,
				is_enabled = $5,
				notes = $6,
				updated_at = $7
			WHERE id = $8
		`
		result, err := db.DB.ExecContext(
			ctx, updateQuery, configName, baseURL, accountID, inboxID,
			isEnabled, notes, now, id,
		)
		if err != nil {
			return fmt.Errorf("chatwoot 설정 업데이트 실패: %w", err)
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
		}
		if rowsAffected == 0 {
			return fmt.Errorf("ID %d에 해당하는 Chatwoot 설정을 찾을 수 없습니다", id)
		}
	}

	log.Info().Msg("Chatwoot 계정 설정이 성공적으로 업데이트되었습니다")
	return nil
}

// DeleteChatwootConfig는 Chatwoot 계정 설정을 데이터베이스에서 삭제합니다.
func DeleteChatwootConfig(ctx context.Context, db *database.Database, id int) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "delete_chatwoot_config").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 계정 설정 삭제 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return errors.New("유효하지 않은 설정 ID")
	}

	// 설정 삭제
	deleteQuery := "DELETE FROM bot_chatwoot_configs WHERE id = $1"
	result, err := db.DB.ExecContext(ctx, deleteQuery, id)
	if err != nil {
		return fmt.Errorf("chatwoot 설정 삭제 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 Chatwoot 설정을 찾을 수 없습니다", id)
	}

	log.Info().Msg("Chatwoot 계정 설정이 성공적으로 삭제되었습니다")
	return nil
}

// DeactivateChatwootConfig는 Chatwoot 계정 설정을 비활성화합니다.
func DeactivateChatwootConfig(ctx context.Context, db *database.Database, id int) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "deactivate_chatwoot_config").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 계정 설정 비활성화 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return errors.New("유효하지 않은 설정 ID")
	}

	// 설정 비활성화
	updateQuery := "UPDATE bot_chatwoot_configs SET is_enabled = false, updated_at = $1 WHERE id = $2"
	now := time.Now().UTC()
	result, err := db.DB.ExecContext(ctx, updateQuery, now, id)
	if err != nil {
		return fmt.Errorf("chatwoot 설정 비활성화 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 Chatwoot 설정을 찾을 수 없습니다", id)
	}

	log.Info().Msg("Chatwoot 계정 설정이 성공적으로 비활성화되었습니다")
	return nil
}

// matrix_mutations.go - Matrix ID 설정 추가/삭제 관련 함수
package queries

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/crypto"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
)

// CreateMatrixIdentity는 새로운 Matrix ID 설정을 데이터베이스에 추가합니다.
// 비밀번호 또는 접근 토큰 중 하나는 필수이며, 저장 전에 마스터 키로 암호화됩니다.
func CreateMatrixIdentity(
	ctx context.Context,
	db *database.Database,
	configName string,
	homeserverURL string,
	userID id.UserID,
	password string,
	accessToken string,
	deviceID string,
	masterKey []byte,
	isEnabled bool,
	notes string,
) (int, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "create_matrix_identity").
		Str("config_name", configName).
		Str("homeserver_url", homeserverURL).
		Str("user_id", string(userID)).
		Bool("has_password", password != "").
		Bool("has_access_token", accessToken != "").
		Bool("is_enabled", isEnabled).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("새 Matrix ID 설정 생성 시작")

	// 입력 유효성 검사
	if configName == "" {
		return 0, errors.New("설정 이름은 필수 입력 항목입니다")
	}
	if homeserverURL == "" {
		return 0, errors.New("matrix 홈서버 URL은 필수 입력 항목입니다")
	}
	if userID == "" {
		return 0, errors.New("matrix 사용자 ID는 필수 입력 항목입니다")
	}
	if password == "" && accessToken == "" {
		return 0, errors.New("비밀번호 또는 접근 토큰 중 하나는 필수 입력 항목입니다")
	}

	// 중복 설정 이름 검사
	checkNameQuery := "SELECT id FROM bot_matrix_identities WHERE config_name = $1 LIMIT 1"
	var existingID int
	err := db.DB.QueryRowContext(ctx, checkNameQuery, configName).Scan(&existingID)
	if err == nil {
		return 0, fmt.Errorf("이미 동일한 이름의 설정이 존재합니다: %s (ID: %d)", configName, existingID)
	}

	// 중복 사용자 ID 검사
	checkUserIDQuery := "SELECT id FROM bot_matrix_identities WHERE user_id = $1 LIMIT 1"
	err = db.DB.QueryRowContext(ctx, checkUserIDQuery, userID).Scan(&existingID)
	if err == nil {
		return 0, fmt.Errorf("이미 동일한 Matrix 사용자 ID를 사용하는 설정이 존재합니다: %s (ID: %d)", userID, existingID)
	}

	// 비밀번호 및 접근 토큰 암호화 (제공된 경우)
	var encryptedPassword, passwordNonce, encryptedAccessToken, accessTokenNonce []byte

	if password != "" {
		encryptedPassword, passwordNonce, err = crypto.EncryptData(password, masterKey)
		if err != nil {
			return 0, fmt.Errorf("비밀번호 암호화 실패: %w", err)
		}
	}

	if accessToken != "" {
		encryptedAccessToken, accessTokenNonce, err = crypto.EncryptData(accessToken, masterKey)
		if err != nil {
			return 0, fmt.Errorf("접근 토큰 암호화 실패: %w", err)
		}
	}

	// 현재 시간
	now := time.Now().UTC()

	// 설정 추가
	insertQuery := `
		INSERT INTO bot_matrix_identities (
			config_name, homeserver_url, user_id, encrypted_password, 
			password_encryption_nonce, encrypted_access_token, access_token_encryption_nonce,
			device_id, is_enabled, notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`

	var id int
	err = db.DB.QueryRowContext(
		ctx, insertQuery, configName, homeserverURL, userID,
		encryptedPassword, passwordNonce, encryptedAccessToken, accessTokenNonce,
		deviceID, isEnabled, notes, now, now,
	).Scan(&id)

	if err != nil {
		return 0, fmt.Errorf("matrix ID 설정 추가 실패: %w", err)
	}

	log.Info().Int("id", id).Msg("matrix ID 설정이 성공적으로 생성되었습니다")
	return id, nil
}

// DeleteMatrixIdentity는 Matrix ID 설정을 데이터베이스에서 삭제합니다.
func DeleteMatrixIdentity(ctx context.Context, db *database.Database, id int) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "delete_matrix_identity").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix ID 설정 삭제 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return errors.New("유효하지 않은 설정 ID")
	}

	// 설정 삭제
	deleteQuery := "DELETE FROM bot_matrix_identities WHERE id = $1"
	result, err := db.DB.ExecContext(ctx, deleteQuery, id)
	if err != nil {
		return fmt.Errorf("matrix ID 설정 삭제 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 Matrix ID 설정을 찾을 수 없습니다", id)
	}

	log.Info().Msg("Matrix ID 설정이 성공적으로 삭제되었습니다")
	return nil
}

// DeactivateMatrixIdentity는 Matrix ID 설정을 비활성화합니다.
func DeactivateMatrixIdentity(ctx context.Context, db *database.Database, id int) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "deactivate_matrix_identity").
		Int("config_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix ID 설정 비활성화 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return errors.New("유효하지 않은 설정 ID")
	}

	// 설정 비활성화
	updateQuery := "UPDATE bot_matrix_identities SET is_enabled = false, updated_at = $1 WHERE id = $2"
	now := time.Now().UTC()
	result, err := db.DB.ExecContext(ctx, updateQuery, now, id)
	if err != nil {
		return fmt.Errorf("matrix ID 설정 비활성화 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 matrix ID 설정을 찾을 수 없습니다", id)
	}

	log.Info().Msg("matrix ID 설정이 성공적으로 비활성화되었습니다")
	return nil
}

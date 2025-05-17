// matrix_update.go - Matrix ID 설정 업데이트 관련 함수
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

// UpdateMatrixIdentity는 기존 Matrix ID 설정을 업데이트합니다.
// 비밀번호나 접근 토큰이 제공되면 새로 암호화하여 업데이트합니다.
func UpdateMatrixIdentity(
	ctx context.Context,
	db *database.Database,
	id int,
	configName string,
	homeserverURL string,
	userID id.UserID,
	password string,
	accessToken string,
	deviceID string,
	masterKey []byte,
	isEnabled bool,
	notes string,
) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "update_matrix_identity").
		Int("config_id", id).
		Str("user_id", string(userID)).
		Bool("has_password", password != "").
		Bool("has_access_token", accessToken != "").
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix ID 설정 업데이트 시작")

	// 입력 유효성 검사
	if id <= 0 {
		return errors.New("유효하지 않은 설정 ID")
	}
	if configName == "" {
		return errors.New("설정 이름은 필수 입력 항목입니다")
	}
	if homeserverURL == "" {
		return errors.New("matrix 홈서버 URL은 필수 입력 항목입니다")
	}
	if userID == "" {
		return errors.New("matrix 사용자 ID는 필수 입력 항목입니다")
	}

	// 중복 설정 이름 검사 (자기 자신 제외)
	checkNameQuery := "SELECT id FROM bot_matrix_identities WHERE config_name = $1 AND id != $2 LIMIT 1"
	var existingID int
	err := db.DB.QueryRowContext(ctx, checkNameQuery, configName, id).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("이미 동일한 이름의 설정이 존재합니다: %s (ID: %d)", configName, existingID)
	}

	// 중복 사용자 ID 검사 (자기 자신 제외)
	checkUserIDQuery := "SELECT id FROM bot_matrix_identities WHERE user_id = $1 AND id != $2 LIMIT 1"
	err = db.DB.QueryRowContext(ctx, checkUserIDQuery, userID, id).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("이미 동일한 Matrix 사용자 ID를 사용하는 설정이 존재합니다: %s (ID: %d)", userID, existingID)
	}

	// 현재 시간
	now := time.Now().UTC()

	// 계정 정보 조회 (비밀번호/토큰 관련 처리를 위해)
	currentConfig, err := GetMatrixIdentityByID(ctx, db, id)
	if err != nil {
		return fmt.Errorf("현재 설정 조회 실패: %w", err)
	}

	var passwordUpdated, tokenUpdated bool
	var encryptedPassword, passwordNonce, encryptedAccessToken, accessTokenNonce []byte

	// 비밀번호 업데이트가 필요한 경우
	if password != "" {
		encryptedPassword, passwordNonce, err = crypto.EncryptData(password, masterKey)
		if err != nil {
			return fmt.Errorf("비밀번호 암호화 실패: %w", err)
		}
		passwordUpdated = true
	} else {
		// 기존 비밀번호 유지
		encryptedPassword = currentConfig.EncryptedPassword
		passwordNonce = currentConfig.PasswordNonce
	}

	// 접근 토큰 업데이트가 필요한 경우
	if accessToken != "" {
		encryptedAccessToken, accessTokenNonce, err = crypto.EncryptData(accessToken, masterKey)
		if err != nil {
			return fmt.Errorf("접근 토큰 암호화 실패: %w", err)
		}
		tokenUpdated = true
	} else {
		// 기존 접근 토큰 유지
		encryptedAccessToken = currentConfig.EncryptedAccessToken
		accessTokenNonce = currentConfig.AccessTokenNonce
	}

	// 업데이트 쿼리 구성
	updateQuery := `
		UPDATE bot_matrix_identities
		SET config_name = $1,
			homeserver_url = $2,
			user_id = $3,
			encrypted_password = $4,
			password_encryption_nonce = $5,
			encrypted_access_token = $6,
			access_token_encryption_nonce = $7,
			device_id = $8,
			is_enabled = $9,
			notes = $10,
			updated_at = $11
		WHERE id = $12
	`

	result, err := db.DB.ExecContext(
		ctx, updateQuery, configName, homeserverURL, userID,
		encryptedPassword, passwordNonce, encryptedAccessToken, accessTokenNonce,
		deviceID, isEnabled, notes, now, id,
	)
	if err != nil {
		return fmt.Errorf("matrix ID 설정 업데이트 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("id %d에 해당하는 Matrix ID 설정을 찾을 수 없습니다", id)
	}

	log.Info().
		Bool("password_updated", passwordUpdated).
		Bool("token_updated", tokenUpdated).
		Msg("Matrix ID 설정이 성공적으로 업데이트되었습니다")
	return nil
}

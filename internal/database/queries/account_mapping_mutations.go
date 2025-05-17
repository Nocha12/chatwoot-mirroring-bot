package queries

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
)

// CreateAccountMapping은 새로운 계정 매핑을 생성합니다.
func CreateAccountMapping(ctx context.Context, db *database.Database, chatwootConfigID, matrixIdentityID int, isActive bool, notes string) (int, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "create_account_mapping").
		Int("chatwoot_config_id", chatwootConfigID).
		Int("matrix_identity_id", matrixIdentityID).
		Bool("is_active", isActive).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("새 계정 매핑 생성 시작")

	now := time.Now().UTC()

	// 중복 매핑 검사
	existingMapping, err := GetAccountMappingByChatwootConfigID(ctx, db, chatwootConfigID)
	if err != nil {
		return 0, fmt.Errorf("중복 매핑 검사 실패(Chatwoot ID): %w", err)
	}
	if existingMapping != nil {
		return 0, fmt.Errorf("해당 Chatwoot 계정 설정(ID: %d)은 이미 다른 Matrix 아이덴티티에 매핑되어 있습니다", chatwootConfigID)
	}

	existingMapping, err = GetAccountMappingByMatrixIdentityID(ctx, db, matrixIdentityID)
	if err != nil {
		return 0, fmt.Errorf("중복 매핑 검사 실패(Matrix ID): %w", err)
	}
	if existingMapping != nil {
		return 0, fmt.Errorf("해당 Matrix 아이덴티티(ID: %d)는 이미 다른 Chatwoot 계정 설정에 매핑되어 있습니다", matrixIdentityID)
	}

	// 새 매핑 생성
	insertQuery := `
		INSERT INTO bot_account_mapping (
			chatwoot_config_id, matrix_identity_id, is_active, notes, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`
	var id int
	err = db.DB.QueryRowContext(
		ctx, insertQuery, chatwootConfigID, matrixIdentityID, isActive, notes, now, now,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("계정 매핑 생성 실패: %w", err)
	}

	log.Debug().Int("mapping_id", id).Msg("계정 매핑 생성 완료")
	return id, nil
}

// UpdateAccountMapping은 기존 계정 매핑을 업데이트합니다.
func UpdateAccountMapping(ctx context.Context, db *database.Database, id int, chatwootConfigID, matrixIdentityID int, isActive bool, notes string) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "update_account_mapping").
		Int("mapping_id", id).
		Int("chatwoot_config_id", chatwootConfigID).
		Int("matrix_identity_id", matrixIdentityID).
		Bool("is_active", isActive).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 업데이트 시작")

	// 중복 매핑 검사 (현재 매핑 제외)
	existingQuery := `
		SELECT id FROM bot_account_mapping
		WHERE chatwoot_config_id = $1 AND id != $2
		LIMIT 1
	`
	var existingID int
	err := db.DB.QueryRowContext(ctx, existingQuery, chatwootConfigID, id).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("해당 Chatwoot 계정 설정(ID: %d)은 이미 다른 매핑(ID: %d)에서 사용 중입니다", chatwootConfigID, existingID)
	}

	existingQuery = `
		SELECT id FROM bot_account_mapping
		WHERE matrix_identity_id = $1 AND id != $2
		LIMIT 1
	`
	err = db.DB.QueryRowContext(ctx, existingQuery, matrixIdentityID, id).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("해당 Matrix 아이덴티티(ID: %d)는 이미 다른 매핑(ID: %d)에서 사용 중입니다", matrixIdentityID, existingID)
	}

	// 매핑 업데이트
	updateQuery := `
		UPDATE bot_account_mapping
		SET chatwoot_config_id = $1, matrix_identity_id = $2, is_active = $3, notes = $4, updated_at = $5
		WHERE id = $6
	`
	now := time.Now().UTC()
	result, err := db.DB.ExecContext(
		ctx, updateQuery, chatwootConfigID, matrixIdentityID, isActive, notes, now, id,
	)
	if err != nil {
		return fmt.Errorf("계정 매핑 업데이트 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 계정 매핑을 찾을 수 없습니다", id)
	}

	log.Debug().Msg("계정 매핑 업데이트 완료")
	return nil
}

// DeleteAccountMapping은 계정 매핑을 데이터베이스에서 완전히 삭제합니다.
func DeleteAccountMapping(ctx context.Context, db *database.Database, id int) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "delete_account_mapping").
		Int("mapping_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 삭제 시작")

	deleteQuery := "DELETE FROM bot_account_mapping WHERE id = $1"
	result, err := db.DB.ExecContext(ctx, deleteQuery, id)
	if err != nil {
		return fmt.Errorf("계정 매핑 삭제 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 계정 매핑을 찾을 수 없습니다", id)
	}

	log.Debug().Msg("계정 매핑 삭제 완료")
	return nil
}

// DeactivateAccountMapping은 계정 매핑을 비활성화합니다 (논리적 삭제).
func DeactivateAccountMapping(ctx context.Context, db *database.Database, id int) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "deactivate_account_mapping").
		Int("mapping_id", id).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 비활성화 시작")

	updateQuery := `
		UPDATE bot_account_mapping
		SET is_active = false, updated_at = $1
		WHERE id = $2
	`
	now := time.Now().UTC()
	result, err := db.DB.ExecContext(ctx, updateQuery, now, id)
	if err != nil {
		return fmt.Errorf("계정 매핑 비활성화 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("ID %d에 해당하는 계정 매핑을 찾을 수 없습니다", id)
	}

	log.Debug().Msg("계정 매핑 비활성화 완료")
	return nil
}

// BatchDeactivateAccountMappings는 특정 Chatwoot 설정 ID나 Matrix 아이덴티티 ID와 관련된 모든 매핑을 비활성화합니다.
func BatchDeactivateAccountMappings(ctx context.Context, db *database.Database, chatwootConfigID, matrixIdentityID int) (int, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "batch_deactivate_account_mappings").
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().
		Int("chatwoot_config_id", chatwootConfigID).
		Int("matrix_identity_id", matrixIdentityID).
		Msg("일괄 계정 매핑 비활성화 시작")

	// 비활성화 조건 구성
	var conditions []string
	var params []interface{}
	paramIndex := 1

	if chatwootConfigID > 0 {
		conditions = append(conditions, fmt.Sprintf("chatwoot_config_id = $%d", paramIndex))
		params = append(params, chatwootConfigID)
		paramIndex++
	}

	if matrixIdentityID > 0 {
		conditions = append(conditions, fmt.Sprintf("matrix_identity_id = $%d", paramIndex))
		params = append(params, matrixIdentityID)
		paramIndex++
	}

	if len(conditions) == 0 {
		return 0, fmt.Errorf("chatwootConfigID 또는 matrixIdentityID 중 하나 이상의 값이 필요합니다")
	}

	// 비활성화 쿼리 실행
	updateQuery := fmt.Sprintf(`
		UPDATE bot_account_mapping
		SET is_active = false, updated_at = $%d
		WHERE %s AND is_active = true
	`, paramIndex, strings.Join(conditions, " OR "))

	now := time.Now().UTC()
	params = append(params, now)

	result, err := db.DB.ExecContext(ctx, updateQuery, params...)
	if err != nil {
		return 0, fmt.Errorf("일괄 계정 매핑 비활성화 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("영향 받은 행 수 확인 실패: %w", err)
	}

	log.Debug().Int64("deactivated_count", rowsAffected).Msg("일괄 계정 매핑 비활성화 완료")
	return int(rowsAffected), nil
}

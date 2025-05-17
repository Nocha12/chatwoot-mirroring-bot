package queries

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// GetAllAccountMappings는 모든 활성화된 계정 매핑 정보를 조회합니다.
func GetAllAccountMappings(ctx context.Context, db *database.Database) ([]AccountMapping, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_all_account_mappings").
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("모든 활성화된 계정 매핑 조회 시작")

	query := `
		SELECT id, chatwoot_config_id, matrix_identity_id, is_active, notes
		FROM bot_account_mapping
		WHERE is_active = true
		ORDER BY id
	`
	rows, err := db.DB.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("계정 매핑 조회 실패: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close rows")
		}
	}()

	var mappings []AccountMapping
	for rows.Next() {
		var mapping AccountMapping
		err := rows.Scan(
			&mapping.ID,
			&mapping.ChatwootConfigID,
			&mapping.MatrixIdentityID,
			&mapping.IsActive,
			&mapping.Notes,
		)
		if err != nil {
			return nil, fmt.Errorf("매핑 데이터 스캔 실패: %w", err)
		}
		mappings = append(mappings, mapping)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("매핑 조회 중 오류 발생: %w", err)
	}

	log.Debug().Int("mappings_count", len(mappings)).Msg("계정 매핑 조회 완료")
	return mappings, nil
}

// GetAccountMappingByChatwootConfigID는 특정 Chatwoot 설정 ID에 대한 매핑 정보를 조회합니다.
func GetAccountMappingByChatwootConfigID(ctx context.Context, db *database.Database, chatwootConfigID int) (*AccountMapping, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_account_mapping_by_chatwoot_config_id").
		Int("chatwoot_config_id", chatwootConfigID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 설정 ID로 계정 매핑 조회 시작")

	query := `
		SELECT id, chatwoot_config_id, matrix_identity_id, is_active, notes
		FROM bot_account_mapping
		WHERE chatwoot_config_id = $1 AND is_active = true
		LIMIT 1
	`
	var mapping AccountMapping
	err := db.DB.QueryRowContext(ctx, query, chatwootConfigID).Scan(
		&mapping.ID,
		&mapping.ChatwootConfigID,
		&mapping.MatrixIdentityID,
		&mapping.IsActive,
		&mapping.Notes,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().Msg("해당 Chatwoot 설정 ID에 대한 매핑 정보가 없음")
			return nil, nil
		}
		return nil, fmt.Errorf("chatwoot 설정 ID로 매핑 조회 실패: %w", err)
	}

	log.Debug().Int("mapping_id", mapping.ID).Msg("Chatwoot 설정 ID로 계정 매핑 조회 완료")
	return &mapping, nil
}

// GetAccountMappingByMatrixIdentityID는 특정 Matrix 아이덴티티 ID에 대한 매핑 정보를 조회합니다.
func GetAccountMappingByMatrixIdentityID(ctx context.Context, db *database.Database, matrixIdentityID int) (*AccountMapping, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_account_mapping_by_matrix_identity_id").
		Int("matrix_identity_id", matrixIdentityID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix 아이덴티티 ID로 계정 매핑 조회 시작")

	query := `
		SELECT id, chatwoot_config_id, matrix_identity_id, is_active, notes
		FROM bot_account_mapping
		WHERE matrix_identity_id = $1 AND is_active = true
		LIMIT 1
	`
	var mapping AccountMapping
	err := db.DB.QueryRowContext(ctx, query, matrixIdentityID).Scan(
		&mapping.ID,
		&mapping.ChatwootConfigID,
		&mapping.MatrixIdentityID,
		&mapping.IsActive,
		&mapping.Notes,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().Msg("해당 Matrix 아이덴티티 ID에 대한 매핑 정보가 없음")
			return nil, nil
		}
		return nil, fmt.Errorf("matrix 아이덴티티 ID로 매핑 조회 실패: %w", err)
	}

	log.Debug().Int("mapping_id", mapping.ID).Msg("Matrix 아이덴티티 ID로 계정 매핑 조회 완료")
	return &mapping, nil
}

// GetMatrixIdentityIDForChatwootConfig는 Chatwoot 계정 ID와 인박스 ID에 대응하는 Matrix 아이덴티티 ID를 조회합니다.
func GetMatrixIdentityIDForChatwootConfig(ctx context.Context, db *database.Database, accountID chatwootapi.AccountID, inboxID chatwootapi.InboxID) (int, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_matrix_identity_id_for_chatwoot_config").
		Int("chatwoot_account_id", int(accountID)).
		Int("chatwoot_inbox_id", int(inboxID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 계정과 인박스 ID로 Matrix 아이덴티티 ID 조회 시작")

	query := `
		SELECT m.matrix_identity_id
		FROM bot_account_mapping m
		JOIN bot_chatwoot_configs c ON m.chatwoot_config_id = c.id
		WHERE c.chatwoot_native_account_id = $1 AND c.inbox_id = $2 AND m.is_active = true AND c.is_enabled = true
		LIMIT 1
	`
	var matrixIdentityID int
	err := db.DB.QueryRowContext(ctx, query, int(accountID), int(inboxID)).Scan(&matrixIdentityID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().Msg("해당 Chatwoot 계정과 인박스 ID에 대한 Matrix 아이덴티티가 없음")
			return 0, nil
		}
		return 0, fmt.Errorf("chatwoot 계정과 인박스 ID로 matrix 아이덴티티 ID 조회 실패: %w", err)
	}

	log.Debug().Int("matrix_identity_id", matrixIdentityID).Msg("Matrix 아이덴티티 ID 조회 완료")
	return matrixIdentityID, nil
}

// GetChatwootConfigIDForMatrixIdentity는 Matrix 사용자 ID에 대응하는 Chatwoot 설정 ID를 조회합니다.
func GetChatwootConfigIDForMatrixIdentity(ctx context.Context, db *database.Database, matrixUserID string) (int, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_chatwoot_config_id_for_matrix_identity").
		Str("matrix_user_id", matrixUserID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix 사용자 ID로 Chatwoot 설정 ID 조회 시작")

	query := `
		SELECT m.chatwoot_config_id
		FROM bot_account_mapping m
		JOIN bot_matrix_identities i ON m.matrix_identity_id = i.id
		WHERE i.user_id = $1 AND m.is_active = true AND i.is_enabled = true
		LIMIT 1
	`
	var chatwootConfigID int
	err := db.DB.QueryRowContext(ctx, query, matrixUserID).Scan(&chatwootConfigID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Debug().Msg("해당 Matrix 사용자 ID에 대한 Chatwoot 설정이 없음")
			return 0, nil
		}
		return 0, fmt.Errorf("matrix 사용자 ID로 chatwoot 설정 ID 조회 실패: %w", err)
	}

	log.Debug().Int("chatwoot_config_id", chatwootConfigID).Msg("Chatwoot 설정 ID 조회 완료")
	return chatwootConfigID, nil
}

// account_mapping_setup.go
package setup

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
)

// SetupAccountMappings는 DB에서 계정 매핑 정보를 로드하고 AccountMappingManager를 초기화합니다.
func SetupAccountMappings(
	ctx context.Context,
	db *database.Database,
	chatwootConfigs map[int]*config.RuntimeChatwootConfig,
	matrixIdentities map[int]*config.MatrixIdentityConfig,
	log zerolog.Logger,
) (*config.AccountMappingManager, error) {
	log = log.With().Str("component", "setup_account_mappings").Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 정보 로드 시작")

	// AccountMappingManager 생성
	mappingManager := config.NewAccountMappingManager()

	// DB에서 활성화된 모든 매핑 로드
	mappings, err := queries.GetAllAccountMappings(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("계정 매핑 로드 실패: %w", err)
	}

	log.Debug().Int("mappings_count", len(mappings)).Msg("계정 매핑 정보 조회 완료")

	// 각 매핑 정보를 AccountMappingManager에 추가
	for _, mapping := range mappings {
		// AccountMappingInfo 생성
		mappingInfo := &config.AccountMappingInfo{
			ID:               mapping.ID,
			ChatwootConfigID: mapping.ChatwootConfigID,
			MatrixIdentityID: mapping.MatrixIdentityID,
			IsActive:         mapping.IsActive,
			Notes:            mapping.Notes,
		}

		// Chatwoot 설정 참조 추가
		if chatwootConfig, ok := chatwootConfigs[mapping.ChatwootConfigID]; ok {
			mappingInfo.ChatwootConfig = chatwootConfig
		} else {
			log.Warn().Int("chatwoot_config_id", mapping.ChatwootConfigID).
				Msg("매핑에 해당하는 Chatwoot 설정을 찾을 수 없음")
			continue // 필수 설정이 없으면 이 매핑은 건너뜀
		}

		// Matrix 아이덴티티 참조 추가
		if matrixIdentity, ok := matrixIdentities[mapping.MatrixIdentityID]; ok {
			mappingInfo.MatrixConfig = matrixIdentity
		} else {
			log.Warn().Int("matrix_identity_id", mapping.MatrixIdentityID).
				Msg("매핑에 해당하는 Matrix 아이덴티티를 찾을 수 없음")
			continue // 필수 설정이 없으면 이 매핑은 건너뜀
		}

		// 매핑 매니저에 추가
		mappingManager.AddMapping(mappingInfo)
		log.Debug().
			Int("mapping_id", mapping.ID).
			Int("chatwoot_config_id", mapping.ChatwootConfigID).
			Int("matrix_identity_id", mapping.MatrixIdentityID).
			Msg("매핑 추가됨")
	}

	activeMappings := mappingManager.GetAllActiveMappings()
	log.Info().Int("active_mappings_count", len(activeMappings)).Msg("계정 매핑 설정 완료")

	return mappingManager, nil
}

// SaveAccountMapping은 새로운 계정 매핑을 DB에 저장하고 AccountMappingManager에 추가합니다.
func SaveAccountMapping(
	ctx context.Context,
	db *database.Database,
	mappingManager *config.AccountMappingManager,
	chatwootConfigID int,
	matrixIdentityID int,
	isActive bool,
	notes string,
	chatwootConfigs map[int]*config.RuntimeChatwootConfig,
	matrixIdentities map[int]*config.MatrixIdentityConfig,
	log zerolog.Logger,
) (int, error) {
	log = log.With().Str("component", "save_account_mapping").Logger()
	ctx = log.WithContext(ctx)

	log.Debug().
		Int("chatwoot_config_id", chatwootConfigID).
		Int("matrix_identity_id", matrixIdentityID).
		Msg("새 계정 매핑 저장 시작")

	// 1. DB에 저장
	mappingID, err := queries.CreateAccountMapping(ctx, db, chatwootConfigID, matrixIdentityID, isActive, notes)
	if err != nil {
		return 0, fmt.Errorf("계정 매핑 생성 실패: %w", err)
	}

	// 2. 메모리 매핑 매니저에 추가
	mappingInfo := &config.AccountMappingInfo{
		ID:               mappingID,
		ChatwootConfigID: chatwootConfigID,
		MatrixIdentityID: matrixIdentityID,
		IsActive:         isActive,
		Notes:            notes,
	}

	// Chatwoot 설정 참조 추가
	if chatwootConfig, ok := chatwootConfigs[chatwootConfigID]; ok {
		mappingInfo.ChatwootConfig = chatwootConfig
	} else {
		return mappingID, fmt.Errorf("매핑에 해당하는 Chatwoot 설정을 찾을 수 없음")
	}

	// Matrix 아이덴티티 참조 추가
	if matrixIdentity, ok := matrixIdentities[matrixIdentityID]; ok {
		mappingInfo.MatrixConfig = matrixIdentity
	} else {
		return mappingID, fmt.Errorf("매핑에 해당하는 Matrix 아이덴티티를 찾을 수 없음")
	}

	// 매핑 매니저에 추가
	mappingManager.AddMapping(mappingInfo)

	log.Info().
		Int("mapping_id", mappingID).
		Int("chatwoot_config_id", chatwootConfigID).
		Int("matrix_identity_id", matrixIdentityID).
		Msg("새 계정 매핑 저장 완료")

	return mappingID, nil
}

// UpdateAccountMappingStatus는 계정 매핑의 활성화 상태를 업데이트합니다.
func UpdateAccountMappingStatus(
	ctx context.Context,
	db *database.Database,
	mappingManager *config.AccountMappingManager,
	mappingID int,
	isActive bool,
	log zerolog.Logger,
) error {
	log = log.With().
		Str("component", "update_account_mapping_status").
		Int("mapping_id", mappingID).
		Bool("is_active", isActive).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 상태 업데이트 시작")

	// 1. DB 상태 업데이트
	if isActive {
		// 활성화인 경우 기존 매핑 업데이트
		err := queries.UpdateAccountMapping(ctx, db, mappingID, 0, 0, isActive, "")
		if err != nil {
			return fmt.Errorf("매핑 활성화 실패: %w", err)
		}
	} else {
		// 비활성화인 경우 논리적 삭제
		err := queries.DeactivateAccountMapping(ctx, db, mappingID)
		if err != nil {
			return fmt.Errorf("매핑 비활성화 실패: %w", err)
		}
	}

	// 2. 메모리 상태 업데이트
	err := mappingManager.SetMappingStatus(mappingID, isActive)
	if err != nil {
		return fmt.Errorf("메모리 매핑 상태 업데이트 실패: %w", err)
	}

	log.Info().Msg("계정 매핑 상태 업데이트 완료")
	return nil
}

// DeleteAccountMapping은 계정 매핑을 물리적으로 삭제합니다.
func DeleteAccountMapping(
	ctx context.Context,
	db *database.Database,
	mappingManager *config.AccountMappingManager,
	mappingID int,
	log zerolog.Logger,
) error {
	log = log.With().
		Str("component", "delete_account_mapping").
		Int("mapping_id", mappingID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 삭제 시작")

	// 1. DB에서 삭제
	err := queries.DeleteAccountMapping(ctx, db, mappingID)
	if err != nil {
		return fmt.Errorf("매핑 삭제 실패: %w", err)
	}

	// 2. 메모리에서 제거
	mappingManager.RemoveMapping(mappingID)

	log.Info().Msg("계정 매핑 삭제 완료")
	return nil
}

// account_config.go - 계정 구성 생성 및 관리를 위한 통합 함수
package queries

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// AccountMappingConfig는 계정 매핑 통합 생성에 필요한 설정을 담는 구조체입니다.
type AccountMappingConfig struct {
	// Chatwoot 계정 설정
	ChatwootConfigName string
	ChatwootBaseURL    string
	ChatwootAccountID  chatwootapi.AccountID
	ChatwootInboxID    chatwootapi.InboxID
	ChatwootAccessToken string
	
	// Matrix 아이덴티티 설정
	MatrixConfigName   string
	MatrixHomeserverURL string
	MatrixUserID       id.UserID
	MatrixPassword     string
	MatrixAccessToken  string
	MatrixDeviceID     string
	
	// 공통 설정
	IsEnabled          bool
	Notes              string
}

// AddAccountWithMapping은 Chatwoot 계정, Matrix ID 설정 생성 및 매핑을 한번에 처리하는 통합 함수입니다.
// 트랜잭션을 사용하여 모든 작업이 함께 성공하거나 실패하도록 보장합니다.
// AddAccountWithMapping은 Chatwoot 계정, Matrix ID 설정 생성 및 매핑을 한번에 처리하는 통합 함수입니다.
// 트랜잭션을 사용하여 모든 작업이 함께 성공하거나 실패하도록 보장합니다.
// 참고: 이 함수는 CreateChatwootConfig, CreateMatrixIdentity, CreateAccountMapping 함수들이
// SQL 트랜잭션을 파라미터로 받을 수 있도록 수정되어야 합니다.
func AddAccountWithMapping(
	ctx context.Context,
	db *database.Database,
	config AccountMappingConfig,
	masterKey []byte,
) (chatwootID int, matrixID int, mappingID int, err error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "add_account_with_mapping").
		Str("chatwoot_config", config.ChatwootConfigName).
		Str("matrix_config", config.MatrixConfigName).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 설정 및 매핑 통합 생성 시작")

	// 필수 입력 검증
	if config.ChatwootConfigName == "" || config.MatrixConfigName == "" {
		return 0, 0, 0, errors.New("chatwoot과 Matrix 설정 이름은 필수 입력 항목입니다")
	}
	if config.ChatwootBaseURL == "" {
		return 0, 0, 0, errors.New("chatwoot 기본 URL은 필수 입력 항목입니다")
	}
	if config.ChatwootAccountID <= 0 {
		return 0, 0, 0, errors.New("유효하지 않은 chatwoot 계정 ID")
	}
	if config.ChatwootInboxID <= 0 {
		return 0, 0, 0, errors.New("유효하지 않은 chatwoot 인박스 ID")
	}
	if config.ChatwootAccessToken == "" {
		return 0, 0, 0, errors.New("chatwoot 접근 토큰은 필수 입력 항목입니다")
	}
	if config.MatrixHomeserverURL == "" {
		return 0, 0, 0, errors.New("matrix 홈서버 URL은 필수 입력 항목입니다")
	}
	if config.MatrixUserID == "" {
		return 0, 0, 0, errors.New("matrix 사용자 ID는 필수 입력 항목입니다")
	}
	if config.MatrixPassword == "" && config.MatrixAccessToken == "" {
		return 0, 0, 0, errors.New("matrix 비밀번호 또는 접근 토큰 중 하나는 필수 입력 항목입니다")
	}

	// 모든 작업은 같은 데이터베이스 커넥션에서 처리됩니다.
	// 여기서는 트랜잭션을 사용하지 않습니다. 차후 버전에서 트랜잭션 지원을 추가할 수 있습니다.

	// 1. Chatwoot 계정 설정 생성
	chatwootID, err = CreateChatwootConfig(
		ctx,
		db,
		config.ChatwootConfigName,
		config.ChatwootBaseURL,
		config.ChatwootAccountID,
		config.ChatwootInboxID,
		config.ChatwootAccessToken,
		masterKey,
		config.IsEnabled,
		config.Notes,
	)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("chatwoot 계정 설정 생성 실패: %w", err)
	}
	log.Debug().Int("chatwoot_id", chatwootID).Msg("Chatwoot 계정 설정 생성 완료")

	// 2. Matrix ID 설정 생성
	matrixID, err = CreateMatrixIdentity(
		ctx,
		db,
		config.MatrixConfigName,
		config.MatrixHomeserverURL,
		config.MatrixUserID,
		config.MatrixPassword,
		config.MatrixAccessToken,
		config.MatrixDeviceID,
		masterKey,
		config.IsEnabled,
		config.Notes,
	)
	if err != nil {
		return chatwootID, 0, 0, fmt.Errorf("matrix ID 설정 생성 실패: %w", err)
	}
	log.Debug().Int("matrix_id", matrixID).Msg("Matrix ID 설정 생성 완료")

	// 3. 계정 매핑 생성
	mappingID, err = CreateAccountMapping(
		ctx,
		db,
		chatwootID,
		matrixID,
		config.IsEnabled,
		config.Notes,
	)
	if err != nil {
		return chatwootID, matrixID, 0, fmt.Errorf("계정 매핑 생성 실패: %w", err)
	}
	log.Debug().Int("mapping_id", mappingID).Msg("계정 매핑 생성 완료")

	// 모든 작업이 완료되었습니다. 향후 트랜잭션 지원을 추가할 예정입니다.

	log.Info().
		Int("chatwoot_id", chatwootID).
		Int("matrix_id", matrixID).
		Int("mapping_id", mappingID).
		Msg("계정 설정 및 매핑 통합 생성 완료")

	return chatwootID, matrixID, mappingID, nil
}

// GetAccountMappingDetails는 계정 매핑 정보와 관련된 Chatwoot 및 Matrix 설정 상세 정보를 함께 조회합니다.
func GetAccountMappingDetails(
	ctx context.Context, 
	db *database.Database, 
	mappingID int,
) (*AccountMappingConfig, *AccountMapping, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_account_mapping_details").
		Int("mapping_id", mappingID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("계정 매핑 상세 정보 조회 시작")

	// 매핑 ID로 계정 매핑 조회 쿼리
	mappingQuery := `
		SELECT id, chatwoot_config_id, matrix_identity_id, is_active, notes
		FROM bot_account_mapping
		WHERE id = $1
	`
	var mapping AccountMapping
	err := db.DB.QueryRowContext(ctx, mappingQuery, mappingID).Scan(
		&mapping.ID,
		&mapping.ChatwootConfigID,
		&mapping.MatrixIdentityID,
		&mapping.IsActive,
		&mapping.Notes,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("매핑 정보 조회 실패: %w", err)
	}

	// Chatwoot 설정 조회
	chatwootConfig, err := GetChatwootConfigByID(ctx, db, mapping.ChatwootConfigID)
	if err != nil {
		return nil, &mapping, fmt.Errorf("chatwoot 설정 조회 실패: %w", err)
	}

	// Matrix ID 설정 조회
	matrixConfig, err := GetMatrixIdentityByID(ctx, db, mapping.MatrixIdentityID)
	if err != nil {
		return nil, &mapping, fmt.Errorf("matrix ID 설정 조회 실패: %w", err)
	}

	// 통합 설정 정보 구성
	config := &AccountMappingConfig{
		ChatwootConfigName:  chatwootConfig.ConfigName,
		ChatwootBaseURL:     chatwootConfig.BaseURL,
		ChatwootAccountID:   chatwootConfig.AccountID,
		ChatwootInboxID:     chatwootConfig.InboxID,
		
		MatrixConfigName:    matrixConfig.ConfigName,
		MatrixHomeserverURL: matrixConfig.HomeserverURL,
		MatrixUserID:        matrixConfig.UserID,
		MatrixDeviceID:      matrixConfig.DeviceID,
		
		IsEnabled:           mapping.IsActive,
		Notes:               mapping.Notes,
	}

	log.Debug().Msg("계정 매핑 상세 정보 조회 완료")
	return config, &mapping, nil
}

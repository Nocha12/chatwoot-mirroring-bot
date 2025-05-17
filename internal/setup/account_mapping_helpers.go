// account_mapping_helpers.go
package setup

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// MatrixUserIDForChatwootAccount는 Chatwoot 계정 ID와 인박스 ID를 사용하여
// 해당 계정에 매핑된 Matrix 사용자 ID를 반환합니다.
func (app *AppSetup) MatrixUserIDForChatwootAccount(
	ctx context.Context,
	accountID chatwootapi.AccountID,
	inboxID chatwootapi.InboxID,
) (id.UserID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "matrix_user_id_for_chatwoot_account").
		Int("chatwoot_account_id", int(accountID)).
		Int("chatwoot_inbox_id", int(inboxID)).
		Logger()

	log.Debug().Msg("Chatwoot 계정으로 Matrix 사용자 ID 조회 시작")

	// AccountMappingManager에서 매핑 정보 조회
	userID, err := app.AccountMappings.GetMatrixUserIDForChatwootAccount(accountID, inboxID)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 계정에 매핑된 Matrix 사용자 ID 조회 실패")
		return "", err
	}

	log.Debug().Str("matrix_user_id", string(userID)).Msg("Matrix 사용자 ID 조회 완료")
	return userID, nil
}

// ChatwootAccountForMatrixUserID는 Matrix 사용자 ID를 사용하여
// 해당 ID에 매핑된 Chatwoot 계정 정보를 반환합니다.
func (app *AppSetup) ChatwootAccountForMatrixUserID(
	ctx context.Context,
	userID id.UserID,
) (chatwootapi.AccountID, chatwootapi.InboxID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "chatwoot_account_for_matrix_user_id").
		Str("matrix_user_id", string(userID)).
		Logger()

	log.Debug().Msg("Matrix 사용자 ID로 Chatwoot 계정 정보 조회 시작")

	// AccountMappingManager에서 매핑 정보 조회
	chatwootConfig, err := app.AccountMappings.GetChatwootAccountForMatrixUserID(userID)
	if err != nil {
		log.Error().Err(err).Msg("Matrix 사용자 ID에 매핑된 Chatwoot 계정 정보 조회 실패")
		return 0, 0, err
	}

	accountID := chatwootConfig.AccountID
	inboxID := chatwootConfig.InboxID

	log.Debug().
		Int("chatwoot_account_id", int(accountID)).
		Int("chatwoot_inbox_id", int(inboxID)).
		Msg("Chatwoot 계정 정보 조회 완료")

	return accountID, inboxID, nil
}

// ChatwootClientForMatrixUserID는 Matrix 사용자 ID를 사용하여
// 해당 ID에 매핑된 Chatwoot API 클라이언트를 반환합니다.
func (app *AppSetup) ChatwootClientForMatrixUserID(
	ctx context.Context,
	userID id.UserID,
) (*chatwootapi.Client, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "chatwoot_client_for_matrix_user_id").
		Str("matrix_user_id", string(userID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix 사용자 ID로 Chatwoot API 클라이언트 조회 시작")

	// Matrix 사용자 ID로 Chatwoot 계정 ID 조회
	accountID, _, err := app.ChatwootAccountForMatrixUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Chatwoot API 클라이언트 맵에서 클라이언트 조회
	client, exists := app.ChatwootAPIs[accountID]
	if !exists {
		err := fmt.Errorf("계정 ID %d에 대한 Chatwoot API 클라이언트를 찾을 수 없습니다", accountID)
		log.Error().Err(err).Msg("Chatwoot API 클라이언트 조회 실패")
		return nil, err
	}

	log.Debug().Int("chatwoot_account_id", int(accountID)).Msg("Chatwoot API 클라이언트 조회 완료")
	return client, nil
}

// GetChatwootClientForAccount는 Chatwoot 계정 ID를 사용하여
// 해당 계정에 대한 Chatwoot API 클라이언트를 반환합니다.
func (app *AppSetup) GetChatwootClientForAccount(
	ctx context.Context,
	accountID chatwootapi.AccountID,
) (*chatwootapi.Client, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_chatwoot_client_for_account").
		Int("chatwoot_account_id", int(accountID)).
		Logger()

	log.Debug().Msg("Chatwoot 계정 ID로 API 클라이언트 조회 시작")

	// Chatwoot API 클라이언트 맵에서 클라이언트 조회
	client, exists := app.ChatwootAPIs[accountID]
	if !exists {
		err := fmt.Errorf("계정 ID %d에 대한 Chatwoot API 클라이언트를 찾을 수 없습니다", accountID)
		log.Error().Err(err).Msg("Chatwoot API 클라이언트 조회 실패")
		return nil, err
	}

	log.Debug().Msg("Chatwoot API 클라이언트 조회 완료")
	return client, nil
}

// IsMatrixUserIDMapped는 주어진 Matrix 사용자 ID가 Chatwoot 계정에 매핑되어 있는지 확인합니다.
func (app *AppSetup) IsMatrixUserIDMapped(
	ctx context.Context,
	userID id.UserID,
) bool {
	log := zerolog.Ctx(ctx).With().
		Str("component", "is_matrix_user_id_mapped").
		Str("matrix_user_id", string(userID)).
		Logger()

	log.Debug().Msg("Matrix 사용자 ID 매핑 여부 확인 시작")

	// AccountMappingManager에서 매핑 정보 조회
	mapping := app.AccountMappings.GetMappingByMatrixUserID(userID)
	result := mapping != nil && mapping.IsActive

	log.Debug().Bool("is_mapped", result).Msg("Matrix 사용자 ID 매핑 여부 확인 완료")
	return result
}

// IsChatwootAccountMapped는 주어진 Chatwoot 계정 ID와 인박스 ID가 Matrix ID에 매핑되어 있는지 확인합니다.
func (app *AppSetup) IsChatwootAccountMapped(
	ctx context.Context,
	accountID chatwootapi.AccountID,
	inboxID chatwootapi.InboxID,
) bool {
	log := zerolog.Ctx(ctx).With().
		Str("component", "is_chatwoot_account_mapped").
		Int("chatwoot_account_id", int(accountID)).
		Int("chatwoot_inbox_id", int(inboxID)).
		Logger()

	log.Debug().Msg("Chatwoot 계정 매핑 여부 확인 시작")

	// AccountMappingManager에서 매핑 정보 조회
	mapping := app.AccountMappings.GetMappingByChatwootAccountAndInbox(accountID, inboxID)
	result := mapping != nil && mapping.IsActive

	log.Debug().Bool("is_mapped", result).Msg("Chatwoot 계정 매핑 여부 확인 완료")
	return result
}

// GetAllActiveMappings는 모든 활성화된 계정 매핑 정보를 반환합니다.
func (app *AppSetup) GetAllActiveMappings(ctx context.Context) []*struct {
	ChatwootAccountID chatwootapi.AccountID
	ChatwootInboxID   chatwootapi.InboxID
	MatrixUserID      id.UserID
} {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_all_active_mappings").
		Logger()

	log.Debug().Msg("모든 활성화된 계정 매핑 정보 조회 시작")

	// AccountMappingManager에서 모든 활성화된 매핑 조회
	mappings := app.AccountMappings.GetAllActiveMappings()
	result := make([]*struct {
		ChatwootAccountID chatwootapi.AccountID
		ChatwootInboxID   chatwootapi.InboxID
		MatrixUserID      id.UserID
	}, 0, len(mappings))

	for _, mapping := range mappings {
		if mapping.ChatwootConfig == nil || mapping.MatrixConfig == nil {
			continue
		}

		result = append(result, &struct {
			ChatwootAccountID chatwootapi.AccountID
			ChatwootInboxID   chatwootapi.InboxID
			MatrixUserID      id.UserID
		}{
			ChatwootAccountID: mapping.ChatwootConfig.AccountID,
			ChatwootInboxID:   mapping.ChatwootConfig.InboxID,
			MatrixUserID:      mapping.MatrixConfig.UserID,
		})
	}

	log.Debug().Int("mappings_count", len(result)).Msg("활성화된 계정 매핑 정보 조회 완료")
	return result
}

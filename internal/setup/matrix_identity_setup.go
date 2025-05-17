// matrix_identity_setup.go
package setup

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
)

// SetupMatrixIdentities는 DB에서 Matrix 아이덴티티 정보를 로드하고 매핑을 반환합니다.
func SetupMatrixIdentities(
	ctx context.Context,
	db *database.Database,
	log zerolog.Logger,
) (map[int]*config.MatrixIdentityConfig, error) {
	log = log.With().Str("component", "setup_matrix_identities").Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix 아이덴티티 정보 로드 시작")

	// DB에서 활성화된 Matrix 아이덴티티 로드
	identities, err := queries.GetMatrixIdentities(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("matrix 아이덴티티 로드 실패: %w", err)
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("활성화된 Matrix 아이덴티티가 없습니다")
	}

	// 결과 맵 생성
	result := make(map[int]*config.MatrixIdentityConfig)

	for _, identity := range identities {
		if !identity.IsEnabled {
			continue
		}

		// MatrixIdentityConfig 생성
		config := &config.MatrixIdentityConfig{
			ID:            identity.ID,
			ConfigName:    identity.ConfigName,
			HomeserverURL: identity.HomeserverURL,
			UserID:        identity.UserID,
			DeviceID:      identity.DeviceID,
			IsEnabled:     identity.IsEnabled,
		}

		// 맵에 추가
		result[identity.ID] = config
		log.Debug().
			Int("identity_id", identity.ID).
			Str("user_id", string(identity.UserID)).
			Msg("Matrix 아이덴티티 로드됨")
	}

	log.Info().Int("identities_count", len(result)).Msg("Matrix 아이덴티티 설정 완료")
	return result, nil
}

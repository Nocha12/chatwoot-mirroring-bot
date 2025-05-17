// chatwoot_setup.go
package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// SetupChatwootAPIs는 파일 기반(cfg) 또는 DB 기반(runtimeCfg) 설정을 받아
// Chatwoot API 클라이언트 맵과 기본 계정 ID를 반환합니다.
// cfg가 nil이면 runtimeCfg를 사용하고, 그렇지 않으면 cfg를 사용합니다.
func SetupChatwootAPIs(
	cfg *config.Configuration,
	runtimeCfg *config.RuntimeConfig,
) (map[chatwootapi.AccountID]*chatwootapi.Client, chatwootapi.AccountID, error) {
	apis := make(map[chatwootapi.AccountID]*chatwootapi.Client)
	var defaultAccountID chatwootapi.AccountID

	if cfg == nil {
		// DB 기반 설정
		first := true
		for _, accCfg := range runtimeCfg.ChatwootAccounts {
			if !accCfg.IsEnabled {
				continue
			}
			client := chatwootapi.NewClient(
				accCfg.BaseURL,
				accCfg.AccountID,
				accCfg.InboxID,
				accCfg.AccessToken,
			)
			apis[accCfg.AccountID] = client
			if first {
				defaultAccountID = accCfg.AccountID
				first = false
			}
		}
	} else {
		// 파일 기반 설정
		for i, accCfg := range cfg.ChatwootAccounts {
			// 토큰 파일 읽기
			tokenBytes, err := os.ReadFile(accCfg.AccessTokenFile)
			if err != nil {
				return nil, 0, fmt.Errorf("액세스 토큰 파일 읽기 실패 (account %d): %w", accCfg.AccountID, err)
			}
			token := strings.TrimSpace(string(tokenBytes))
			// BaseURL 결정
			baseURL := accCfg.BaseUrl
			if baseURL == "" {
				baseURL = cfg.ChatwootBaseUrl
			}

			client := chatwootapi.NewClient(
				baseURL,
				accCfg.AccountID,
				accCfg.InboxID,
				token,
			)
			apis[accCfg.AccountID] = client
			if i == 0 {
				defaultAccountID = accCfg.AccountID
			}
		}
	}

	if len(apis) == 0 {
		return nil, 0, fmt.Errorf("chatwoot 계정 설정이 없습니다")
	}
	return apis, defaultAccountID, nil
}

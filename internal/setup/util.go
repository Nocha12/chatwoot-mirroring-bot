// util.go
package setup

import (
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// GetChatwootAPIForAccount는 지정된 계정 ID에 맞는 Chatwoot API 클라이언트를 반환합니다.
// 계정 ID에 해당하는 클라이언트가 없으면 기본 계정 클라이언트를 반환합니다.
func GetChatwootAPIForAccount(
	chatwootAPIs map[chatwootapi.AccountID]*chatwootapi.Client,
	accountID chatwootapi.AccountID,
	defaultAccountID chatwootapi.AccountID,
) *chatwootapi.Client {
	if api, exists := chatwootAPIs[accountID]; exists {
		return api
	}
	return chatwootAPIs[defaultAccountID]
}

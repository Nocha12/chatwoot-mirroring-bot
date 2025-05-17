// Package conversation은 Matrix와 Chatwoot 간의 대화 연결을 관리하는 패키지입니다.
package conversation

import (
	"sync"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// ManagerImpl은 Manager 인터페이스를 구현하는 구조체입니다.
type ManagerImpl struct {
	Client             matrix.MatrixClient
	StateStore         *database.Database
	GetChatwootAPI     func(accountID chatwootapi.AccountID) *chatwootapi.Client
	DefaultAccountID   chatwootapi.AccountID
	BridgeMembersLimit int // 브릿지할 최대 멤버 수 제한 (이 값 이상이면 브릿지하지 않음)
	createRoomLock     sync.Mutex
}

// NewManager는 새로운 Manager 인스턴스를 생성합니다.
func NewManager(
	client matrix.MatrixClient,
	stateStore *database.Database,
	getChatwootAPI func(accountID chatwootapi.AccountID) *chatwootapi.Client,
	defaultAccountID chatwootapi.AccountID,
	bridgeMembersLimit int,
) *ManagerImpl {
	return &ManagerImpl{
		Client:             client,
		StateStore:         stateStore,
		GetChatwootAPI:     getChatwootAPI,
		DefaultAccountID:   defaultAccountID,
		BridgeMembersLimit: bridgeMembersLimit,
	}
}

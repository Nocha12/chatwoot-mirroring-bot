package chatwoot

import (
	"sync"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// MessageHandler는 Chatwoot 메시지 이벤트를 처리하는 구조체입니다.
type MessageHandler struct {
	// 의존성 주입을 위한 필드들
	GetMatrixClient func(accountID chatwootapi.AccountID, inboxID chatwootapi.InboxID) *mautrix.Client
	StateStore      *database.Database
	ChatwootAPIs    map[chatwootapi.AccountID]*chatwootapi.Client
	GetAPI          func(accountID chatwootapi.AccountID) *chatwootapi.Client
	RoomSendlocks   map[id.RoomID]*sync.Mutex
}

// NewMessageHandler는 새로운 MessageHandler 인스턴스를 생성합니다.
func NewMessageHandler(
	getMatrixClient func(accountID chatwootapi.AccountID, inboxID chatwootapi.InboxID) *mautrix.Client,
	stateStore *database.Database,
	chatwootAPIs map[chatwootapi.AccountID]*chatwootapi.Client,
	getAPIFunc func(accountID chatwootapi.AccountID) *chatwootapi.Client,
	roomSendlocks map[id.RoomID]*sync.Mutex,
) *MessageHandler {
	return &MessageHandler{
		GetMatrixClient: getMatrixClient,
		StateStore:      stateStore,
		ChatwootAPIs:    chatwootAPIs,
		GetAPI:          getAPIFunc,
		RoomSendlocks:   roomSendlocks,
	}
}

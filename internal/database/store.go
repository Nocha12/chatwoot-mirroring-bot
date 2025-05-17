package database

import (
	"context"
	"errors"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"maunium.net/go/mautrix/id"
)

var ErrNotFound = errors.New("레코드를 찾을 수 없습니다")

// Store는 데이터베이스 작업을 위한 인터페이스입니다.
type Store interface {
	// 방–대화 매핑
	GetChatwootConversationIDFromMatrixRoom(ctx context.Context, roomID id.RoomID) (chatwootapi.ConversationID, chatwootapi.AccountID, error)
	GetMatrixRoomFromChatwootConversation(ctx context.Context, conversationID chatwootapi.ConversationID, accountID string) (id.RoomID, string, error)
	StoreMatrixRoomForChatwootConversation(ctx context.Context, roomID id.RoomID, conversationID chatwootapi.ConversationID, accountID string) error
	DeleteMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) error
	UpdateConversationIDForRoom(ctx context.Context, roomID id.RoomID, accountID int, inboxID int, conversationID chatwootapi.ConversationID) error
	UpdateMostRecentEventIDForRoom(ctx context.Context, roomID id.RoomID, mostRecentEventID id.EventID) error
	GetAccountAndInboxIDForConversation(ctx context.Context, roomID id.RoomID) (chatwootapi.AccountID, chatwootapi.InboxID, error)

	// 이벤트–메시지 매핑
	GetChatwootMessageIDsForMatrixEventID(ctx context.Context, eventID id.EventID) ([]chatwootapi.MessageID, chatwootapi.AccountID, error)
	GetMatrixEventIDsForChatwootMessage(ctx context.Context, accountID int, messageID chatwootapi.MessageID) ([]id.EventID, error)
	StoreMatrixEventToChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, eventID id.EventID, messageID chatwootapi.MessageID) error
	DeleteMatrixEventForChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, messageID chatwootapi.MessageID) error
	SetChatwootMessageIDForMatrixEvent(ctx context.Context, accountID int, eventID id.EventID, messageID chatwootapi.MessageID) error

	// 고급 조회
	GetChatwootMessageFromMatrixEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (chatwootapi.ConversationID, chatwootapi.MessageID, error)
	GetMatrixEventFromChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) (id.RoomID, id.EventID, error)

	// 초기화/관리
	Connect(dbType, uri string) error
	Init(ctx context.Context) error
	Upgrade(ctx context.Context) error
	Close() error
}

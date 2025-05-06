package matrix

import (
	"context"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// MatrixClient는 Matrix 클라이언트 인터페이스를 정의합니다.
type MatrixClient interface {
	UserID() id.UserID
	SendMessageEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, content interface{}, opts ...mautrix.ReqSendEvent) (*mautrix.RespSendEvent, error)
	SendStateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content interface{}) (*mautrix.RespSendEvent, error)
	RedactEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID, opts ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error)
	JoinedRooms(ctx context.Context) (*mautrix.RespJoinedRooms, error)
}

// StateStore는 상태 저장 인터페이스를 정의합니다.
type StateStore interface {
	StoreMatrixEventToChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, roomID id.RoomID, eventID id.EventID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error
	GetChatwootMessageFromMatrixEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (chatwootapi.ConversationID, chatwootapi.MessageID, error)
	GetMatrixEventFromChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) (id.RoomID, id.EventID, error)
	DeleteMatrixEventForChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error
	GetChatwootConversationIDFromMatrixRoom(ctx context.Context, roomID id.RoomID) (chatwootapi.ConversationID, chatwootapi.AccountID, error)
	GetAccountAndInboxIDForConversation(ctx context.Context, roomID id.RoomID) (chatwootapi.AccountID, chatwootapi.InboxID, error)
	UpdateMostRecentEventIDForRoom(ctx context.Context, roomID id.RoomID, eventID id.EventID) error
	// handler.go에서 필요한 추가 메서드
	GetChatwootMessageIDsForMatrixEventID(ctx context.Context, eventID id.EventID) ([]chatwootapi.MessageID, chatwootapi.AccountID, error)
	// chatwoot/message.go에서 필요한 메서드
	GetMatrixRoomFromChatwootConversation(ctx context.Context, conversationID chatwootapi.ConversationID, accountID chatwootapi.AccountID) (id.RoomID, chatwootapi.AccountID, error)
	StoreMatrixRoomForChatwootConversation(ctx context.Context, roomID id.RoomID, conversationID chatwootapi.ConversationID, accountID chatwootapi.AccountID) error
}

// MessageHelper는 메시지 처리 인터페이스를 정의합니다.
type MessageHelper interface {
	HandleMatrixMessageContent(ctx context.Context, evt *event.Event, conversationID chatwootapi.ConversationID, content *event.MessageEventContent) ([]*chatwootapi.Message, error)
	HandleMatrixReaction(ctx context.Context, evt *event.Event, targetRoomID id.RoomID, targetEventID id.EventID) error
	HandleMatrixRedaction(ctx context.Context, evt *event.Event, targetRoomID id.RoomID, targetEventID id.EventID) error
}

// ConversationManager는 대화 관리 인터페이스를 정의합니다.
type ConversationManager interface {
	GetOrCreateChatwootConversation(ctx context.Context, roomID id.RoomID, evt *event.Event) (chatwootapi.ConversationID, error)
}

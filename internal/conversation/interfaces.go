package conversation

import (
	"context"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// Manager는 Matrix <-> Chatwoot 대화 연결 관리를 위한 인터페이스입니다.
type Manager interface {
	// GetOrCreateChatwootConversation은 Matrix 방에 대응하는 Chatwoot 대화를 검색하거나 생성합니다.
	GetOrCreateChatwootConversation(ctx context.Context, roomID id.RoomID, evt *event.Event) (chatwootapi.ConversationID, error)

	// GetMatrixRoomForChatwootConversation은 Chatwoot 대화에 대응하는 Matrix 방을 검색합니다.
	GetMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) (id.RoomID, id.EventID, error)

	// BackfillConversationForRoom은 Matrix 방에 대화 기록을 백필합니다.
	BackfillConversationForRoom(ctx context.Context, roomID id.RoomID) error
}

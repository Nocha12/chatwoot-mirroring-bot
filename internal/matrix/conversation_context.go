package matrix

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// ConversationContext는 Matrix 이벤트 처리에 필요한 Chatwoot 컨텍스트 정보를 제공합니다.
type ConversationContext struct {
	AccountID      chatwootapi.AccountID
	InboxID        chatwootapi.InboxID
	ConversationID chatwootapi.ConversationID
}

// getEventContext는 Matrix 이벤트에서 대화 컨텍스트를 추출합니다.
func (h *MatrixHandler) getEventContext(ctx context.Context, roomID id.RoomID, evt *event.Event) (*ConversationContext, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "conversation_context").
		Stringer("room_id", roomID).
		Logger()
	ctx = log.WithContext(ctx)

	// 대화 ID 가져오기
	conversationID, err := h.convManager.GetOrCreateChatwootConversation(ctx, roomID, evt)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 대화 ID 가져오기 실패")
		return nil, fmt.Errorf("chatwoot 대화 ID 가져오기 실패: %w", err)
	}

	// 계정 ID와 인박스 ID 가져오기
	accountID, inboxID, err := h.stateStore.GetAccountAndInboxIDForConversation(ctx, roomID)
	if err != nil {
		log.Error().Err(err).Msg("대화를 위한 계정 및 인박스 ID 가져오기 실패")
		return nil, fmt.Errorf("대화를 위한 계정 및 인박스 ID 가져오기 실패: %w", err)
	}

	log.Debug().
		Int("account_id", int(accountID)).
		Int("inbox_id", int(inboxID)).
		Int("conversation_id", int(conversationID)).
		Msg("대화 컨텍스트 생성 완료")

	return &ConversationContext{
		AccountID:      accountID,
		InboxID:        inboxID,
		ConversationID: conversationID,
	}, nil
}

// getChatwootAPI는 주어진 계정 ID에 대한 Chatwoot API 클라이언트를 반환합니다.
func (h *MatrixHandler) getChatwootAPI(accountID chatwootapi.AccountID) (*chatwootapi.Client, error) {
	api, ok := h.chatwootApis[accountID]
	if !ok {
		// 계정 ID가 없으면 기본 계정 사용
		if h.defaultAccID == 0 {
			return nil, fmt.Errorf("유효한 Chatwoot 계정 ID가 없음: %d", accountID)
		}
		
		// 기본 계정에 대한 API 클라이언트 확인
		api, ok = h.chatwootApis[h.defaultAccID]
		if !ok {
			return nil, fmt.Errorf("기본 계정(%d)에 대한 Chatwoot API 클라이언트를 찾을 수 없음", h.defaultAccID)
		}
		
		return api, nil
	}
	
	return api, nil
}

// getChatwootMessageIDs는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID 목록을 반환합니다.
func (h *MatrixHandler) getChatwootMessageIDs(ctx context.Context, eventID id.EventID) ([]chatwootapi.MessageID, chatwootapi.AccountID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_chatwoot_message_ids").
		Stringer("event_id", eventID).
		Logger()
	ctx = log.WithContext(ctx)

	chatwootMsgIDs, accountID, err := h.stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, eventID)
	if err != nil || len(chatwootMsgIDs) == 0 {
		log.Warn().Err(err).Msg("Chatwoot 메시지 ID 조회 실패")
		return nil, 0, fmt.Errorf("chatwoot 메시지 ID 조회 실패: %w", err)
	}
	
	log.Debug().Int("message_count", len(chatwootMsgIDs)).Msg("Chatwoot 메시지 ID 조회 성공")
	return chatwootMsgIDs, accountID, nil
}

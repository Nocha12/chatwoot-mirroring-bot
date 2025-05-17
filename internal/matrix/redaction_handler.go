package matrix

import (
	"context"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
)

// HandleRedaction은 Matrix 리덕션(삭제) 이벤트를 처리합니다.
func (h *MatrixHandler) HandleRedaction(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_redaction").Logger()
	ctx = log.WithContext(ctx)

	// 리덕션 내용 확인
	_, ok := evt.Content.Parsed.(*event.RedactionEventContent)
	if !ok {
		log.Warn().Msg("리덕션 내용 파싱 실패")
		return
	}

	// 삭제 대상 이벤트 ID 확인
	redactedEventID := evt.Redacts
	if redactedEventID == "" {
		log.Warn().Msg("삭제 대상 이벤트 ID 찾기 실패")
		return
	}

	// 대화 컨텍스트 가져오기 (단순화된 방식: 리덕션은 conversationID만 필요)
	conversationID, _, err := h.stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 대화 ID 가져오기 실패")
		return
	}

	// 대화 ID를 기반으로 적절한 계정 ID 가져오기
	accountID, _, err := h.stateStore.GetAccountAndInboxIDForConversation(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("대화를 위한 계정 ID 가져오기 실패")
		return
	}

	// 삭제 대상 이벤트의 Chatwoot 메시지 ID 조회
	chatwootMsgIDs, _, err := h.getChatwootMessageIDs(ctx, redactedEventID)
	if err != nil || len(chatwootMsgIDs) == 0 {
		log.Warn().Err(err).Stringer("redacted_event_id", redactedEventID).Msg("Chatwoot 메시지 ID 조회 실패")
		return
	}
	chatwootMsgID := chatwootMsgIDs[0]

	// Chatwoot API 클라이언트 가져오기
	chatwootAPI, err := h.getChatwootAPI(accountID)
	if err != nil {
		log.Error().Err(err).Int("account_id", int(accountID)).Msg("Chatwoot API 클라이언트 가져오기 실패")
		return
	}

	// Chatwoot 메시지 삭제
	err = chatwootAPI.Messages.DeleteMessage(ctx, conversationID, chatwootMsgID)
	if err != nil {
		log.Error().
			Err(err).
			Int("conversation_id", int(conversationID)).
			Int("chatwoot_message_id", int(chatwootMsgID)).
			Msg("Chatwoot 메시지 삭제 실패")
		return
	}

	log.Info().
		Int("conversation_id", int(conversationID)).
		Int("chatwoot_message_id", int(chatwootMsgID)).
		Msg("Matrix 리덕션 처리 완료 (Chatwoot 메시지 삭제)")
}

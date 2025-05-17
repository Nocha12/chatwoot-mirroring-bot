package matrix

import (
	"context"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
)

// HandleMessage는 Matrix 메시지 이벤트를 처리합니다.
func (h *MatrixHandler) HandleMessage(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_message").Logger()
	ctx = log.WithContext(ctx)

	// 메시지 내용 확인
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok || content.MsgType == "" {
		log.Warn().Msg("메시지 내용 파싱 실패")
		return
	}

	// 자신이 보낸 메시지는 무시
	if evt.Sender == h.client.UserID() {
		log.Debug().Msg("자신이 보낸 메시지 무시")
		return
	}

	// 비어 있는 메시지 무시
	if content.Body == "" {
		log.Debug().Msg("비어 있는 메시지 무시")
		return
	}

	// 대화 컨텍스트 가져오기
	conversationCtx, err := h.getEventContext(ctx, evt.RoomID, evt)
	if err != nil {
		log.Error().Err(err).Msg("대화 컨텍스트 가져오기 실패")
		return
	}

	// 메시지 처리 및 Chatwoot로 전송
	messages, err := h.messageHelper.HandleMatrixMessageContent(
		ctx, 
		evt, 
		conversationCtx.AccountID, 
		conversationCtx.ConversationID, 
		content,
	)
	if err != nil {
		log.Error().Err(err).Msg("Matrix 메시지 처리 실패")
		return
	}

	// 처리된 메시지들을 DB에 저장
	for _, message := range messages {
		err = h.stateStore.StoreMatrixEventToChatwootMessage(
			ctx,
			conversationCtx.AccountID,
			evt.ID,
			message.ID,
		)
		if err != nil {
			log.Error().
				Err(err).
				Int("chatwoot_message_id", int(message.ID)).
				Stringer("matrix_event_id", evt.ID).
				Msg("Matrix 이벤트를 Chatwoot 메시지로 저장 실패")
		}
	}

	log.Info().
		Int("conversation_id", int(conversationCtx.ConversationID)).
		Int("message_count", len(messages)).
		Msg("Matrix 메시지 처리 완료")
}

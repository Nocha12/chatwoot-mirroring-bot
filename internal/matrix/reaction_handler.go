package matrix

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// HandleReaction은 Matrix 리액션 이벤트를 처리합니다.
func (h *MatrixHandler) HandleReaction(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_reaction").Logger()
	ctx = log.WithContext(ctx)

	// 리액션 내용 확인
	content, ok := evt.Content.Parsed.(*event.ReactionEventContent)
	if !ok {
		log.Warn().Msg("리액션 내용 파싱 실패")
		return
	}

	// 대화 컨텍스트 가져오기 (단순화된 방식: 리액션은 conversationID만 필요)
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

	// 리액션이 달린 원본 이벤트 ID에서 Chatwoot 메시지 ID 찾기
	relatesTo := content.RelatesTo
	if relatesTo.EventID == "" {
		log.Warn().Msg("리액션의 관련 이벤트 ID 찾기 실패")
		return
	}

	// 원본 메시지의 Chatwoot 메시지 ID 조회
	chatwootMsgIDs, _, err := h.getChatwootMessageIDs(ctx, relatesTo.EventID)
	if err != nil || len(chatwootMsgIDs) == 0 {
		log.Warn().Err(err).Stringer("relates_to_event_id", relatesTo.EventID).Msg("Chatwoot 메시지 ID 조회 실패")
		return
	}
	chatwootMsgID := chatwootMsgIDs[0]
	log.Debug().Int("chatwoot_msg_id", int(chatwootMsgID)).Msg("리액션 연결할 Chatwoot 메시지 ID 찾음")

	// 이모지 문자열 추출 및 정리
	emoji := strings.TrimPrefix(strings.TrimSuffix(relatesTo.Key, ""), "")

	// Chatwoot API 클라이언트 가져오기
	chatwootAPI, err := h.getChatwootAPI(accountID)
	if err != nil {
		log.Error().Err(err).Int("account_id", int(accountID)).Msg("Chatwoot API 클라이언트 가져오기 실패")
		return
	}

	// Chatwoot에 리액션 메시지 전송
	message := fmt.Sprintf("(reacted with %s)", emoji)
	_, err = chatwootAPI.Messages.SendTextMessage(ctx, conversationID, message, chatwootapi.IncomingMessage)
	if err != nil {
		log.Error().
			Err(err).
			Int("conversation_id", int(conversationID)).
			Str("message", message).
			Msg("Chatwoot에 리액션 메시지 전송 실패")
		return
	}

	log.Info().
		Int("conversation_id", int(conversationID)).
		Str("emoji", emoji).
		Msg("Matrix 리액션 처리 완료")
}

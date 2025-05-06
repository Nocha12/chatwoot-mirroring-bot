package matrix

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// MatrixHandler는 Matrix 이벤트 처리를 위한 구조체입니다.
type MatrixHandler struct {
	client        MatrixClient
	chatwootApis  map[chatwootapi.AccountID]*chatwootapi.Client
	defaultAccID  chatwootapi.AccountID
	stateStore    StateStore
	messageHelper MessageHelper
	convManager   ConversationManager
}

// NewMatrixHandler는 새로운 MatrixHandler 인스턴스를 생성합니다.
func NewMatrixHandler(
	client MatrixClient,
	chatwootApis map[chatwootapi.AccountID]*chatwootapi.Client,
	defaultAccID chatwootapi.AccountID,
	stateStore StateStore,
	messageHelper MessageHelper,
	convManager ConversationManager,
) *MatrixHandler {
	return &MatrixHandler{
		client:        client,
		chatwootApis:  chatwootApis,
		defaultAccID:  defaultAccID,
		stateStore:    stateStore,
		messageHelper: messageHelper,
		convManager:   convManager,
	}
}

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

	// Chatwoot 대화 ID 가져오기
	conversationID, err := h.convManager.GetOrCreateChatwootConversation(ctx, evt.RoomID, evt)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 대화 ID 가져오기 실패")
		return
	}

	// 대화 ID를 기반으로 적절한 계정 ID 가져오기
	accountID, _, err := h.stateStore.GetAccountAndInboxIDForConversation(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("대화를 위한 계정 및 인박스 ID 가져오기 실패")
		return
	}

	// 메시지 처리 및 Chatwoot로 전송
	messages, err := h.messageHelper.HandleMatrixMessageContent(ctx, evt, conversationID, content)
	if err != nil {
		log.Error().Err(err).Msg("Matrix 메시지 처리 실패")
		return
	}

	// 처리된 메시지들을 DB에 저장
	for _, message := range messages {
		err = h.stateStore.StoreMatrixEventToChatwootMessage(
			ctx,
			accountID,
			evt.RoomID,
			evt.ID,
			conversationID,
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
		Int("conversation_id", int(conversationID)).
		Int("message_count", len(messages)).
		Msg("Matrix 메시지 처리 완료")
}

// GetCustomAttrForDevice는 디바이스 정보를 기반으로 커스텀 속성을 반환합니다.
func (h *MatrixHandler) GetCustomAttrForDevice(ctx context.Context, evt *event.Event) (string, string) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_custom_attr_for_device").
		Logger()

	clientType, exists := evt.Content.Raw["com.beeper.origin_client_type"]
	if !exists || clientType == nil {
		log.Debug().Msg("클라이언트 타입 정보 없음")
		return "", ""
	}

	var clientTypeString, clientVersionString string
	if ct, ok := clientType.(string); ok {
		clientTypeString = fmt.Sprintf("%s version", ct)
	} else {
		log.Warn().Msg("클라이언트 타입이 문자열이 아님")
		return "", ""
	}

	clientVersion, exists := evt.Content.Raw["com.beeper.origin_client_version"]
	if !exists && clientVersion == nil {
		log.Debug().Msg("클라이언트 버전 정보 없음")
		return "", ""
	}

	if cv, ok := clientVersion.(string); ok {
		clientVersionString = cv
	} else {
		log.Warn().Msg("클라이언트 버전이 문자열이 아님")
		return "", ""
	}

	log.Debug().
		Str("client_type", clientTypeString).
		Str("client_version", clientVersionString).
		Msg("클라이언트 타입과 버전 정보 확인")
	return clientTypeString, clientVersionString
}

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

	// 대화 ID 가져오기
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
	chatwootMsgIDs, _, err := h.stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, relatesTo.EventID)
	if err != nil || len(chatwootMsgIDs) == 0 {
		log.Warn().Err(err).Stringer("relates_to_event_id", relatesTo.EventID).Msg("Chatwoot 메시지 ID 조회 실패")
		return
	}
	chatwootMsgID := chatwootMsgIDs[0]
	log.Debug().Int("chatwoot_msg_id", int(chatwootMsgID)).Msg("리액션 연결할 Chatwoot 메시지 ID 찾음")

	// 이모지 문자열 추출 및 정리
	emoji := strings.TrimPrefix(strings.TrimSuffix(relatesTo.Key, ""), "")

	// Chatwoot에 리액션 메시지 전송
	message := fmt.Sprintf("(reacted with %s)", emoji)
	_, err = h.chatwootApis[chatwootapi.AccountID(accountID)].SendTextMessage(ctx, conversationID, message, chatwootapi.IncomingMessage)
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

	// 대화 ID 가져오기
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
	chatwootMsgIDs, _, err := h.stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, redactedEventID)
	if err != nil || len(chatwootMsgIDs) == 0 {
		log.Warn().Err(err).Stringer("redacted_event_id", redactedEventID).Msg("Chatwoot 메시지 ID 조회 실패")
		return
	}
	chatwootMsgID := chatwootMsgIDs[0]

	// Chatwoot 메시지 삭제
	err = h.chatwootApis[chatwootapi.AccountID(accountID)].DeleteMessage(ctx, conversationID, chatwootMsgID)
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

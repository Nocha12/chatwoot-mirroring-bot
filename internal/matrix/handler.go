package matrix

import (
	"context"
	"fmt"
	"regexp"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// 이 파일에서는 interfaces.go에 정의된 인터페이스를 사용합니다.

// roomLocks는 방 간 동시 접근을 방지하기 위한 맵입니다.
var roomLocks = make(map[id.RoomID]*sync.Mutex)
var roomLocksLock = sync.Mutex{}

// GetOrCreateRoomLock은 주어진 방 ID에 대한 락을 반환하거나 생성합니다.
func GetOrCreateRoomLock(roomID id.RoomID) *sync.Mutex {
	roomLocksLock.Lock()
	defer roomLocksLock.Unlock()

	if lock, ok := roomLocks[roomID]; ok {
		return lock
	}

	lock := &sync.Mutex{}
	roomLocks[roomID] = lock
	return lock
}

// Handler는 Matrix 이벤트를 처리하는 구조체입니다.
type Handler struct {
	Client        MatrixClient
	ChatwootApis  map[chatwootapi.AccountID]*chatwootapi.Client
	DefaultAccID  chatwootapi.AccountID
	StateStore    StateStore
	ConvManager   ConversationManager
	MessageHelper MessageHelper
}

// NewHandler는 새로운 Handler 인스턴스를 생성합니다.
func NewHandler(
	client MatrixClient,
	chatwootApis map[chatwootapi.AccountID]*chatwootapi.Client,
	defaultAccID chatwootapi.AccountID,
	stateStore StateStore,
	convManager ConversationManager,
	msgHelper MessageHelper,
) *Handler {
	return &Handler{
		Client:        client,
		ChatwootApis:  chatwootApis,
		DefaultAccID:  defaultAccID,
		StateStore:    stateStore,
		ConvManager:   convManager,
		MessageHelper: msgHelper,
	}
}

// rageshakeIssueRegex는 이슈 ID 패턴을 정의합니다.
var rageshakeIssueRegex = regexp.MustCompile(`[A-Z]{1,5}-\d+`)

// HandleMessage는 Matrix 메시지 이벤트를 처리합니다.
func (h *Handler) HandleMessage(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_message").Logger()
	ctx = log.WithContext(ctx)

	// 메시지 내용 확인
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok || content.MsgType == "" {
		log.Warn().Msg("메시지 내용 파싱 실패")
		return
	}

	// 자신이 보낸 메시지는 무시
	if evt.Sender == h.Client.UserID() {
		log.Debug().Msg("자신이 보낸 메시지 무시")
		return
	}

	// 비어 있는 메시지 무시
	if content.Body == "" || content.NewContent != nil {
		log.Debug().Msg("비어 있는 메시지 또는 편집된 메시지 무시")
		return
	}

	// Chatwoot 대화 ID 가져오기
	conversationID, err := h.ConvManager.GetOrCreateChatwootConversation(ctx, evt.RoomID, evt)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 대화 ID 가져오기 실패")
		return
	}

	// 대화 ID를 기반으로 적절한 계정 ID 가져오기
	accountID, inboxID, err := h.StateStore.GetAccountAndInboxIDForConversation(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("대화를 위한 계정 및 인박스 ID 가져오기 실패")
		return
	}
	log = log.With().Int("account_id", int(accountID)).Int("inbox_id", int(inboxID)).Logger()

	// 메시지 처리 및 Chatwoot로 전송
	messages, err := h.MessageHelper.HandleMatrixMessageContent(ctx, evt, conversationID, content)
	if err != nil {
		log.Error().Err(err).Msg("Matrix 메시지 처리 실패")
		return
	}

	// 처리된 메시지들을 DB에 저장
	for _, message := range messages {
		err = h.StateStore.StoreMatrixEventToChatwootMessage(
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

// HandleReaction은 Matrix 리액션 이벤트를 처리합니다.
func (h *Handler) HandleReaction(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_reaction").Logger()
	ctx = log.WithContext(ctx)

	// 리액션 내용 확인
	content, ok := evt.Content.Parsed.(*event.ReactionEventContent)
	if !ok {
		log.Warn().Msg("리액션 내용 파싱 실패")
		return
	}

	// 대화 ID 가져오기
	conversationID, err := h.ConvManager.GetOrCreateChatwootConversation(ctx, evt.RoomID, evt)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 대화 ID 가져오기 실패")
		return
	}

	// 대화 ID를 기반으로 적절한 계정 ID 가져오기
	accountID, _, err := h.StateStore.GetAccountAndInboxIDForConversation(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("대화를 위한 계정 ID 가져오기 실패")
		return
	}

	// 해당 계정의 API 클라이언트 가져오기
	api, ok := h.ChatwootApis[chatwootapi.AccountID(accountID)]
	if !ok {
		log.Warn().Int("account_id", int(accountID)).Msg("계정 ID에 대한 API 클라이언트를 찾을 수 없음, 기본 계정 사용 시도")
		// 기본 계정 API 사용 시도
		api, ok = h.ChatwootApis[h.DefaultAccID]
		if !ok {
			log.Error().Msg("기본 계정 API 클라이언트도 찾을 수 없음")
			return
		}
	}

	// 리액션이 달린 원본 이벤트 ID에서 Chatwoot 메시지 ID 찾기
	relatesTo := content.RelatesTo
	if relatesTo.EventID == "" {
		log.Warn().Msg("리액션의 관련 이벤트 ID 찾기 실패")
		return
	}

	// 원본 메시지의 Chatwoot 메시지 ID 조회
	chatwootMessageIDs, _, err := h.StateStore.GetChatwootMessageIDsForMatrixEventID(ctx, relatesTo.EventID)
	if err != nil {
		log.Error().
			Err(err).
			Stringer("relates_to_event_id", relatesTo.EventID).
			Msg("관련 Chatwoot 메시지 ID 조회 실패")
		return
	}

	if len(chatwootMessageIDs) == 0 {
		log.Warn().Msg("관련 Chatwoot 메시지 없음")
		return
	}

	// 이모지 추출
	emoji := relatesTo.Key
	log.Debug().Str("emoji", emoji).Msg("추출된 리액션 이모지")

	// 첫 번째 관련 메시지에 반응 추가 (Chatwoot API에서 지원하는 경우)
	chatwootMessageID := chatwootMessageIDs[0]

	// TODO: 여기서 Chatwoot API를 통해 반응을 추가하는 로직이 필요합니다.
	// 현재 Chatwoot API에 직접적인 '반응' 기능이 없는 경우 대안을 구현해야 합니다.
	// 예: 개인 메시지로 반응 정보 전송
	// api.AddReaction(ctx, conversationID, chatwootMessageID, emoji)

	// 대신, 개인 메시지로 반응 정보 전송
	reactionMessage := fmt.Sprintf("👤 리액션 추가: %s", emoji)
	_, err = api.SendPrivateMessage(ctx, conversationID, reactionMessage)
	if err != nil {
		log.Error().
			Err(err).
			Int("message_id", int(chatwootMessageID)).
			Str("emoji", emoji).
			Msg("리액션 메시지 전송 실패")
		return
	}

	log.Info().
		Int("conversation_id", int(conversationID)).
		Int("message_id", int(chatwootMessageID)).
		Str("emoji", emoji).
		Msg("Matrix 리액션 처리 완료")
}

// HandleRedaction은 Matrix 리덕션(삭제) 이벤트를 처리합니다.
func (h *Handler) HandleRedaction(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_redaction").Logger()
	ctx = log.WithContext(ctx)

	// 삭제 대상 이벤트 ID 확인
	targetEventID := evt.Redacts
	if targetEventID == "" {
		log.Warn().Msg("삭제 대상 이벤트 ID가 비어있음")
		return
	}

	// 대화 ID 가져오기
	conversationID, _, err := h.StateStore.GetChatwootConversationIDFromMatrixRoom(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 대화 ID 가져오기 실패")
		return
	}

	// 대화 ID를 기반으로 적절한 계정 ID 가져오기
	accountID, _, err := h.StateStore.GetAccountAndInboxIDForConversation(ctx, evt.RoomID)
	if err != nil {
		log.Error().Err(err).Msg("대화를 위한 계정 ID 가져오기 실패")
		return
	}

	// 해당 계정의 API 클라이언트 가져오기
	api, ok := h.ChatwootApis[chatwootapi.AccountID(accountID)]
	if !ok {
		log.Warn().Int("account_id", int(accountID)).Msg("계정 ID에 대한 API 클라이언트를 찾을 수 없음, 기본 계정 사용 시도")
		// 기본 계정 API 사용 시도
		api, ok = h.ChatwootApis[h.DefaultAccID]
		if !ok {
			log.Error().Msg("기본 계정 API 클라이언트도 찾을 수 없음")
			return
		}
	}

	// 대상 이벤트와 연결된 Chatwoot 메시지 ID 찾기
	chatwootMessageIDs, _, err := h.StateStore.GetChatwootMessageIDsForMatrixEventID(ctx, targetEventID)
	if err != nil {
		log.Error().
			Err(err).
			Stringer("target_event_id", targetEventID).
			Msg("관련 Chatwoot 메시지 ID 조회 실패")
		return
	}

	if len(chatwootMessageIDs) == 0 {
		log.Warn().Msg("관련 Chatwoot 메시지 없음")
		return
	}

	// 모든 관련 Chatwoot 메시지 삭제
	var errors []error
	for _, messageID := range chatwootMessageIDs {
		err = api.DeleteMessage(ctx, conversationID, messageID)
		if err != nil {
			errors = append(errors, err)
			log.Error().
				Err(err).
				Int("conversation_id", int(conversationID)).
				Int("message_id", int(messageID)).
				Msg("Chatwoot 메시지 삭제 실패")
		} else {
			log.Info().
				Int("conversation_id", int(conversationID)).
				Int("message_id", int(messageID)).
				Msg("Chatwoot 메시지 삭제 성공")
		}
	}

	if len(errors) > 0 {
		log.Error().
			Int("error_count", len(errors)).
			Msg("일부 Chatwoot 메시지 삭제에 실패했습니다")
	} else {
		log.Info().Msg("모든 관련 Chatwoot 메시지가 성공적으로 삭제되었습니다")
	}
}

// SendMessage는 Matrix 방에 메시지를 전송합니다.
func SendMessage(ctx context.Context, client MatrixClient, roomID id.RoomID, content *event.MessageEventContent, extraContent ...map[string]any) (*mautrix.RespSendEvent, error) {
	log := zerolog.Ctx(ctx).With().Stringer("room_id", roomID).Logger()
	ctx = log.WithContext(ctx)

	wrappedContent := event.Content{Parsed: content}
	if len(extraContent) == 1 {
		wrappedContent.Raw = extraContent[0]
	}

	lock := GetOrCreateRoomLock(roomID)
	lock.Lock()
	defer lock.Unlock()

	resp, err := client.SendMessageEvent(ctx, roomID, event.EventMessage, &wrappedContent)
	if err != nil {
		log.Err(err).Msg("메시지 전송 실패")
		return nil, err
	}

	log.Debug().Stringer("event_id", resp.EventID).Msg("메시지 전송 성공")
	return resp, nil
}

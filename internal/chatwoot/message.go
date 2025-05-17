package chatwoot

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// SendMessage는 Matrix 방에 메시지를 전송하는 함수입니다.
func (h *MessageHandler) SendMessage(ctx context.Context, client *mautrix.Client, roomID id.RoomID, content *event.MessageEventContent, extraContent ...map[string]any) (resp *mautrix.RespSendEvent, err error) {
	lock, ok := h.RoomSendlocks[roomID]
	if !ok {
		lock = &sync.Mutex{}
		h.RoomSendlocks[roomID] = lock
	}

	lock.Lock()
	defer lock.Unlock()

	// content를 기본 맵으로 변환
	mergedContent := map[string]interface{}{
		"msgtype": content.MsgType,
		"body":    content.Body,
	}

	if content.Format != "" {
		mergedContent["format"] = content.Format
	}

	if content.FormattedBody != "" {
		mergedContent["formatted_body"] = content.FormattedBody
	}

	// 추가 컨텐츠 병합
	for _, extra := range extraContent {
		for key, value := range extra {
			mergedContent[key] = value
		}
	}

	return client.SendMessageEvent(ctx, roomID, event.EventMessage, mergedContent)
}

// HandleMessageCreated는 Chatwoot에서 메시지가 생성되었을 때 실행되는 핸들러입니다.
func (h *MessageHandler) HandleMessageCreated(ctx context.Context, mc chatwootapi.MessageCreated) error {
	log := zerolog.Ctx(ctx).With().
		Int("conversation_id", int(mc.Conversation.ID)).
		Int("message_id", int(mc.ID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 메시지 생성 이벤트 처리 시작")

	// 비공개(private) 메시지는 처리하지 않음
	if mc.Private {
		log.Debug().Msg("비공개 메시지 무시")
		return nil
	}

	// 아웃바운드(outgoing) 메시지는 처리하지 않음 (Matrix -> Chatwoot 방향은 이미 처리됨)
	if mc.MessageType == "outgoing" {
		// 메시지 ID가 이미 DB에 있는지 확인
		matrixEventID, err := queries.GetMatrixEventFromChatwootMessage(ctx, h.StateStore.DB, int(mc.Conversation.AccountID), chatwootapi.MessageID(mc.ID))
		if err == nil && matrixEventID != "" {
			log.Debug().Str("matrix_event_id", string(matrixEventID)).Msg("아웃바운드 메시지 연결 정보 찾음, 무시")
			return nil
		} else {
			log.Debug().Err(err).Msg("아웃바운드 메시지지만 Matrix 이벤트 ID 매핑을 찾을 수 없음")
		}
	}

	// 삭제된 메시지인 경우 (Content 필드가 비어있고 ContentAttributes.Deleted = true)
	if mc.Content == "" && mc.ContentAttributes != nil && mc.ContentAttributes.Deleted {
		log.Debug().Msg("삭제된 메시지 감지, Matrix에서도 삭제 처리")
		// DB에서 Matrix 이벤트 ID 조회
		matrixEventID, err := queries.GetMatrixEventFromChatwootMessage(ctx, h.StateStore.DB, int(mc.Conversation.AccountID), chatwootapi.MessageID(mc.ID))
		if err != nil {
			log.Warn().Err(err).Msg("삭제된 메시지에 대한 Matrix 이벤트 ID를 찾을 수 없음")
			return nil
		}

		// Matrix 방 ID 조회
		convID := chatwootapi.ConversationID(mc.Conversation.ID)
		accountID := chatwootapi.AccountID(mc.Conversation.AccountID)
		roomID, _, err := h.StateStore.GetMatrixRoomFromChatwootConversation(ctx, convID, accountID)
		if err != nil {
			log.Warn().Err(err).Msg("Chatwoot 대화에 대한 Matrix 방을 찾을 수 없음")
			return nil
		}

		matrixClient := h.GetMatrixClient(chatwootapi.AccountID(mc.Conversation.AccountID), chatwootapi.InboxID(mc.Conversation.InboxID))
		if matrixClient == nil {
			log.Error().Msg("Matrix 클라이언트를 찾을 수 없습니다")
			return fmt.Errorf("matrix client not found")
		}
		// Matrix에서 메시지 삭제 (redact)
		_, err = matrixClient.RedactEvent(ctx, roomID, matrixEventID)
		if err != nil {
			log.Error().Err(err).Msg("Matrix 메시지 삭제 실패")
			return err
		}

		// DB에서도 매핑 정보 삭제
		// err = queries.DeleteMatrixEventForChatwootMessage(ctx, h.StateStore.DB, chatwootapi.AccountID(mc.Conversation.AccountID), chatwootapi.ConversationID(mc.Conversation.ID), chatwootapi.MessageID(mc.ID))
		// if err != nil {
		// 	log.Warn().Err(err).Msg("DB에서 메시지 매핑 정보 삭제 실패")
		// }

		log.Info().Str("matrix_event_id", string(matrixEventID)).Msg("Matrix 메시지 삭제 완료")
		return nil
	}

	// 대화 상태 확인 및 처리
	convID := chatwootapi.ConversationID(mc.Conversation.ID)
	accountID := chatwootapi.AccountID(mc.Conversation.AccountID)
	roomID, _, err := h.StateStore.GetMatrixRoomFromChatwootConversation(ctx, convID, accountID)
	if err != nil {
		log.Warn().Err(err).Msg("Chatwoot 대화에 대한 Matrix 방을 찾을 수 없음")
		// TODO: 방이 없는 경우 새로 생성하는 로직 추가 가능
		return err
	}

	matrixClient := h.GetMatrixClient(accountID, chatwootapi.InboxID(mc.Conversation.InboxID))
	if matrixClient == nil {
		log.Error().Msg("Matrix 클라이언트를 찾을 수 없습니다")
		return fmt.Errorf("matrix client not found")
	}

	// 방 존재 여부 검증
	exists, err := h.validateRoomExists(ctx, matrixClient, roomID)
	if err != nil {
		log.Error().Err(err).Msg("방 존재 여부 확인 실패")
		return err
	}
	if !exists {
		log.Warn().Msg("Matrix 방이 존재하지 않음")
		return fmt.Errorf("matrix 방 %s이(가) 존재하지 않음", roomID)
	}

	// 메시지 내용 준비
	msgContent := &event.MessageEventContent{
		MsgType: event.MsgText,
		Body:    mc.Content, // 기본 텍스트
	}

	// HTML 형식이 있다면 처리
	if mc.ContentType == "text" {
		// Matrix HTML 형식으로 변환
		formattedBody := mc.Content
		// 간단한 마크다운 -> HTML 변환 (실제로는 더 복잡한 변환 로직이 필요할 수 있음)
		formattedBody = strings.ReplaceAll(formattedBody, "\n", "<br>")
		msgContent.Format = event.FormatHTML
		msgContent.FormattedBody = formattedBody
	}

	// 첨부파일 처리
	var sentEvent *mautrix.RespSendEvent
	if mc.ContentAttributes != nil && mc.ContentAttributes.Attachments != nil && len(mc.ContentAttributes.Attachments) > 0 {
		log.Debug().Int("attachment_count", len(mc.ContentAttributes.Attachments)).Msg("첨부파일 처리 시작")

		// 첫 번째 첨부파일만 처리 (여러 개 있을 경우 나머지는 추가 메시지로 전송 가능)
		attachment := mc.ContentAttributes.Attachments[0]
		sentEvent, err = h.handleAttachment(ctx, roomID, chatwootapi.AccountID(mc.Conversation.AccountID), chatwootapi.InboxID(mc.Conversation.InboxID), mc.ID, attachment)
		if err != nil {
			log.Error().Err(err).Msg("첨부파일 처리 실패")
			// 첨부파일 처리 실패시에도 텍스트 메시지는 보낼 수 있도록 진행
		} else {
			// 첨부파일이 성공적으로 전송된 경우, 텍스트가 없으면 텍스트 메시지 전송 불필요
			if mc.Content == "" {
				// 첨부파일만 있는 경우 DB에 매핑 저장 후 종료
				err = queries.StoreMatrixEventForChatwootMessage(ctx, h.StateStore.DB, int(mc.Conversation.AccountID), chatwootapi.MessageID(mc.ID), sentEvent.EventID)
				if err != nil {
					log.Warn().Err(err).Msg("DB에 메시지 매핑 저장 실패")
				}
				return nil
			}
		}
	}

	// 텍스트 메시지 전송 (첨부파일이 없거나, 첨부파일과 텍스트가 모두 있는 경우)
	if sentEvent == nil || mc.Content != "" {
		sentEvent, err = h.SendMessage(ctx, matrixClient, roomID, msgContent)
		if err != nil {
			log.Error().Err(err).Msg("Matrix 메시지 전송 실패")
			return err
		}
	}

	// 메시지 매핑 저장 (DB에 이벤트 ID와 Chatwoot 메시지 ID 매핑)
	err = queries.StoreMatrixEventForChatwootMessage(ctx, h.StateStore.DB, int(mc.Conversation.AccountID), chatwootapi.MessageID(mc.ID), sentEvent.EventID)
	if err != nil {
		log.Warn().Err(err).Msg("DB에 메시지 매핑 저장 실패")
	}

	log.Info().Str("matrix_event_id", string(sentEvent.EventID)).Msg("Matrix 메시지 전송 완료")
	return nil
}

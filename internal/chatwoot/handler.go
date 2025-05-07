package chatwoot

import (
	"bytes"
	"context"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// MessageHandler는 Chatwoot 메시지 이벤트를 처리하는 구조체입니다.
type MessageHandler struct {
	// 의존성 주입을 위한 필드들
	Client        *mautrix.Client
	StateStore    *database.Database
	ChatwootAPIs  map[chatwootapi.AccountID]*chatwootapi.Client
	GetAPI        func(accountID chatwootapi.AccountID) *chatwootapi.Client
	RoomSendlocks map[id.RoomID]*sync.Mutex
}

// NewMessageHandler는 새로운 MessageHandler 인스턴스를 생성합니다.
func NewMessageHandler(
	client *mautrix.Client,
	stateStore *database.Database,
	chatwootAPIs map[chatwootapi.AccountID]*chatwootapi.Client,
	getAPIFunc func(accountID chatwootapi.AccountID) *chatwootapi.Client,
	roomSendlocks map[id.RoomID]*sync.Mutex,
) *MessageHandler {
	return &MessageHandler{
		Client:        client,
		StateStore:    stateStore,
		ChatwootAPIs:  chatwootAPIs,
		GetAPI:        getAPIFunc,
		RoomSendlocks: roomSendlocks,
	}
}

// SendMessage는 Matrix 방에 메시지를 전송하는 함수입니다.
func (h *MessageHandler) SendMessage(ctx context.Context, roomID id.RoomID, content *event.MessageEventContent, extraContent ...map[string]any) (resp *mautrix.RespSendEvent, err error) {
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

	return h.Client.SendMessageEvent(ctx, roomID, event.EventMessage, mergedContent)
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

		// Matrix에서 메시지 삭제 (redact)
		_, err = h.Client.RedactEvent(ctx, roomID, matrixEventID)
		if err != nil {
			log.Error().Err(err).Msg("Matrix 메시지 삭제 실패")
			return err
		}

		// DB에서도 매핑 정보 삭제
		err = queries.DeleteMatrixEventForChatwootMessage(ctx, h.StateStore.DB, chatwootapi.AccountID(mc.Conversation.AccountID), chatwootapi.ConversationID(mc.Conversation.ID), chatwootapi.MessageID(mc.ID))
		if err != nil {
			log.Warn().Err(err).Msg("DB에서 메시지 매핑 정보 삭제 실패")
		}

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

	// 방 존재 여부 검증
	exists, err := h.validateRoomExists(ctx, roomID)
	if err != nil {
		log.Error().Err(err).Msg("방 존재 여부 확인 실패")
		return err
	}
	if !exists {
		log.Warn().Msg("Matrix 방이 존재하지 않음")
		return fmt.Errorf("Matrix 방 %s이(가) 존재하지 않음", roomID)
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
		sentEvent, err = h.handleAttachment(ctx, roomID, mc.ID, attachment)
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
		sentEvent, err = h.SendMessage(ctx, roomID, msgContent)
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

// validateRoomExists는 Matrix 방이 존재하는지 확인하는 함수입니다.
func (h *MessageHandler) validateRoomExists(ctx context.Context, roomID id.RoomID) (bool, error) {
	log := zerolog.Ctx(ctx)
	log.Debug().Stringer("room_id", roomID).Msg("방 존재 여부 확인")

	// 방의 암호화 상태 확인
	var encState *event.EncryptionEventContent
	err := h.Client.StateEvent(ctx, roomID, event.StateEncryption, "", &encState)
	if err != nil {
		// 404 오류면 방이 없거나 액세스할 수 없는 것
		// 403 오류면 액세스할 수 없는 것 (초대되지 않음)
		httpErr, ok := err.(mautrix.HTTPError)
		if ok && (httpErr.RespError.ErrCode == "M_NOT_FOUND" || httpErr.RespError.ErrCode == "M_FORBIDDEN") {
			log.Debug().Err(err).Str("error_code", httpErr.RespError.ErrCode).Msg("방이 존재하지 않거나 액세스할 수 없음")

			// 방에 참여 시도
			_, joinErr := h.Client.JoinRoomByID(ctx, roomID)
			if joinErr != nil {
				log.Warn().Err(joinErr).Msg("방 참여 시도 실패")
				return false, nil
			}

			log.Info().Msg("방에 성공적으로 참여함")
			return true, nil
		}

		// 다른 오류는 서버 문제일 수 있음
		log.Error().Err(err).Msg("방 상태 확인 중 오류 발생")
		return false, err
	}

	// 방 존재함
	log.Debug().Msg("방이 존재하며 액세스 가능")
	return true, nil
}

// handleAttachment는 Chatwoot 첨부파일을 처리하여 Matrix에 전송하는 함수입니다.
func (h *MessageHandler) handleAttachment(ctx context.Context, roomID id.RoomID, chatwootMessageID chatwootapi.MessageID, chatwootAttachment chatwootapi.Attachment) (*mautrix.RespSendEvent, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_attachment").
		Int("attachment_id", int(chatwootAttachment.ID)).
		Int("account_id", int(chatwootAttachment.AccountID)).
		Str("file_type", chatwootAttachment.FileType).
		Logger()
	ctx = log.WithContext(ctx)

	// Chatwoot API 클라이언트 가져오기
	api := h.GetAPI(chatwootapi.AccountID(chatwootAttachment.AccountID))

	// 첨부파일 다운로드
	log.Debug().Str("data_url", chatwootAttachment.DataURL).Msg("첨부파일 다운로드 시작")
	attachmentData, err := api.DownloadAttachment(ctx, chatwootAttachment.DataURL)
	if err != nil {
		log.Error().Err(err).Msg("첨부파일 다운로드 실패")
		return nil, err
	}
	log.Debug().Int("file_size", len(attachmentData)).Msg("첨부파일 다운로드 완료")

	// 파일 타입에 따른 처리
	var fileName string
	fileType := chatwootAttachment.FileType

	// 확장자 추출
	if path := strings.Split(chatwootAttachment.DataURL, "/"); len(path) > 0 {
		fileName = path[len(path)-1] // URL의 마지막 부분을 파일명으로 사용
	}

	if fileName == "" {
		fileName = fmt.Sprintf("attachment-%d", chatwootAttachment.ID)
	}

	// MIME 타입에 따른 메시지 타입 결정
	msgType := event.MsgFile // 기본은 파일
	var width, height int

	if strings.HasPrefix(fileType, "image/") {
		msgType = event.MsgImage

		// 이미지 크기 가져오기 시도
		if img, _, err := image.DecodeConfig(bytes.NewReader(attachmentData)); err == nil {
			width = img.Width
			height = img.Height
			log.Debug().Int("width", width).Int("height", height).Msg("이미지 크기 가져옴")
		}
	} else if strings.HasPrefix(fileType, "video/") {
		msgType = event.MsgVideo
	} else if strings.HasPrefix(fileType, "audio/") {
		msgType = event.MsgAudio
	}

	// 파일 업로드
	uploadResp, err := h.Client.UploadBytes(ctx, attachmentData, fileType)
	if err != nil {
		log.Error().Err(err).Msg("Matrix 미디어 업로드 실패")
		return nil, err
	}
	contentURI := uploadResp.ContentURI
	log.Debug().Str("mxc_url", contentURI.String()).Msg("Matrix 미디어 업로드 완료")

	// 메시지 내용 준비
	content := &event.MessageEventContent{
		MsgType: msgType,
		Body:    fileName,
	}

	// URL 업로드 결과 설정
	content.URL = contentURI.CUString()

	// 파일 정보 추가
	content.Info = &event.FileInfo{
		MimeType: fileType,
		Size:     chatwootAttachment.FileSize,
	}

	// 이미지 크기 정보 추가
	if width > 0 && height > 0 {
		content.Info.Width = width
		content.Info.Height = height
	}

	// 메시지 전송
	sentEvent, err := h.SendMessage(ctx, roomID, content)
	if err != nil {
		log.Error().Err(err).Msg("첨부파일 메시지 전송 실패")
		return nil, err
	}

	log.Info().Str("event_id", string(sentEvent.EventID)).Msg("첨부파일 메시지 전송 완료")
	return sentEvent, nil
}

package matrix

import (
	"bytes"
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// MessageHelperImpl은 MessageHelper 인터페이스를 구현하는 구조체입니다.
type MessageHelperImpl struct {
	Client         *mautrix.Client
	GetAPIFunc     func(accountID chatwootapi.AccountID) *chatwootapi.Client
	RenderMarkdown bool
}

// NewMessageHelper는 새로운 MessageHelperImpl 인스턴스를 생성합니다.
func NewMessageHelper(
	client *mautrix.Client,
	getAPIFunc func(accountID chatwootapi.AccountID) *chatwootapi.Client,
	renderMarkdown bool,
) *MessageHelperImpl {
	return &MessageHelperImpl{
		Client:         client,
		GetAPIFunc:     getAPIFunc,
		RenderMarkdown: renderMarkdown,
	}
}

// HandleMatrixMessageContent 함수는 Matrix 메시지 내용을 처리하여 Chatwoot로 전송합니다
func (h *MessageHelperImpl) HandleMatrixMessageContent(ctx context.Context, evt *event.Event, conversationID chatwootapi.ConversationID, content *event.MessageEventContent) ([]*chatwootapi.Message, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_matrix_message_content").
		Int("conversation_id", int(conversationID)).
		Stringer("event_id", evt.ID).
		Logger()
	ctx = log.WithContext(ctx)

	accountID, _, err := h.getAccountAndInboxForConversation(ctx, conversationID)
	if err != nil {
		return nil, err
	}
	api := h.GetAPIFunc(accountID)

	// 메시지 타입에 따른 처리
	switch content.MsgType {
	case event.MsgText, event.MsgNotice, event.MsgEmote:
		// 텍스트 메시지 처리
		messageBody := content.Body
		if content.MsgType == event.MsgEmote {
			// /me 형식의 메시지는 "* 사용자 메시지" 형태로 변환
			messageBody = fmt.Sprintf("* %s", messageBody)
		}

		// HTML 형식 지원
		// 나중에 HTML 형식을 처리할 수도 있으니 로그로 기록
		if content.Format == event.FormatHTML && content.FormattedBody != "" {
			log.Debug().Str("formatted_body", content.FormattedBody).Msg("포매팅된 HTML 메시지 수신")
		}

		// 메시지 송신
		message := chatwootapi.NewMessage{
			Content:     messageBody,
			MessageType: "incoming",
		}

		// 필요시 HTML 형식 처리 로직 추가
		// ...

		sentMessage, err := api.SendTextMessage(ctx, conversationID, message.Content, chatwootapi.IncomingMessage)
		if err != nil {
			log.Error().Err(err).Msg("Chatwoot 메시지 생성 실패")
			return nil, err
		}

		return []*chatwootapi.Message{sentMessage}, nil

	case event.MsgImage, event.MsgVideo, event.MsgAudio, event.MsgFile:
		// 미디어 메시지 타입 결정
		var mediaType string
		switch content.MsgType {
		case event.MsgImage:
			mediaType = "image"
		case event.MsgVideo:
			mediaType = "video"
		case event.MsgAudio:
			mediaType = "audio"
		default:
			mediaType = "file"
		}

		// 미디어 메시지 처리
		return h.handleMediaMessage(ctx, evt, conversationID, content, mediaType, "incoming")

	default:
		log.Warn().Str("msg_type", string(content.MsgType)).Msg("지원되지 않는 메시지 타입")
		return nil, fmt.Errorf("지원되지 않는 메시지 타입: %s", content.MsgType)
	}
}

// handleMediaMessage는 미디어 메시지를 처리합니다 (이미지, 비디오, 오디오, 파일)
func (h *MessageHelperImpl) handleMediaMessage(ctx context.Context, evt *event.Event, conversationID chatwootapi.ConversationID, content *event.MessageEventContent, mediaType string, messageType chatwootapi.MessageType) ([]*chatwootapi.Message, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_media_message").
		Int("conversation_id", int(conversationID)).
		Str("media_type", mediaType).
		Logger()
	ctx = log.WithContext(ctx)

	// 미디어 다운로드 및 복호화
	mediaData, err := h.downloadAndDecryptMedia(ctx, content)
	if err != nil {
		log.Error().Err(err).Msg("미디어 다운로드 및 복호화 실패")
		return nil, err
	}

	// 파일 이름 및 MIME 타입 결정
	fileName := content.Body
	var mimeType string
	if content.Info != nil && content.Info.MimeType != "" {
		mimeType = content.Info.MimeType
	} else {
		// MIME 타입 추측 로직
		switch mediaType {
		case "image":
			mimeType = "image/jpeg" // 기본값
		case "video":
			mimeType = "video/mp4"
		case "audio":
			mimeType = "audio/mpeg"
		default:
			mimeType = "application/octet-stream"
		}
	}

	// Chatwoot API 클라이언트 가져오기
	accountID, _, err := h.getAccountAndInboxForConversation(ctx, conversationID)
	if err != nil {
		return nil, err
	}
	api := h.GetAPIFunc(accountID)

	// 첨부파일 메시지 전송
	sentMessage, err := api.SendAttachmentMessage(ctx, conversationID, fileName, mimeType, bytes.NewReader(mediaData), chatwootapi.IncomingMessage)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 첨부파일 업로드 실패")
		return nil, err
	}
	log.Debug().Int("message_id", int(sentMessage.ID)).Msg("첨부파일 메시지 전송 성공")

	// 첨부파일 메시지를 이미 전송했으므로 추가적인 텍스트 메시지는 필요 없음
	// 필요시 파일 관련 추가 설명이 있을 경우 별도 처리 로직 추가
	log.Debug().Str("description", content.Body).Msg("첨부파일 설명")

	return []*chatwootapi.Message{sentMessage}, nil
}

// HandleMatrixReaction은 Matrix 리액션 이벤트를 처리합니다.
func (h *MessageHelperImpl) HandleMatrixReaction(ctx context.Context, evt *event.Event, targetRoomID id.RoomID, targetEventID id.EventID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_matrix_reaction").
		Stringer("event_id", evt.ID).
		Stringer("target_event_id", targetEventID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix 리액션 처리 준비 중")
	// TODO: 리액션 처리 로직 구현
	log.Info().Msg("리액션 처리 기능은 아직 구현되지 않았습니다")
	return nil
}

// HandleMatrixRedaction은 Matrix 리덕션(삭제) 이벤트를 처리합니다.
func (h *MessageHelperImpl) HandleMatrixRedaction(ctx context.Context, evt *event.Event, targetRoomID id.RoomID, targetEventID id.EventID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_matrix_redaction").
		Stringer("event_id", evt.ID).
		Stringer("target_event_id", targetEventID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Matrix 리덕션 처리 준비 중")
	// TODO: 리덕션 처리 로직 구현
	log.Info().Msg("리덕션 처리 기능은 아직 구현되지 않았습니다")
	return nil
}

// downloadAndDecryptMedia는 Matrix 미디어를 다운로드하고 필요시 복호화합니다.
func (h *MessageHelperImpl) downloadAndDecryptMedia(ctx context.Context, content *event.MessageEventContent) ([]byte, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "download_and_decrypt_media").
		Logger()

	var data []byte

	// 암호화된 파일 처리
	if content.File != nil && content.File.URL != "" {
		// 암호화된 데이터 다운로드
		contentURL, err := content.File.URL.Parse()
		if err != nil {
			log.Error().Err(err).Msg("컨텐츠 URL 파싱 실패")
			return nil, err
		}
		data, err = h.downloadMedia(ctx, contentURL)
		if err != nil {
			return nil, err
		}

		// 복호화
		// 최신 mautrix 라이브러리에서는 EncryptedFile에 직접 Decrypt 메서드 사용
		data, err = content.File.EncryptedFile.Decrypt(data)
		if err != nil {
			log.Error().Err(err).Msg("파일 복호화 실패")
			return nil, err
		}
	} else if content.URL != "" {
		// 암호화되지 않은 파일 다운로드
		contentURL, err := content.URL.Parse()
		if err != nil {
			log.Error().Err(err).Msg("컨텐츠 URL 파싱 실패")
			return nil, err
		}

		data, err = h.downloadMedia(ctx, contentURL)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("다운로드할 URL이 없음")
	}

	return data, nil
}

// downloadMedia는 Matrix 미디어 URL에서 데이터를 다운로드합니다.
func (h *MessageHelperImpl) downloadMedia(ctx context.Context, uri id.ContentURI) ([]byte, error) {
	log := zerolog.Ctx(ctx)
	log.Debug().Str("uri", uri.String()).Msg("미디어 다운로드 시작")

	// Matrix 클라이언트를 통해 다운로드
	data, err := h.Client.DownloadBytes(ctx, uri)
	if err != nil {
		log.Error().Err(err).Str("uri", uri.String()).Msg("미디어 다운로드 실패")
		return nil, err
	}

	log.Debug().Int("size", len(data)).Msg("미디어 다운로드 완료")
	return data, nil
}

// getAccountAndInboxForConversation은 대화 ID에 대한 계정 ID와 인박스 ID를 반환합니다.
func (h *MessageHelperImpl) getAccountAndInboxForConversation(ctx context.Context, conversationID chatwootapi.ConversationID) (chatwootapi.AccountID, chatwootapi.InboxID, error) {
	// 실제 구현에서는 DB 또는 다른 소스에서 계정 및 인박스 정보를 가져와야 합니다.
	// 현재는 간단한 예시로 더미 값을 반환합니다.
	return chatwootapi.AccountID(1), chatwootapi.InboxID(1), nil
}

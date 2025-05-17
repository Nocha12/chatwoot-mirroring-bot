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

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

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

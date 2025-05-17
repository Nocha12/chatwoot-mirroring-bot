package chatwootapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

// MessagesAPI는 Chatwoot Message API 엔드포인트와 상호작용하는 메서드를 그룹화합니다.
type MessagesAPI struct {
	client *Client // 부모 Client 구조체에 대한 참조
}

// SendMessageRequestPayload는 메시지 전송 API 요청 페이로드입니다.
type SendMessageRequestPayload struct {
	Content     string      `json:"content,omitempty"`
	Private     bool        `json:"private,omitempty"`
	MessageType MessageType `json:"message_type,omitempty"`
}

// doSendTextMessage는 내부적으로 텍스트 메시지를 전송하기 위한 공통 로직을 구현합니다.
// 이 함수 자체도 doAPIRequest를 사용하도록 수정합니다.
func (api *MessagesAPI) doSendTextMessage(ctx context.Context, conversationID ConversationID, payload SendMessageRequestPayload) (*Message, error) {
	log := zerolog.Ctx(ctx).With().
		Int("conversation_id", int(conversationID)).
		Logger()

	log.Debug().Msg("텍스트 메시지 전송 중 (내부)")

	// 요청 페이로드 준비 (구조체 사용)
	jsonValue, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Msg("메시지 페이로드 마샬링 실패")
		return nil, fmt.Errorf("메시지 페이로드 마샬링 실패: %w", err)
	}

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	var message Message
	err = api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodPost,
		fmt.Sprintf("conversations/%d/messages", conversationID),
		nil, // 쿼리 파라미터 없음
		bytes.NewBuffer(jsonValue),
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		&message,
	)
	if err != nil {
		log.Err(err).Msg("텍스트 메시지 전송 API 요청 실패")
		return nil, fmt.Errorf("텍스트 메시지 전송 API 요청 실패: %w", err)
	}

	return &message, nil
}

// SendTextMessage는 텍스트 메시지를 전송합니다.
func (api *MessagesAPI) SendTextMessage(ctx context.Context, conversationID ConversationID, content string, messageType MessageType) (*Message, error) {
	payload := SendMessageRequestPayload{
		Content:     content,
		MessageType: messageType,
	}
	return api.doSendTextMessage(ctx, conversationID, payload) // 동일 API 그룹 내 메서드 호출
}

// SendPrivateMessage는 대화에 비공개 메시지를 전송합니다.
func (api *MessagesAPI) SendPrivateMessage(ctx context.Context, conversationID ConversationID, message string) (*Message, error) {
	payload := SendMessageRequestPayload{
		Content: message,
		Private: true,
	}
	return api.doSendTextMessage(ctx, conversationID, payload) // 동일 API 그룹 내 메서드 호출
}

// createAttachmentMultipartBody는 첨부파일 메시지 전송을 위한 멀티파트 폼 데이터를 생성합니다.
func (api *MessagesAPI) createAttachmentMultipartBody(filename string, mimeType string, fileData io.Reader, messageType MessageType) (io.Reader, string, error) {
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// messageType 필드 추가
	if err := writer.WriteField("message_type", string(messageType)); err != nil {
		return nil, "", fmt.Errorf("message_type 필드 작성 실패: %w", err)
	}

	// 첨부파일 필드 추가
	// 파일 필드의 헤더 생성
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="attachments[]"; filename="%s"`, api.client.escapeQuotes(filename))) // 부모 클라이언트의 헬퍼 메서드 호출
	header.Set("Content-Type", mimeType)

	// 파일 데이터 파트 생성
	part, err := writer.CreatePart(header)
	if err != nil {
		return nil, "", fmt.Errorf("첨부파일 파트 생성 실패: %w", err)
	}

	// 파일 데이터를 파트에 복사
	if _, err = io.Copy(part, fileData); err != nil {
		return nil, "", fmt.Errorf("파일 데이터 복사 실패: %w", err)
	}

	// form 완료
	err = writer.Close()
	if err != nil {
		return nil, "", fmt.Errorf("multipart 폼 완료 실패: %w", err)
	}

	return &b, writer.FormDataContentType(), nil
}

// SendAttachmentMessage는 첨부파일이 있는 메시지를 전송합니다.
func (api *MessagesAPI) SendAttachmentMessage(ctx context.Context, conversationID ConversationID, filename string, mimeType string, fileData io.Reader, messageType MessageType) (*Message, error) {
	log := zerolog.Ctx(ctx).With().
		Int("conversation_id", int(conversationID)).
		Str("filename", filename).
		Str("mime_type", mimeType).
		Str("message_type", string(messageType)).
		Logger()

	log.Info().Msg("첨부파일 메시지 전송 중")

	// 멀티파트 본문 생성
	body, contentType, err := api.createAttachmentMultipartBody(filename, mimeType, fileData, messageType) // 동일 API 그룹 내 메서드 호출
	if err != nil {
		log.Err(err).Msg("멀티파트 본문 생성 실패")
		return nil, fmt.Errorf("멀티파트 본문 생성 실패: %w", err)
	}

	// doMultipartAPIRequest를 사용하여 요청 실행 및 응답 처리
	var message Message
	err = api.client.doMultipartAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodPost,
		fmt.Sprintf("conversations/%d/messages", conversationID),
		body,
		contentType,
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		&message,
	)
	if err != nil {
		log.Err(err).Msg("첨부파일 메시지 전송 API 요청 실패")
		return nil, fmt.Errorf("첨부파일 메시지 전송 API 요청 실패: %w", err)
	}

	log.Info().Int("message_id", int(message.ID)).Msg("첨부파일 메시지 전송 성공")
	return &message, nil
}

// DeleteMessage는 Chatwoot 메시지를 삭제합니다.
func (api *MessagesAPI) DeleteMessage(ctx context.Context, conversationID ConversationID, messageID MessageID) error {
	log := zerolog.Ctx(ctx).With().
		Int("conversation_id", int(conversationID)).
		Int("message_id", int(messageID)).
		Logger()

	log.Info().Msg("메시지 삭제 중")

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	err := api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodDelete,
		fmt.Sprintf("conversations/%d/messages/%d", conversationID, messageID),
		nil,                  // 쿼리 파라미터 없음
		nil,                  // DELETE 요청은 본문 없음
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		nil,                  // 응답 결과 필요 없음
	)
	if err != nil {
		log.Err(err).Msg("메시지 삭제 API 요청 실패")
		return fmt.Errorf("메시지 삭제 API 요청 실패: %w", err)
	}

	return nil
}

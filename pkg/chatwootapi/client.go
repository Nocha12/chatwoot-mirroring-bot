package chatwootapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
)

// 메시지 유형 상수
type MessageType string

const (
	IncomingMessage MessageType = "incoming"
	OutgoingMessage MessageType = "outgoing"
)

// 대화 상태 상수
type ConversationStatus string

const (
	ConversationStatusOpen     ConversationStatus = "open"
	ConversationStatusResolved ConversationStatus = "resolved"
	ConversationStatusPending  ConversationStatus = "pending"
)

// Client는 Chatwoot API와 상호작용하기 위한 클라이언트 구조체입니다.
type Client struct {
	BaseURL     string
	AccountID   AccountID
	InboxID     InboxID
	AccessToken string

	HttpClient *http.Client
}

// NewClient는 새로운 Chatwoot API 클라이언트를 생성합니다.
func NewClient(baseURL string, accountID AccountID, inboxID InboxID, accessToken string) *Client {
	return &Client{
		BaseURL:     baseURL,
		AccountID:   accountID,
		InboxID:     inboxID,
		AccessToken: accessToken,
		HttpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("too many (>=10) redirects, cancelling request")
				}
				if len(via) > 0 {
					for key, values := range via[len(via)-1].Header {
						req.Header[key] = values
					}
				}
				return nil
			},
		},
	}
}

// DoRequest는 HTTP 요청을 실행합니다.
func (c *Client) DoRequest(req *http.Request) (*http.Response, error) {
	req.Header.Add("Api-Access-Token", c.AccessToken)
	return c.HttpClient.Do(req)
}

// MakeURI는 Chatwoot API 엔드포인트 URI를 생성합니다.
func (c *Client) MakeURI(endpoint string) string {
	url, err := url.Parse(c.BaseURL)
	if err != nil {
		panic(err)
	}
	url.Path = path.Join(url.Path, fmt.Sprintf("api/v1/accounts/%d", c.AccountID), endpoint)
	return url.String()
}

// CreateContact는 Chatwoot에 새로운 연락처를 생성합니다.
func (c *Client) CreateContact(ctx context.Context, userID id.UserID, name string) (ContactID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("user_id", userID.String()).
		Str("name", name).
		Logger()

	if name == "" {
		name = userID.String()
		if userID.Homeserver() == "beeper.local" && strings.HasPrefix(userID.Localpart(), "imessagego_1.") {
			decoded, err := id.DecodeUserLocalpart(strings.TrimPrefix(userID.Localpart(), "imessagego_1."))
			if err == nil {
				name = decoded
			}
		}
	}

	log.Info().Str("name", name).Msg("연락처 생성 중")
	payload := map[string]interface{}{
		"inbox_id":   c.InboxID,
		"name":       name,
		"identifier": userID.String(),
	}
	jsonValue, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MakeURI("contacts"), bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Err(err).Msg("요청 생성 실패")
		return 0, fmt.Errorf("요청 생성 실패: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.DoRequest(req)
	if err != nil {
		log.Err(err).Msg("요청 실패")
		return 0, fmt.Errorf("요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err == nil {
			log.Error().Str("data", string(data)).Msg("200이 아닌 상태 코드 받음")
		}
		return 0, fmt.Errorf("POST contacts 반환값이 200이 아님: %d", resp.StatusCode)
	}

	var contactPayload struct {
		Payload struct {
			Contact struct {
				ID ContactID `json:"id"`
			} `json:"contact"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&contactPayload); err != nil {
		return 0, fmt.Errorf("응답 본문 디코딩 실패: %w", err)
	}

	log.Debug().Any("contact_payload", contactPayload).Msg("연락처 페이로드 받음")
	return contactPayload.Payload.Contact.ID, nil
}

// ContactIDForMXID는 Matrix ID를 이용해 Chatwoot 연락처 ID를 찾습니다.
func (c *Client) ContactIDForMXID(ctx context.Context, userID id.UserID) (ContactID, error) {
	log := zerolog.Ctx(ctx)
	query := userID.String()
	if userID.Homeserver() == "beeper.local" {
		// 브릿지된 iMessage에 대한 특별 처리
		if strings.HasPrefix(userID.Localpart(), "imessagego_1.") {
			decoded, err := id.DecodeUserLocalpart(strings.TrimPrefix(userID.Localpart(), "imessagego_1."))
			if err == nil {
				query = decoded
			}
		}
	}

	log.Info().Str("query", query).Msg("연락처 검색")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MakeURI("contacts/search"), nil)
	if err != nil {
		return 0, fmt.Errorf("검색 요청 생성 실패: %w", err)
	}

	q := req.URL.Query()
	q.Add("q", query)
	req.URL.RawQuery = q.Encode()

	resp, err := c.DoRequest(req)
	if err != nil {
		return 0, fmt.Errorf("검색 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("GET contacts/search 반환값이 200이 아님: %d", resp.StatusCode)
	}

	var contactsPayload struct {
		Payload []struct {
			ID          ContactID `json:"id"`
			Name        string    `json:"name"`
			Identifier  string    `json:"identifier"`
			Email       string    `json:"email"`
			PhoneNumber string    `json:"phone_number"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&contactsPayload); err != nil {
		return 0, fmt.Errorf("응답 본문 디코딩 실패: %w", err)
	}

	for _, contact := range contactsPayload.Payload {
		if contact.Identifier == query {
			return contact.ID, nil
		} else if contact.Email == query {
			return contact.ID, nil
		} else if contact.PhoneNumber == query {
			return contact.ID, nil
		}
	}

	return 0, fmt.Errorf("사용자 ID %s와 일치하는 연락처를 찾을 수 없습니다", query)
}

// GetConversation은 특정 대화의 정보를 가져옵니다.
func (c *Client) GetConversation(ctx context.Context, conversationID ConversationID) (*Conversation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MakeURI(fmt.Sprintf("conversations/%d", conversationID)), nil)
	if err != nil {
		return nil, fmt.Errorf("대화 정보 요청 생성 실패: %w", err)
	}

	resp, err := c.DoRequest(req)
	if err != nil {
		return nil, fmt.Errorf("대화 정보 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET conversations/%d 반환값이 200이 아님: %d", conversationID, resp.StatusCode)
	}

	var conversation Conversation
	err = json.NewDecoder(resp.Body).Decode(&conversation)
	if err != nil {
		return nil, fmt.Errorf("대화 정보 디코딩 실패: %w", err)
	}

	return &conversation, nil
}

// CreateConversation은 새로운 대화를 생성합니다.
func (c *Client) CreateConversation(ctx context.Context, sourceID string, contactID ContactID, additionalAttrs map[string]string) (*Conversation, error) {
	log := zerolog.Ctx(ctx).With().
		Str("source_id", sourceID).
		Int("contact_id", int(contactID)).
		Logger()

	log.Info().Msg("대화 생성 중")
	payload := map[string]interface{}{
		"source_id":  sourceID,
		"inbox_id":   c.InboxID,
		"contact_id": contactID,
	}
	for k, v := range additionalAttrs {
		payload[k] = v
	}

	jsonValue, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MakeURI("conversations"), bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Err(err).Msg("대화 생성 요청 생성 실패")
		return nil, fmt.Errorf("대화 생성 요청 생성 실패: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.DoRequest(req)
	if err != nil {
		log.Err(err).Msg("대화 생성 요청 실패")
		return nil, fmt.Errorf("대화 생성 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err == nil {
			log.Error().Str("data", string(data)).Msg("200이 아닌 상태 코드 받음")
		}
		return nil, fmt.Errorf("POST conversations 반환값이 200이 아님: %d", resp.StatusCode)
	}

	var conversation Conversation
	err = json.NewDecoder(resp.Body).Decode(&conversation)
	if err != nil {
		return nil, fmt.Errorf("대화 정보 디코딩 실패: %w", err)
	}

	return &conversation, nil
}

// doSendTextMessage는 내부적으로 텍스트 메시지를 전송하기 위한 공통 로직을 구현합니다.
func (c *Client) doSendTextMessage(ctx context.Context, conversationID ConversationID, jsonValues map[string]any) (*Message, error) {
	jsonValue, _ := json.Marshal(jsonValues)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MakeURI(fmt.Sprintf("conversations/%d/messages", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, fmt.Errorf("메시지 전송 요청 생성 실패: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.DoRequest(req)
	if err != nil {
		return nil, fmt.Errorf("메시지 전송 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err == nil {
			zerolog.Ctx(ctx).Error().Str("data", string(data)).Msg("200이 아닌 상태 코드 받음")
		}
		return nil, fmt.Errorf("POST messages 반환값이 200이 아님: %d", resp.StatusCode)
	}

	var message Message
	err = json.NewDecoder(resp.Body).Decode(&message)
	if err != nil {
		return nil, fmt.Errorf("메시지 응답 디코딩 실패: %w", err)
	}

	return &message, nil
}

// SendTextMessage는 텍스트 메시지를 전송합니다.
func (c *Client) SendTextMessage(ctx context.Context, conversationID ConversationID, content string, messageType MessageType) (*Message, error) {
	return c.doSendTextMessage(ctx, conversationID, map[string]any{
		"content":      content,
		"message_type": messageType,
	})
}

// SendPrivateMessage는 대화에 비공개 메시지를 전송합니다.
func (c *Client) SendPrivateMessage(ctx context.Context, conversationID ConversationID, message string) (*Message, error) {
	return c.doSendTextMessage(ctx, conversationID, map[string]any{
		"content": message,
		"private": true,
	})
}

// ToggleStatus는 대화의 상태를 변경합니다.
func (c *Client) ToggleStatus(ctx context.Context, conversationID ConversationID, status ConversationStatus) error {
	payload := map[string]interface{}{
		"status": string(status),
	}

	jsonValue, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MakeURI(fmt.Sprintf("conversations/%d/toggle_status", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		return fmt.Errorf("상태 변경 요청 생성 실패: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.DoRequest(req)
	if err != nil {
		return fmt.Errorf("상태 변경 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err == nil {
			zerolog.Ctx(ctx).Error().Str("data", string(data)).Msg("200이 아닌 상태 코드 받음")
		}
		return fmt.Errorf("POST toggle_status 반환값이 200이 아님: %d", resp.StatusCode)
	}

	return nil
}

// 파일명에서 인용부호를 이스케이프하기 위한 유틸리티
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// escapeQuotes는 문자열의 인용부호를 이스케이프합니다.
func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// SendAttachmentMessage는 첨부파일이 있는 메시지를 전송합니다.
func (c *Client) SendAttachmentMessage(ctx context.Context, conversationID ConversationID, filename string, mimeType string, fileData io.Reader, messageType MessageType) (*Message, error) {
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// messageType 추가
	if err := writer.WriteField("message_type", string(messageType)); err != nil {
		return nil, fmt.Errorf("messageType 필드 작성 실패: %w", err)
	}

	// 파일 필드의 헤더 생성
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="attachments[]"; filename="%s"`, escapeQuotes(filename)))
	header.Set("Content-Type", mimeType)

	// 파일 데이터 추가
	part, err := writer.CreatePart(header)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 파트 생성 실패: %w", err)
	}

	// 파일 데이터를 첨부
	if _, err = io.Copy(part, fileData); err != nil {
		return nil, fmt.Errorf("파일 데이터 복사 실패: %w", err)
	}

	// form 완료
	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("multipart 폼 완료 실패: %w", err)
	}

	// 요청 생성
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.MakeURI(fmt.Sprintf("conversations/%d/messages", conversationID)), &b)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 요청 생성 실패: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// 요청 전송
	resp, err := c.DoRequest(req)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	// 응답 확인
	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err == nil {
			zerolog.Ctx(ctx).Error().Str("data", string(data)).Msg("200이 아닌 상태 코드 받음")
		}
		return nil, fmt.Errorf("POST messages(attachment) 반환값이 200이 아님: %d", resp.StatusCode)
	}

	// 응답 파싱
	var message Message
	err = json.NewDecoder(resp.Body).Decode(&message)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 응답 디코딩 실패: %w", err)
	}

	return &message, nil
}

// DeleteMessage는 Chatwoot 메시지를 삭제합니다.
func (c *Client) DeleteMessage(ctx context.Context, conversationID ConversationID, messageID MessageID) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.MakeURI(fmt.Sprintf("conversations/%d/messages/%d", conversationID, messageID)), nil)
	if err != nil {
		return fmt.Errorf("메시지 삭제 요청 생성 실패: %w", err)
	}

	resp, err := c.DoRequest(req)
	if err != nil {
		return fmt.Errorf("메시지 삭제 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("DELETE messages/%d 반환값이 200이 아님: %d", messageID, resp.StatusCode)
	}

	return nil
}

// CreateOrGetConversation은 연락처와 소스 ID를 사용해 대화를 찾거나 생성합니다.
func (c *Client) CreateOrGetConversation(ctx context.Context, contactID ContactID, sourceID string) (ConversationID, error) {
	log := zerolog.Ctx(ctx).With().
		Int("contact_id", int(contactID)).
		Str("source_id", sourceID).
		Logger()

	log.Info().Msg("대화 찾기/생성 중")

	// 먼저 연락처의 열린 대화를 찾아봄
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.MakeURI(fmt.Sprintf("contacts/%d/conversations?status=open", contactID)), nil)
	if err != nil {
		return 0, fmt.Errorf("열린 대화 요청 생성 실패: %w", err)
	}

	resp, err := c.DoRequest(req)
	if err != nil {
		return 0, fmt.Errorf("열린 대화 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var conversations []Conversation
		err = json.NewDecoder(resp.Body).Decode(&conversations)
		if err != nil {
			return 0, fmt.Errorf("대화 디코딩 실패: %w", err)
		}

		for _, conv := range conversations {
			if conv.ID > 0 && (sourceID == "" || conv.Meta.SourceID == sourceID) {
				return conv.ID, nil
			}
		}
	}

	// 열린 대화가 없으면 생성
	conversation, err := c.CreateConversation(ctx, sourceID, contactID, nil)
	if err != nil {
		return 0, fmt.Errorf("대화 생성 실패: %w", err)
	}

	return conversation.ID, nil
}

// CloseConversation은 대화를 닫습니다.
func (c *Client) CloseConversation(ctx context.Context, conversationID ConversationID) error {
	return c.ToggleStatus(ctx, conversationID, ConversationStatusResolved)
}

// DownloadAttachment는 Chatwoot 첨부파일을 다운로드합니다.
func (c *Client) DownloadAttachment(ctx context.Context, url string) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("첨부파일에 다운로드 URL이 없습니다")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 요청 생성 실패: %w", err)
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 다운로드 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("첨부파일 다운로드 실패: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 데이터 읽기 실패: %w", err)
	}

	return data, nil
}

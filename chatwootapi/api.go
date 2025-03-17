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

type MessageType string

const (
	IncomingMessage MessageType = "incoming"
	OutgoingMessage MessageType = "outgoing"
)

type ConversationStatus string

const (
	ConversationStatusOpen     ConversationStatus = "open"
	ConversationStatusResolved ConversationStatus = "resolved"
	ConversationStatusPending  ConversationStatus = "pending"
)

type ChatwootAPI struct {
	BaseURL     string
	AccountID   AccountID
	InboxID     InboxID
	AccessToken string

	Client *http.Client
}

func CreateChatwootAPI(baseURL string, accountID AccountID, inboxID InboxID, accessToken string) *ChatwootAPI {
	return &ChatwootAPI{
		BaseURL:     baseURL,
		AccountID:   accountID,
		InboxID:     inboxID,
		AccessToken: accessToken,
		Client: &http.Client{
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

func (api *ChatwootAPI) DoRequest(req *http.Request) (*http.Response, error) {
	req.Header.Add("Api-Access-Token", api.AccessToken)
	return api.Client.Do(req)
}

func (api *ChatwootAPI) MakeURI(endpoint string) string {
	url, err := url.Parse(api.BaseURL)
	if err != nil {
		panic(err)
	}
	url.Path = path.Join(url.Path, fmt.Sprintf("api/v1/accounts/%d", api.AccountID), endpoint)
	return url.String()
}

func (api *ChatwootAPI) CreateContact(ctx context.Context, userID id.UserID, name string) (ContactID, error) {
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

	log.Info().Str("name", name).Msg("Creating contact")
	payload := map[string]interface{}{
		"inbox_id": api.InboxID,
		"name":     name,
		"identifier": userID.String(),
	}
	jsonValue, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI("contacts"), bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Err(err).Msg("Failed to create request")
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		log.Err(err).Msg("Failed to make request")
		return 0, err
	}
	if resp.StatusCode != 200 {
		data, err := io.ReadAll(resp.Body)
		if err == nil {
			log.Error().Str("data", string(data)).Msg("got non-200 status code")
		}
		return 0, fmt.Errorf("POST contacts returned non-200 status code: %d", resp.StatusCode)
	}

	var contactPayload ContactPayload
	if err := json.NewDecoder(resp.Body).Decode(&contactPayload); err != nil {
		return 0, err
	}

	log.Debug().Any("contact_payload", contactPayload).Msg("Got contact payload")
	return contactPayload.Payload.Contact.ID, nil
}

func (api *ChatwootAPI) ContactIDForMXID(ctx context.Context, userID id.UserID) (ContactID, error) {
	log := zerolog.Ctx(ctx)
	query := userID.String()
	if userID.Homeserver() == "beeper.local" {
		// Special handling for bridged iMessages.
		if strings.HasPrefix(userID.Localpart(), "imessagego_1.") {
			decoded, err := id.DecodeUserLocalpart(strings.TrimPrefix(userID.Localpart(), "imessagego_1."))
			if err == nil {
				query = decoded
			}
		}
	}

	log.Info().Str("query", query).Msg("Searching for contact")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.MakeURI("contacts/search"), nil)
	if err != nil {
		return 0, err
	}

	q := req.URL.Query()
	q.Add("q", query)
	req.URL.RawQuery = q.Encode()

	resp, err := api.DoRequest(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("GET contacts/search returned non-200 status code: %d", resp.StatusCode)
	}

	var contactsPayload ContactsPayload
	if err := json.NewDecoder(resp.Body).Decode(&contactsPayload); err != nil {
		return 0, err
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

	return 0, fmt.Errorf("couldn't find user with user ID %s", query)
}

func (api *ChatwootAPI) GetChatwootConversation(ctx context.Context, conversationID ConversationID) (*Conversation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.MakeURI(fmt.Sprintf("conversations/%d", conversationID)), nil)
	if err != nil {
		return nil, err
	}

	resp, err := api.DoRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET conversations/%d returned non-200 status code: %d", conversationID, resp.StatusCode)
	}

	var conversation Conversation
	err = json.NewDecoder(resp.Body).Decode(&conversation)
	return &conversation, err
}

func (api *ChatwootAPI) CreateConversation(ctx context.Context, sourceID string, contactID ContactID, additionalAttrs map[string]string) (*Conversation, error) {
	values := map[string]any{
		"source_id":             sourceID,
		"inbox_id":              api.InboxID,
		"contact_id":            contactID,
		"status":                "open",
		"additional_attributes": additionalAttrs,
	}
	jsonValue, _ := json.Marshal(values)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI("conversations"), bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("POST conversations returned non-200 status code: %d: %s", resp.StatusCode, string(content))
	}

	var conversation Conversation
	err = json.NewDecoder(resp.Body).Decode(&conversation)
	return &conversation, err
}

func (api *ChatwootAPI) GetConversation(ctx context.Context, id ConversationID) (*Conversation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.MakeURI(fmt.Sprintf("conversations/%d", id)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := api.DoRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET conversation returned non-200 status code: %d: %s", resp.StatusCode, content)
	}

	var conversation Conversation
	err = json.NewDecoder(resp.Body).Decode(&conversation)
	return &conversation, err
}

func (api *ChatwootAPI) GetConversationLabels(ctx context.Context, conversationID ConversationID) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api.MakeURI(fmt.Sprintf("conversations/%d/labels", conversationID)), nil)
	if err != nil {
		return nil, err
	}

	resp, err := api.DoRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GET conversation labels returned non-200 status code: %d: %s", resp.StatusCode, content)
	}

	var labels ConversationLabelsPayload
	err = json.NewDecoder(resp.Body).Decode(&labels)
	return labels.Payload, err
}

func (api *ChatwootAPI) SetConversationLabels(ctx context.Context, conversationID ConversationID, labels []string) error {
	jsonValue, err := json.Marshal(map[string]any{"labels": labels})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI(fmt.Sprintf("conversations/%d/labels", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST conversations returned non-200 status code: %d: %s", resp.StatusCode, string(content))
	}
	return nil
}

func (api *ChatwootAPI) SetConversationCustomAttributes(ctx context.Context, conversationID ConversationID, customAttrs map[string]string) error {
	jsonValue, _ := json.Marshal(map[string]any{
		"custom_attributes": customAttrs,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI(fmt.Sprintf("conversations/%d/custom_attributes", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("POST conversations/%d/custom_attributes returned non-200 status code: %d", conversationID, resp.StatusCode)
	}
	return nil
}

func (api *ChatwootAPI) doSendTextMessage(ctx context.Context, conversationID ConversationID, jsonValues map[string]any) (*Message, error) {
	log := zerolog.Ctx(ctx).With().Str("component", "send_text_message").Logger()
	jsonValue, err := json.Marshal(jsonValues)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI(fmt.Sprintf("conversations/%d/messages", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Err(err).Msg("Failed to create request")
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		log.Err(err).Msg("failed to send request")
		return nil, err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("POST conversations/%d/messages returned non-200 status code: %d: %s", conversationID, resp.StatusCode, string(content))
	}

	decoder := json.NewDecoder(resp.Body)
	var message Message
	err = decoder.Decode(&message)
	return &message, err
}

func (api *ChatwootAPI) SendTextMessage(ctx context.Context, conversationID ConversationID, content string, messageType MessageType) (*Message, error) {
	values := map[string]any{"content": content, "message_type": messageType, "private": false}
	return api.doSendTextMessage(ctx, conversationID, values)
}

func (api *ChatwootAPI) SendPrivateMessage(ctx context.Context, conversationID ConversationID, content string) (*Message, error) {
	values := map[string]any{"content": content, "message_type": OutgoingMessage, "private": true}
	return api.doSendTextMessage(ctx, conversationID, values)
}

func (api *ChatwootAPI) ToggleStatus(ctx context.Context, conversationID ConversationID, status ConversationStatus) error {
	jsonValue, err := json.Marshal(map[string]any{"status": status})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI(fmt.Sprintf("conversations/%d/toggle_status", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST conversations/%d/toggle_status returned non-200 status code: %d: %s", conversationID, resp.StatusCode, string(content))
	}
	return nil
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func (api *ChatwootAPI) SendAttachmentMessage(ctx context.Context, conversationID ConversationID, filename string, mimeType string, fileData io.Reader, messageType MessageType) (*Message, error) {
	// 성공적인 curl 요청과 정확히, 가능한 모든 측면에서 똑같이 만듭니다
	bodyBuf := &bytes.Buffer{}
	bodyWriter := multipart.NewWriter(bodyBuf)

	// 폼 필드 순서를 curl과 동일하게 맞춥니다
	messageTypeFieldWriter, err := bodyWriter.CreateFormField("message_type")
	if err != nil {
		return nil, err
	}
	messageTypeFieldWriter.Write([]byte(messageType))

	contentFieldWriter, err := bodyWriter.CreateFormField("content")
	if err != nil {
		return nil, err
	}
	contentFieldWriter.Write([]byte{})

	privateFieldWriter, err := bodyWriter.CreateFormField("private")
	if err != nil {
		return nil, err
	}
	privateFieldWriter.Write([]byte("false"))

	// 파일 첨부
	h := make(textproto.MIMEHeader)
	h.Set(
		"Content-Disposition",
		fmt.Sprintf(`form-data; name="attachments[]"; filename="%s"`, quoteEscaper.Replace(filename)))
	if mimeType != "" {
		h.Set("Content-Type", mimeType)
	} else {
		h.Set("Content-Type", "application/octet-stream")
	}
	fileWriter, err := bodyWriter.CreatePart(h)
	if err != nil {
		return nil, err
	}

	// 파일 데이터 복사
	io.Copy(fileWriter, fileData)

	bodyWriter.Close()

	// 요청 생성
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI(fmt.Sprintf("conversations/%d/messages", conversationID)), bodyBuf)
	if err != nil {
		return nil, err
	}
	
	// Content-Type 및 API 토큰 헤더 설정 - curl과 정확히 동일하게
	req.Header.Set("Content-Type", bodyWriter.FormDataContentType())
	req.Header.Set("Api-Access-Token", api.AccessToken)
	
	// 디버그 로깅
	log := zerolog.Ctx(ctx)
	if log != nil {
		log.Debug().Str("url", req.URL.String()).Str("method", req.Method).
			Str("content-type", req.Header.Get("Content-Type")).
			Str("api-access-token", req.Header.Get("Api-Access-Token")).
			Msg("첨부 파일 업로드 요청 전송 (curl과 동일한 방식)")
	}

	// curl과 동일하게 직접 http 클라이언트 사용하되 리다이렉트 시 헤더 복사 추가
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many (>=10) redirects, cancelling request")
			}
			// 이전 요청의 헤더를 복사
			if len(via) > 0 {
				for key, values := range via[len(via)-1].Header {
					req.Header[key] = values
				}
			}
			return nil
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	
	// 응답 처리
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("POST conversations/%d/messages returned non-200 status code: %d: %s", conversationID, resp.StatusCode, string(content))
	}

	var message Message
	err = json.NewDecoder(resp.Body).Decode(&message)
	if err != nil {
		return nil, err
	}
	
	return &message, nil
}

func (api *ChatwootAPI) DownloadAttachment(ctx context.Context, url string) ([]byte, error) {
	log := zerolog.Ctx(ctx)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		log.Err(err).Msg("failed to create request")
		return nil, err
	}
	resp, err := api.DoRequest(req)
	if err != nil {
		log.Err(err).Msg("failed to do request")
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET attachment returned non-200 status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Err(err).Msg("failed to read response body")
		return nil, err
	}
	return data, err
}

func (api *ChatwootAPI) DeleteMessage(ctx context.Context, conversationID ConversationID, messageID MessageID) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, api.MakeURI(fmt.Sprintf("conversations/%d/messages/%d", conversationID, messageID)), nil)
	if err != nil {
		return err
	}

	resp, err := api.DoRequest(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("GET attachment returned non-200 status code: %d", resp.StatusCode)
	}

	return nil
}

func (api *ChatwootAPI) CreateOrGetConversation(ctx context.Context, contactID ContactID, sourceID string) (ConversationID, error) {
	values := map[string]any{
		"source_id":  sourceID,
		"inbox_id":   api.InboxID,
		"contact_id": contactID,
		"status":     "open",
	}
	jsonValue, _ := json.Marshal(values)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI("conversations"), bytes.NewBuffer(jsonValue))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("POST conversations returned non-200 status code: %d: %s", resp.StatusCode, string(content))
	}

	var conversation Conversation
	err = json.NewDecoder(resp.Body).Decode(&conversation)
	return conversation.ID, err
}

func (api *ChatwootAPI) CloseConversation(ctx context.Context, conversationID ConversationID) error {
	values := map[string]any{"status": "resolved"}
	jsonValue, _ := json.Marshal(values)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api.MakeURI(fmt.Sprintf("conversations/%d/toggle_status", conversationID)), bytes.NewBuffer(jsonValue))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := api.DoRequest(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		content, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST conversations/%d/toggle_status returned non-200 status code: %d: %s", conversationID, resp.StatusCode, string(content))
	}
	return nil
}

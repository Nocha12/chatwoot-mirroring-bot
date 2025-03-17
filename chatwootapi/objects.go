package chatwootapi

type ContactID int
type ConversationID int
type AccountID int
type InboxID int
type MessageID int
type AttachmentID int
type SenderID int

// Contact
type Contact struct {
	ID          ContactID `json:"id"`
	Identifier  string    `json:"identifier"`
	PhoneNumber string    `json:"phone_number,omitempty"`
	Email       string    `json:"email,omitempty"`
}

type ContactsPayload struct {
	Payload []Contact `json:"payload"`
}

type ContactPayloadInner struct {
	Contact Contact `json:"contact"`
}

type ContactPayload struct {
	Payload ContactPayloadInner `json:"payload"`
}

type CreateContactPayload struct {
	InboxID     InboxID `json:"inbox_id"`
	Name        string  `json:"name"`
	PhoneNumber string  `json:"phone_number"`
	Identifier  string  `json:"identifier"`
}

// Attachment

type Attachment struct {
	ID        AttachmentID `json:"id"`
	FileType  string       `json:"file_type"`
	FileSize  int          `json:"file_size"`
	AccountID AccountID    `json:"account_id"`
	DataURL   string       `json:"data_url"`
	ThumbURL  string       `json:"thumb_url"`
}

// Message

type Sender struct {
	ID            SenderID `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"user"`
	AvailableName string   `json:"available_name"`
}

type Message struct {
	ID          MessageID    `json:"id"`
	Content     *string      `json:"content"`
	Private     bool         `json:"private"`
	Attachments []Attachment `json:"attachments"`
	Sender      Sender       `json:"sender"`
}

// Conversation

type ConversationMeta struct {
	Sender Contact `json:"sender"`
}

type Conversation struct {
	ID               ConversationID    `json:"id"`
	AccountID        AccountID         `json:"account_id"`
	InboxID          InboxID           `json:"inbox_id"`
	Messages         []Message         `json:"messages"`
	Meta             ConversationMeta  `json:"meta"`
	CustomAttributes map[string]string `json:"custom_attributes"`
}

type ConversationsPayload struct {
	Payload []Conversation `json:"payload"`
}

type ConversationLabelsPayload struct {
	Payload []string `json:"payload"`
}

// Content Attributes

type ContentAttributes struct {
	Deleted bool `json:"deleted"`
}

// Webhook

type MessageCreated struct {
	ID                MessageID          `json:"id"`
	Content           string             `json:"content"`
	CreatedAt         string             `json:"created_at"`
	MessageType       string             `json:"message_type"`
	ContentType       string             `json:"content_type"`
	ContentAttributes *ContentAttributes `json:"content_attributes"`
	Private           bool               `json:"private"`
	Conversation      Conversation       `json:"conversation"`
}

// GetConversationsResponse는 대화 목록 조회 API 응답 구조체입니다
type GetConversationsResponse struct {
	Payload []Conversation `json:"payload"`
	Meta    Meta           `json:"meta"`
}

// GetContactsResponse는 연락처 목록 조회 API 응답 구조체입니다
type GetContactsResponse struct {
	Payload []Contact `json:"payload"`
	Meta    Meta      `json:"meta"`
}

// CreateMessageResponse는 메시지 생성 API 응답 구조체입니다
type CreateMessageResponse struct {
	ID                MessageID          `json:"id"`
	Content           string             `json:"content"`
	CreatedAt         string             `json:"created_at"`
	MessageType       string             `json:"message_type"`
	ContentType       string             `json:"content_type"`
	ContentAttributes *ContentAttributes `json:"content_attributes"`
	Private           bool               `json:"private"`
}

// Meta는 페이지네이션 메타데이터 구조체입니다
type Meta struct {
	Count        int `json:"count"`
	CurrentPage  int `json:"current_page"`
	PerPage      int `json:"per_page"`
	TotalCount   int `json:"total_count"`
	TotalPages   int `json:"total_pages"`
}

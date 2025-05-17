package chatwootapi

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

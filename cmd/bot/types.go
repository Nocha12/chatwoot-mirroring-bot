package main

import (
	"sync"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// 전역 변수 정의
var VERSION = "0.2.1"

// Chatwoot 대화 ID 저장을 위한 상태 이벤트 타입
var chatwootConversationIDType = event.Type{
	Type:  "com.beeper.chatwoot.conversation_id",
	Class: event.StateEventType,
}

// ChatwootConversationIDEventContent는 Chatwoot 대화 ID를 저장하는 이벤트 컨텐츠입니다.
type ChatwootConversationIDEventContent struct {
	ConversationID chatwootapi.ConversationID `json:"conversation_id"`
}

// RoomSendLocks는 방 동기화를 위한 락 맵입니다
type RoomSendLocks map[id.RoomID]*sync.Mutex

// NewRoomSendLocks는 새로운 RoomSendLocks 맵을 생성합니다
func NewRoomSendLocks() RoomSendLocks {
	return make(RoomSendLocks)
}

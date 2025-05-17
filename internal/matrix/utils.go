package matrix

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// roomLocks는 방 간 동시 접근을 방지하기 위한 맵입니다.
var roomLocks = make(map[id.RoomID]*sync.Mutex)
var roomLocksLock = sync.Mutex{}

// GetOrCreateRoomLock은 주어진 방 ID에 대한 락을 반환하거나 생성합니다.
func GetOrCreateRoomLock(roomID id.RoomID) *sync.Mutex {
	roomLocksLock.Lock()
	defer roomLocksLock.Unlock()

	if lock, ok := roomLocks[roomID]; ok {
		return lock
	}

	lock := &sync.Mutex{}
	roomLocks[roomID] = lock
	return lock
}

// SendMessage는 Matrix 방에 메시지를 전송합니다.
func SendMessage(ctx context.Context, client MatrixClient, roomID id.RoomID, content *event.MessageEventContent, extraContent ...map[string]any) (*mautrix.RespSendEvent, error) {
	log := zerolog.Ctx(ctx).With().Stringer("room_id", roomID).Logger()
	ctx = log.WithContext(ctx)

	wrappedContent := event.Content{Parsed: content}
	if len(extraContent) == 1 {
		wrappedContent.Raw = extraContent[0]
	}

	lock := GetOrCreateRoomLock(roomID)
	lock.Lock()
	defer lock.Unlock()

	resp, err := client.SendMessageEvent(ctx, roomID, event.EventMessage, &wrappedContent)
	if err != nil {
		log.Err(err).Msg("메시지 전송 실패")
		return nil, err
	}

	log.Debug().Stringer("event_id", resp.EventID).Msg("메시지 전송 성공")
	return resp, nil
}

// logError는 에러를 표준화된 방식으로 로깅합니다.
// nolint:unused
func logError(ctx context.Context, err error, component string, msg string, fields ...interface{}) {
	logger := zerolog.Ctx(ctx).With().Str("component", component).Err(err)

	// 추가 필드가 있으면 로그에 포함
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			if key, ok := fields[i].(string); ok {
				switch val := fields[i+1].(type) {
				case int:
					logger = logger.Int(key, val)
				case string:
					logger = logger.Str(key, val)
				case id.EventID:
					logger = logger.Stringer(key, val)
				case id.RoomID:
					logger = logger.Stringer(key, val)
				}
			}
		}
	}
	
	// logger.Logger()는 값을 반환하므로 Error() 포인터 메서드를 직접 호출할 수 없습니다.
	// 대신 컨텍스트에서 로거를 가져와 사용합니다.
	logObj := logger.Logger()
	logObj.Error().Msg(msg)
}

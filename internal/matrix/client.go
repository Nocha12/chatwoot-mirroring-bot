package matrix

import (
	"context"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Client는 Matrix 클라이언트 작업을 위한 인터페이스입니다.
type Client interface {
	// 메시지 전송 관련 메서드
	SendMessage(ctx context.Context, roomID id.RoomID, eventType event.Type, content interface{}) (*mautrix.RespSendEvent, error)
	SendText(ctx context.Context, roomID id.RoomID, text string) (*mautrix.RespSendEvent, error)
	SendNotice(ctx context.Context, roomID id.RoomID, text string) (*mautrix.RespSendEvent, error)
	SendReaction(ctx context.Context, roomID id.RoomID, eventID id.EventID, reaction string) (*mautrix.RespSendEvent, error)
	RedactEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID, reason string) (*mautrix.RespSendEvent, error)

	// 방 관련 메서드
	JoinRoomByID(ctx context.Context, roomID id.RoomID) (*mautrix.RespJoinRoom, error)
	LeaveRoom(ctx context.Context, roomID id.RoomID) (*mautrix.RespLeaveRoom, error)
	GetStateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string) (interface{}, error)
	SetRoomName(ctx context.Context, roomID id.RoomID, name string) (*mautrix.RespSendEvent, error)

	// 미디어 관련 메서드
	DownloadBytes(ctx context.Context, mxcURL id.ContentURI) ([]byte, error)
	UploadBytes(ctx context.Context, data []byte, fileName string) (id.ContentURI, error)

	// 기타 메서드
	Whoami(ctx context.Context) (*mautrix.RespWhoami, error)
	GetUserID() id.UserID
}

// ClientImpl은 Client 인터페이스를 구현하는 구조체입니다.
type ClientImpl struct {
	Client       *mautrix.Client
	CryptoHelper *cryptohelper.CryptoHelper
}

// NewClient는 새로운 Matrix 클라이언트 인스턴스를 생성합니다.
func NewClient(client *mautrix.Client, cryptoHelper *cryptohelper.CryptoHelper) *ClientImpl {
	return &ClientImpl{
		Client:       client,
		CryptoHelper: cryptoHelper,
	}
}

// ClientAdapter는 MatrixClient 인터페이스를 구현하는 어댑터입니다.
// ClientImpl을 MatrixClient 인터페이스로 변환합니다.
type ClientAdapter struct {
	*ClientImpl
}

// NewClientAdapter는 ClientImpl을 래핑하는 ClientAdapter를 생성합니다.
func NewClientAdapter(client *ClientImpl) *ClientAdapter {
	return &ClientAdapter{
		ClientImpl: client,
	}
}

// UserID는 사용자 ID를 반환합니다.
func (ca *ClientAdapter) UserID() id.UserID {
	return ca.ClientImpl.Client.UserID
}

// SendMessageEvent는 메시지 이벤트를 전송합니다.
func (ca *ClientAdapter) SendMessageEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, content interface{}, opts ...mautrix.ReqSendEvent) (*mautrix.RespSendEvent, error) {
	// 옵션을 무시하고 기본 동작만 수행
	return ca.ClientImpl.Client.SendMessageEvent(ctx, roomID, eventType, content, opts...)
}

// GetEvent는 이벤트를 조회합니다.
func (ca *ClientAdapter) GetEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (*event.Event, error) {
	return ca.ClientImpl.Client.GetEvent(ctx, roomID, eventID)
}

// RedactEvent는 이벤트를 삭제합니다.
func (ca *ClientAdapter) RedactEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID, opts ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error) {
	// 옵션을 그대로 전달
	return ca.ClientImpl.Client.RedactEvent(ctx, roomID, eventID, opts...)
}

// State는 방의 상태를 조회합니다.
func (ca *ClientAdapter) State(ctx context.Context, roomID id.RoomID) (mautrix.RoomStateMap, error) {
	return ca.ClientImpl.Client.State(ctx, roomID)
}

// MautrixClientAdapter는 mautrix.Client를 MatrixClient 인터페이스로 변환하는 어댑터입니다.
type MautrixClientAdapter struct {
	Client *mautrix.Client
}

// NewMautrixClientAdapter는 mautrix.Client를 래핑하는 MautrixClientAdapter를 생성합니다.
func NewMautrixClientAdapter(client *mautrix.Client) *MautrixClientAdapter {
	return &MautrixClientAdapter{
		Client: client,
	}
}

// UserID는 사용자 ID를 반환합니다.
func (mca *MautrixClientAdapter) UserID() id.UserID {
	// UserID가 메서드가 아닌 필드이므로 그냥 반환
	return mca.Client.UserID
}

// SendMessageEvent는 메시지 이벤트를 전송합니다.
func (mca *MautrixClientAdapter) SendMessageEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, content interface{}, opts ...mautrix.ReqSendEvent) (*mautrix.RespSendEvent, error) {
	return mca.Client.SendMessageEvent(ctx, roomID, eventType, content, opts...)
}

// GetEvent는 이벤트를 조회합니다.
func (mca *MautrixClientAdapter) GetEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (*event.Event, error) {
	return mca.Client.GetEvent(ctx, roomID, eventID)
}

// RedactEvent는 이벤트를 삭제합니다.
func (mca *MautrixClientAdapter) RedactEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID, opts ...mautrix.ReqRedact) (*mautrix.RespSendEvent, error) {
	// 가변인자를 받아서 mautrix.Client의 RedactEvent로 전달
	return mca.Client.RedactEvent(ctx, roomID, eventID, opts...)
}

// State는 방의 상태를 조회합니다.
func (mca *MautrixClientAdapter) State(ctx context.Context, roomID id.RoomID) (mautrix.RoomStateMap, error) {
	return mca.Client.State(ctx, roomID)
}

// SendStateEvent는 상태 이벤트를 전송합니다.
func (mca *MautrixClientAdapter) SendStateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, content interface{}) (*mautrix.RespSendEvent, error) {
	return mca.Client.SendStateEvent(ctx, roomID, eventType, stateKey, content)
}

// JoinedRooms는 현재 참여 중인 방 목록을 가져옵니다.
func (mca *MautrixClientAdapter) JoinedRooms(ctx context.Context) (*mautrix.RespJoinedRooms, error) {
	return mca.Client.JoinedRooms(ctx)
}

// JoinedMembers는 방에 참여 중인 멤버 목록을 가져옵니다.
func (mca *MautrixClientAdapter) JoinedMembers(ctx context.Context, roomID id.RoomID) (*mautrix.RespJoinedMembers, error) {
	return mca.Client.JoinedMembers(ctx, roomID)
}

// JoinRoom은 방에 참여합니다.
func (mca *MautrixClientAdapter) JoinRoom(ctx context.Context, roomID string, content *mautrix.ReqJoinRoom) (*mautrix.RespJoinRoom, error) {
	return mca.Client.JoinRoom(ctx, roomID, content)
}

// LeaveRoom은 방에서 나갑니다.
func (mca *MautrixClientAdapter) LeaveRoom(ctx context.Context, roomID id.RoomID) (*mautrix.RespLeaveRoom, error) {
	return mca.Client.LeaveRoom(ctx, roomID)
}

// StateEvent는 방의 상태 이벤트를 가져옵니다.
func (mca *MautrixClientAdapter) StateEvent(ctx context.Context, roomID id.RoomID, eventType event.Type, stateKey string, outContent interface{}) error {
	return mca.Client.StateEvent(ctx, roomID, eventType, stateKey, outContent)
}

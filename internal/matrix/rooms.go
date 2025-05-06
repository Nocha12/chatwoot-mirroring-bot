package matrix

import (
	"context"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// RoomHelper는 Matrix 방 관련 기능을 제공하는 헬퍼 구조체입니다.
type RoomHelper struct {
	Client *mautrix.Client
}

// NewRoomHelper는 새로운 RoomHelper 인스턴스를 생성합니다.
func NewRoomHelper(client *mautrix.Client) *RoomHelper {
	return &RoomHelper{
		Client: client,
	}
}

// ValidateRoomExists는 Matrix 방이 존재하는지 확인하고 필요시 참여합니다.
func (h *RoomHelper) ValidateRoomExists(ctx context.Context, roomID id.RoomID) (bool, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "validate_room_exists").
		Stringer("room_id", roomID).
		Logger()
	ctx = log.WithContext(ctx)

	// 방 상태 확인 (예: canonical_alias)
	// mautrix 최신 버전에서는 StateEvent에 상태를 받을 포인터가 필요
	var aliasContent interface{}
	err := h.Client.StateEvent(ctx, roomID, event.StateCanonicalAlias, "", &aliasContent)
	if err != nil {
		// 404 오류면 방이 없거나 액세스할 수 없는 것
		// 403 오류면 액세스할 수 없는 것 (초대되지 않음)
		httpErr, ok := err.(mautrix.HTTPError)
		if ok && (httpErr.RespError.ErrCode == "M_NOT_FOUND" || httpErr.RespError.ErrCode == "M_FORBIDDEN") {
			log.Debug().Err(err).Str("error_code", httpErr.RespError.ErrCode).Msg("방이 존재하지 않거나 액세스할 수 없음")

			// 방에 참여 시도
			_, joinErr := h.Client.JoinRoomByID(ctx, roomID)
			if joinErr != nil {
				log.Warn().Err(joinErr).Msg("방 참여 시도 실패")
				return false, nil
			}

			log.Info().Msg("방에 성공적으로 참여함")
			return true, nil
		}

		// 다른 오류는 서버 문제일 수 있음
		log.Error().Err(err).Msg("방 상태 확인 중 오류 발생")
		return false, err
	}

	// 방 존재함
	log.Debug().Msg("방이 존재하며 액세스 가능")
	return true, nil
}

// GetRoomMembers는 방의 모든 멤버를 가져옵니다.
func (h *RoomHelper) GetRoomMembers(ctx context.Context, roomID id.RoomID) ([]id.UserID, error) {
	log := zerolog.Ctx(ctx)

	// 방의 모든 멤버 상태 이벤트 가져오기
	membersResp, err := h.Client.Members(ctx, roomID, mautrix.ReqMembers{
		Membership: event.MembershipJoin,
	})
	if err != nil {
		log.Error().Err(err).Stringer("room_id", roomID).Msg("방 멤버 목록 가져오기 실패")
		return nil, err
	}

	members := make([]id.UserID, 0, len(membersResp.Chunk))
	for _, evt := range membersResp.Chunk {
		if evt.StateKey != nil && *evt.StateKey != "" {
			members = append(members, id.UserID(*evt.StateKey))
		}
	}

	log.Debug().Int("member_count", len(members)).Msg("방 멤버 목록 가져옴")
	return members, nil
}

// GetRoomName은 방 이름을 가져옵니다.
func (h *RoomHelper) GetRoomName(ctx context.Context, roomID id.RoomID) (string, error) {
	log := zerolog.Ctx(ctx)

	// 방 이름 상태 이벤트 가져오기
	var nameContent struct {
		Name string `json:"name"`
	}
	err := h.Client.StateEvent(ctx, roomID, event.StateRoomName, "", &nameContent)
	if err != nil {
		// 방 이름이 설정되지 않은 경우
		httpErr, ok := err.(mautrix.HTTPError)
		if ok && httpErr.RespError.ErrCode == "M_NOT_FOUND" {
			log.Debug().Msg("방 이름이 설정되지 않음")
			return "", nil
		}

		log.Error().Err(err).Msg("방 이름 가져오기 실패")
		return "", err
	}

	// StateEvent가 직접 구조체에 파싱하므로 별도 파싱 필요 없음

	return nameContent.Name, nil
}

// IsDirectChat은 해당 방이 1:1 다이렉트 채팅인지 확인합니다.
func (h *RoomHelper) IsDirectChat(ctx context.Context, roomID id.RoomID) (bool, error) {
	// log 변수는 실제 사용되지 않으므로 제거
	_ = zerolog.Ctx(ctx)

	// 방 멤버 수 확인
	members, err := h.GetRoomMembers(ctx, roomID)
	if err != nil {
		return false, err
	}

	// 방 멤버가 2명이면 1:1 다이렉트 채팅으로 간주
	// 실제로는 m.direct 이벤트를 확인하는 것이 더 정확하지만, 간단한 예시로 멤버 수만 확인
	return len(members) == 2, nil
}

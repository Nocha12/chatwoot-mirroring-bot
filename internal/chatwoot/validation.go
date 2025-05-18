package chatwoot

import (
	"context"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// validateRoomExists는 Matrix 방이 존재하는지 확인하는 함수입니다.
func (h *MessageHandler) validateRoomExists(ctx context.Context, client *mautrix.Client, roomID id.RoomID) (bool, error) {
	log := zerolog.Ctx(ctx)
	log.Debug().Stringer("room_id", roomID).Msg("방 존재 여부 확인")

	// 방의 암호화 상태 확인
	var encState *event.EncryptionEventContent
	err := client.StateEvent(ctx, roomID, event.StateEncryption, "", &encState)
	if err != nil {
		// 404 오류면 방이 없거나 액세스할 수 없는 것
		// 403 오류면 액세스할 수 없는 것 (초대되지 않음)
		httpErr, ok := err.(mautrix.HTTPError)
		if ok && (httpErr.RespError.ErrCode == "M_NOT_FOUND" || httpErr.RespError.ErrCode == "M_FORBIDDEN") {
			log.Debug().Err(err).Str("error_code", httpErr.RespError.ErrCode).Msg("방이 존재하지 않거나 액세스할 수 없음")

			// 방에 참여 시도
			_, joinErr := client.JoinRoomByID(ctx, roomID)
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

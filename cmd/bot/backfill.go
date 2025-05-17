package main

import (
	"context"
	"fmt"
	"time"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// StartBackfillProcess는 백필 작업을 시작합니다.
func StartBackfillProcess(ctx context.Context, appSetup *setup.AppSetup) {
	log := zerolog.Ctx(ctx)

	if !appSetup.Config.Backfill.ChatwootConversations && !appSetup.Config.Backfill.ConversationIDStateEvents {
		return
	}

	go runBackfillLoop(ctx, appSetup, log)
}

// runBackfillLoop는 백필 프로세스 루프를 실행합니다.
func runBackfillLoop(ctx context.Context, appSetup *setup.AppSetup, log *zerolog.Logger) {
	for {
		backfillLog := log.With().Str("component", "conversation_creation_backfill").Logger()
		backfillCtx := backfillLog.WithContext(context.Background())

		backfillLog.Info().Msg("시작: 아직 대화가 없는 방에 대한 대화 생성")

		joined, err := appSetup.Client.JoinedRooms(backfillCtx)
		if err != nil {
			backfillLog.Fatal().Err(err).Msg("참여한 방 목록 가져오기 실패")
		}

		for _, roomID := range joined.JoinedRooms {
			conversationID, _, err := appSetup.DB.GetChatwootConversationIDFromMatrixRoom(backfillCtx, roomID)
			if err != nil {
				// 이 방에는 아직 Chatwoot 대화가 연결되어 있지 않음
				if appSetup.Config.Backfill.ChatwootConversations {
					err = backfillConversationForRoom(backfillCtx, roomID, appSetup.Client)
					if err != nil {
						backfillLog.Warn().Err(err).Msg("방에 대한 대화 백필 실패")
						continue
					}
				}
			} else if appSetup.Config.Backfill.ConversationIDStateEvents {
				// 이미 Chatwoot 대화가 있는 경우, 해당 방에 Chatwoot 대화 ID가 포함된
				// 상태 이벤트가 있는지 확인합니다.
				_, err = appSetup.Client.SendStateEvent(backfillCtx, roomID, chatwootConversationIDType, "", ChatwootConversationIDEventContent{
					ConversationID: conversationID,
				})
				if err != nil {
					backfillLog.Warn().Err(err).Msg("대화 ID 상태 이벤트 전송 실패")
				}
			}
		}

		backfillLog.Info().Msg("완료: 아직 대화가 없는 방에 대한 대화 생성... 24시간 후 다시 백필 시작")
		time.Sleep(24 * time.Hour)
	}
}

// backfillConversationForRoom은 특정 방에 대한 대화를 백필합니다.
func backfillConversationForRoom(ctx context.Context, roomID id.RoomID, client *mautrix.Client) error {
	log := zerolog.Ctx(ctx).With().Stringer("room_id", roomID).Logger()
	ctx = log.WithContext(ctx)

	log.Info().Msg("방에 대한 대화 생성 중")

	// 대화 생성을 위한 룸 정보 가져오기
	// 룸 이름 가져오기
	var roomName string
	var roomNameContent event.RoomNameEventContent
	err := client.StateEvent(ctx, roomID, event.StateRoomName, "", &roomNameContent)
	if err == nil && roomNameContent.Name != "" {
		roomName = roomNameContent.Name
	} else {
		log.Debug().Err(err).Msg("방 이름 이벤트 가져오기 실패")
	}

	// 방 이름이 없는 경우 참가자 수 기반으로 이름 생성
	if roomName == "" {
		// 현재 참가자 목록 가져오기
		members := 0
		joinResp, err := client.JoinedMembers(ctx, roomID)
		if err == nil && joinResp != nil {
			members = len(joinResp.Joined)
		} else {
			log.Debug().Err(err).Msg("방 참가자 목록 가져오기 실패")
			// 기본값 2명(봇 + 사용자)
			members = 2
		}
		roomName = fmt.Sprintf("Matrix 채팅 (%d명 참가자)", members)
	}

	// 기본 계정 ID 사용 (여러 계정 관리는 추후 구현)
	// 이 기능은 아직 구현되지 않았으므로 가장 기본적인 로그만 출력
	log.Info().Str("roomName", roomName).Msg("새 Chatwoot 대화 생성 필요")
	return nil
}

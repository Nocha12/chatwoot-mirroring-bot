package conversation

import (
	"context"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
)

// BackfillConversationForRoom은 Matrix 방에 대화 기록을 백필합니다.
func (m *ManagerImpl) BackfillConversationForRoom(ctx context.Context, roomID id.RoomID) error {
	log := zerolog.Ctx(ctx).With().Stringer("room_id", roomID).Logger()

	log.Info().Msg("대화 백필 시작")

	// TODO: MatrixClient 인터페이스에 Messages 메서드를 추가하거나 여기서 타입 단언을 사용해야 합니다.
	// 현재는 임시로 이 기능을 비활성화합니다.
	/*
		messages, err := m.Client.Messages(ctx, roomID, "", "", mautrix.DirectionBackward, nil, 50)
		if err != nil {
			log.Err(err).Msg("방의 메시지 가져오기 실패")
			return err
		}
	*/
	log.Warn().Msg("백필 기능이 현재 구현되지 않았습니다")

	// 대화 ID 확인 시도
	conversationID, accountID, err := m.StateStore.GetChatwootConversationIDFromMatrixRoom(ctx, roomID)
	if err != nil {
		// 대화가 없으면 여기서 생성하거나 처리할 수 있습니다.
		// 현재는 간단히 로그만 남기고 종료합니다.
		log.Debug().Err(err).Msg("방에 대화 ID가 없어 건너뜁니다")
		return nil
	}

	log.Info().
		Int("chatwoot_conversation_id", int(conversationID)).
		Int("account_id", int(accountID)).
		Msg("기존 Chatwoot 대화를 찾았습니다")

	// 백필 기능은 현재 구현되지 않았으므로, 여기서 종료합니다.
	log.Info().
		Int("chatwoot_conversation_id", int(conversationID)).
		Int("account_id", int(accountID)).
		Msg("백필 기능이 현재 구현되지 않았습니다. 기존 대화 정보만 반환합니다.")

	// 주석: 아래는 GetMessages API가 구현되면 사용할 코드입니다.
	/*
		// Chatwoot API 클라이언트 가져오기
		api := m.GetChatwootAPI(chatwootapi.AccountID(accountID))

		// 이 부분은 chatwootapi 패키지에 GetMessages와 같은 메서드가 구현되면 활성화합니다.
		// 현재는 해당 메서드가 구현되어 있지 않아 주석 처리합니다.
		// messages, err := api.Conversations.GetMessages(ctx, conversationID)
		// if err != nil {
		//	log.Error().
		//		Err(err).
		//		Int("conversation_id", int(conversationID)).
		//		Int("account_id", int(accountID)).
		//		Msg("메시지 기록 가져오기 실패")
		//	return fmt.Errorf("failed to get messages for conversation %d: %w", conversationID, err)
		// }
		//
		// log.Info().
		//	Int("message_count", len(messages)).
		//	Msg("백필할 메시지 수")
		//
		// // 메시지 전송 (여기서는 단순화된 구현, 실제로는 추가적인 처리가 필요할 수 있음)
		// for _, msg := range messages {
		//	// 메시지 처리 로직 구현
		//	log.Debug().
		//		Int("message_id", msg.ID).
		//		Msg("메시지 백필 처리 중")
		//	// 여기에 Matrix 방으로 메시지 전송 로직 추가
		// }
	*/

	return nil
}

// Package conversation은 Matrix와 Chatwoot 간의 대화 연결을 관리하는 패키지입니다.
package conversation

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// createChatwootConversation은 Matrix 방에 대응하는 새 Chatwoot 대화를 생성합니다.
func (m *ManagerImpl) createChatwootConversation(ctx context.Context, roomID id.RoomID, contactMXID id.UserID, customAttrs map[string]string) (chatwootapi.ConversationID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "create_chatwoot_conversation").
		Stringer("room_id", roomID).
		Stringer("contact_mxid", contactMXID).
		Any("custom_attrs", customAttrs).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("대화 생성 락 획득")
	m.createRoomLock.Lock()
	defer log.Debug().Msg("대화 생성 락 해제")
	defer m.createRoomLock.Unlock()

	// 먼저 이미 존재하는 대화 ID가 있는지 다시 확인
	if conversationID, _, err := m.StateStore.GetChatwootConversationIDFromMatrixRoom(ctx, roomID); err == nil {
		log.Info().
			Int("conversation_id", int(conversationID)).
			Msg("대화가 이미 존재합니다")
		return conversationID, nil
	}

	log.Info().Msg("Chatwoot 연락처 ID 조회 중")
	// 기본 계정의 API 클라이언트 사용
	api := m.GetChatwootAPI(m.DefaultAccountID)
	contactID, err := api.Contacts.ContactIDForMXID(ctx, contactMXID)
	if err != nil {
		log.Warn().
			Err(err).
			Stringer("contact_mxid", contactMXID).
			Msg("사용자에 대한 연락처 ID를 찾을 수 없습니다. 새로 생성을 시도합니다")

		// Twitter 사용자 이름에 대한 특별한 처리
		contactName := ""
		if strings.HasPrefix(contactMXID.Localpart(), "twitter_") {
			memberEventContent := map[string]any{}
			if err := m.Client.StateEvent(ctx, roomID, event.StateMember, contactMXID.String(), &memberEventContent); err == nil {
				log.Trace().Any("member_event_content", memberEventContent).Msg("Got member event content")
				if identifiers, ok := memberEventContent["com.beeper.bridge.identifiers"]; ok {
					if identifiersMap, ok := identifiers.(map[string]interface{}); ok {
						if twitter, ok := identifiersMap["twitter"]; ok {
							if twitterMap, ok := twitter.(map[string]interface{}); ok {
								if username, ok := twitterMap["username"]; ok {
									contactName = username.(string)
								}
							}
						}
					}
				}
			}
		}

		// 일반적인 사용자 이름 처리
		if contactName == "" {
			localpart, _, _ := contactMXID.Parse()
			contactName = localpart
		}

		log.Info().
			Str("contact_name", contactName).
			Msg("연락처 생성 시도")
		// Chatwoot에 새 연락처 생성
		if contactID, err = api.Contacts.CreateContact(ctx, contactMXID, contactName); err != nil {
			log.Error().
				Err(err).
				Str("contact_name", contactName).
				Stringer("contact_mxid", contactMXID).
				Msg("Chatwoot에 연락처 생성 실패")
			return -1, fmt.Errorf("failed to create contact for %s: %w", contactMXID, err)
		}
		log.Info().
			Int("contact_id", int(contactID)).
			Msg("Chatwoot에 연락처 생성 성공")
	} else {
		log.Info().
			Int("contact_id", int(contactID)).
			Msg("기존 연락처 ID 찾음")
	}

	// 대화 이름 설정
	var roomName string
	if err := m.Client.StateEvent(ctx, roomID, event.StateRoomName, "", &roomName); err == nil && roomName != "" {
		log.Info().
			Str("room_name", roomName).
			Msg("룸 이름을 찾았습니다")
	} else {
		// 룸 이름이 없으면 사용자 이름을 사용
		localpart, _, _ := contactMXID.Parse()
		roomName = localpart
		log.Info().
			Str("contact_localpart", localpart).
			Msg("룸 이름이 없어 연락처 로컬파트를 사용합니다")
	}

	log.Info().
		Int("contact_id", int(contactID)).
		Str("conversation_name", roomName).
		Msg("Chatwoot 대화 생성 시도")

	// Chatwoot에 새 대화 생성
	conversation, err := api.Conversations.CreateConversation(ctx, roomID.String(), contactID, customAttrs)
	if err != nil {
		log.Error().
			Err(err).
			Int("contact_id", int(contactID)).
			Str("conversation_name", roomName).
			Msg("Chatwoot 대화 생성 실패")
		return -1, fmt.Errorf("failed to create conversation for contact %d: %w", contactID, err)
	}

	// Matrix 룸과 Chatwoot 대화 ID 연결 저장
	log.Info().
		Int("conversation_id", int(conversation.ID)).
		Stringer("room_id", roomID).
		Msg("Chatwoot 대화 ID와 Matrix 룸 연결 저장")

	// 인박스 ID 가져오기
	inboxIDInt := int(api.InboxID)
	accountIDInt := int(m.DefaultAccountID)

	if err := m.StateStore.UpdateConversationIDForRoom(ctx, roomID, accountIDInt, inboxIDInt, conversation.ID); err != nil {
		log.Error().
			Err(err).
			Int("conversation_id", int(conversation.ID)).
			Stringer("room_id", roomID).
			Msg("Chatwoot 대화 ID와 Matrix 룸 연결 저장 실패")
		return -1, fmt.Errorf("failed to store conversation ID %d for room %s: %w", conversation.ID, roomID, err)
	}

	log.Info().
		Int("chatwoot_conversation_id", int(conversation.ID)).
		Msg("Chatwoot 대화 생성 및 연결 완료")
	return conversation.ID, nil
}



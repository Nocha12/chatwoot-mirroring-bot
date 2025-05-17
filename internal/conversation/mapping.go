package conversation

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// GetOrCreateChatwootConversation은 Matrix 방에 대응하는 Chatwoot 대화를 검색하거나 생성합니다.
func (m *ManagerImpl) GetOrCreateChatwootConversation(ctx context.Context, roomID id.RoomID, evt *event.Event) (chatwootapi.ConversationID, error) {
	log := zerolog.Ctx(ctx).With().Str("method", "GetOrCreateChatwootConversation").Logger()
	ctx = log.WithContext(ctx)

	log.Info().
		Stringer("room_id", roomID).
		Stringer("sender", evt.Sender).
		Msg("대화 ID 찾기 또는 생성 시작")

	conversationID, accountID, err := m.StateStore.GetChatwootConversationIDFromMatrixRoom(ctx, roomID)
	if err == nil {
		log.Info().
			Int("conversation_id", int(conversationID)).
			Int("account_id", int(accountID)).
			Msg("기존 대화 ID 발견")
		return conversationID, nil
	}

	log.Info().
		Err(err).
		Msg("기존 대화 ID를 찾을 수 없어 새로 생성합니다")

	for i := 0; i < 2; i++ {
		log.Info().Int("attempt", i+1).Msg("대화 생성 시도")

		// StateStore 직접 접근 대신 JoinedMembers 메서드 사용
		joinedMembersResp, err := m.Client.JoinedMembers(ctx, roomID)
		var joinedMembers map[id.UserID]struct{}
		if err == nil {
			joinedMembers = make(map[id.UserID]struct{}, len(joinedMembersResp.Joined))
			for userID := range joinedMembersResp.Joined {
				joinedMembers[id.UserID(userID)] = struct{}{}
			}
		}
		if err != nil {
			log.Error().
				Err(err).
				Stringer("room_id", roomID).
				Msg("룸의 참가자 목록을 가져오는데 실패했습니다")
			return -1, fmt.Errorf("failed to get joined members for room %s: %w", roomID, err)
		}
		memberCount := len(joinedMembers)
		log.Info().
			Int("member_count", memberCount).
			Msg("룸 참가자 수 확인")

		if m.BridgeMembersLimit >= 0 && memberCount >= m.BridgeMembersLimit {
			log.Info().
				Int("member_count", memberCount).
				Int("bridge_if_members_less_than", m.BridgeMembersLimit).
				Msg("너무 많은 참가자가 있는 룸을 위한 Chatwoot 대화를 생성하지 않습니다")
			return -1, fmt.Errorf("not creating Chatwoot conversation for room with %d members", memberCount)
		}

		contactMXID := evt.Sender
		if m.Client.UserID() == evt.Sender {
			// 봇으로부터 메시지가 왔습니다. 룸에 있는 다른 사용자를 찾아 사용합니다.
			log.Info().Msg("봇 메시지에 대한 처리: 다른 참가자 검색")
			delete(joinedMembers, evt.Sender)
			if len(joinedMembers) != 1 {
				log.Warn().
					Int("member_count", len(joinedMembers)).
					Msg("DM이 아닌 룸에 대한 Chatwoot 대화를 생성하지 않습니다. 참가자 목록을 다시 가져옵니다")

				// 데이터베이스 상태가 정확하지 않을 수 있으므로, 서버에서 참가자 목록을 다시 가져옵니다.
				membersResp, err := m.Client.JoinedMembers(ctx, roomID)
				if err != nil {
					log.Error().
						Err(err).
						Msg("대화가 DM인지 확인하기 위한 참가자 목록 가져오기 실패")
					return -1, fmt.Errorf("failed to get joined members to verify if this conversation is a non-DM room: %w", err)
				}

				log.Info().
					Int("member_count", len(membersResp.Joined)).
					Interface("joined_users", membersResp.Joined).
					Msg("서버에서 가져온 참가자 목록")

				if len(membersResp.Joined) == 1 {
					// 봇만 룸에 있는 경우 룸을 나갑니다
					log.Warn().Msg("봇만 있는 DM이 아닌 룸이므로 나갑니다")
					_, err := m.Client.LeaveRoom(ctx, roomID)
					if err != nil {
						log.Error().Err(err).Str("room_id", string(roomID)).Msg("방 나가기 실패")
					}
					break
				}
				continue
			}
			for k := range joinedMembers {
				contactMXID = k
				log.Info().
					Stringer("contact_mxid", contactMXID).
					Msg("DM 상대방 사용자 발견")
			}
		}

		log.Warn().Err(err).Msg("기존 Chatwoot 대화를 찾지 못했습니다")
		customAttrs := map[string]string{}
		deviceTypeKey, deviceVersion := m.GetCustomAttrForDevice(ctx, evt)
		if deviceTypeKey != "" && deviceVersion != "" {
			customAttrs[deviceTypeKey] = deviceVersion
			log.Info().
				Str("device_type", deviceTypeKey).
				Str("device_version", deviceVersion).
				Msg("사용자 장치 정보 확인")
		}

		conversationID, err := m.createChatwootConversation(ctx, roomID, contactMXID, customAttrs)
		if err != nil {
			log.Error().
				Err(err).
				Msg("Chatwoot 대화 생성 실패")
			continue
		}

		log.Info().
			Int("conversation_id", int(conversationID)).
			Msg("새 Chatwoot 대화 생성 성공")
		return conversationID, nil
	}

	return -1, fmt.Errorf("no messages found for room suitable for creating conversation")
}

// GetMatrixRoomForChatwootConversation은 Chatwoot 대화에 대응하는 Matrix 방을 검색합니다.
func (m *ManagerImpl) GetMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) (id.RoomID, id.EventID, error) {
	log := zerolog.Ctx(ctx).With().Str("component", "get_matrix_room").Logger()
	ctx = log.WithContext(ctx)

	roomID, mostRecentEventIDStr, err := m.StateStore.GetMatrixRoomFromChatwootConversation(ctx, conversationID, chatwootapi.AccountID(accountID))
	if err != nil {
		log.Warn().Err(err).Msg("대화에 대한 Matrix 방 찾기 실패")
		return "", "", err
	}

	return roomID, id.EventID(fmt.Sprintf("%d", mostRecentEventIDStr)), nil
}

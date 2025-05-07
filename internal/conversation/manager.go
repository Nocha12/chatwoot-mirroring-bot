package conversation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// Manager는 Matrix <-> Chatwoot 대화 연결 관리를 위한 인터페이스입니다.
type Manager interface {
	// GetOrCreateChatwootConversation은 Matrix 방에 대응하는 Chatwoot 대화를 검색하거나 생성합니다.
	GetOrCreateChatwootConversation(ctx context.Context, roomID id.RoomID, evt *event.Event) (chatwootapi.ConversationID, error)

	// GetMatrixRoomForChatwootConversation은 Chatwoot 대화에 대응하는 Matrix 방을 검색합니다.
	GetMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) (id.RoomID, id.EventID, error)

	// BackfillConversationForRoom은 Matrix 방에 대화 기록을 백필합니다.
	BackfillConversationForRoom(ctx context.Context, roomID id.RoomID) error
}

// ManagerImpl은 Manager 인터페이스를 구현하는 구조체입니다.
type ManagerImpl struct {
	Client             matrix.MatrixClient
	StateStore         *database.Database
	GetChatwootAPI     func(accountID chatwootapi.AccountID) *chatwootapi.Client
	DefaultAccountID   chatwootapi.AccountID
	BridgeMembersLimit int // 브릿지할 최대 멤버 수 제한 (이 값 이상이면 브릿지하지 않음)
	createRoomLock     sync.Mutex
}

// NewManager는 새로운 Manager 인스턴스를 생성합니다.
func NewManager(
	client matrix.MatrixClient,
	stateStore *database.Database,
	getChatwootAPI func(accountID chatwootapi.AccountID) *chatwootapi.Client,
	defaultAccountID chatwootapi.AccountID,
	bridgeMembersLimit int,
) *ManagerImpl {
	return &ManagerImpl{
		Client:             client,
		StateStore:         stateStore,
		GetChatwootAPI:     getChatwootAPI,
		DefaultAccountID:   defaultAccountID,
		BridgeMembersLimit: bridgeMembersLimit,
	}
}

// rageshakeIssueRegex는 문제 ID 패턴을 매칭하는 정규표현식입니다.
var rageshakeIssueRegex = regexp.MustCompile(`[A-Z]{1,5}-\d+`)

// GetCustomAttrForDevice는 장치 관련 커스텀 속성을 확인합니다.
func (m *ManagerImpl) GetCustomAttrForDevice(ctx context.Context, evt *event.Event) (string, string) {
	log := zerolog.Ctx(ctx)

	// Rageshake 이슈 ID 확인
	issue := rageshakeIssueRegex.FindString(evt.Content.AsMessage().Body)
	if issue != "" {
		log.Info().Str("issue", issue).Msg("메시지에서 이슈 ID를 발견했습니다")
		return "rageshake_issue", issue
	}

	// 장치 정보 확인
	if strings.Contains(evt.Content.AsMessage().Body, "Browser: ") || strings.Contains(evt.Content.AsMessage().Body, "Platform: ") {
		// rageshake 로그 형식의 디바이스 정보 확인
		return "device_type", "rageshake"
	}

	// 다른 디바이스 정보 확인 로직을 추가할 수 있습니다.

	return "", ""
}

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
					m.Client.LeaveRoom(ctx, roomID)
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
	contactID, err := api.ContactIDForMXID(ctx, contactMXID)
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
		if contactID, err = api.CreateContact(ctx, contactMXID, contactName); err != nil {
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
	conversation, err := api.CreateConversation(ctx, roomID.String(), contactID, customAttrs)
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

// GetMatrixRoomForChatwootConversation은 Chatwoot 대화에 대응하는 Matrix 방을 검색합니다.
func (m *ManagerImpl) GetMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) (id.RoomID, id.EventID, error) {
	log := zerolog.Ctx(ctx).With().Str("component", "get_matrix_room").Logger()
	ctx = log.WithContext(ctx)

	roomID, mostRecentEventIDStr, err := m.StateStore.GetMatrixRoomFromChatwootConversation(ctx, conversationID, chatwootapi.AccountID(accountID))
	if err != nil {
		log.Warn().Err(err).Msg("대화에 대한 Matrix 방 찾기 실패")
		return "", "", err
	}

	return roomID, id.EventID(mostRecentEventIDStr), nil
}

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
	return nil

	return fmt.Errorf("대화 생성에 적합한 메시지를 찾을 수 없습니다")
}

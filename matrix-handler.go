package main

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"

	"github.com/beeper/chatwoot/chatwootapi"
)

var createRoomLock sync.Mutex = sync.Mutex{}

func createChatwootConversation(ctx context.Context, roomID id.RoomID, contactMXID id.UserID, customAttrs map[string]string) (chatwootapi.ConversationID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "create_chatwoot_conversation").
		Stringer("room_id", roomID).
		Stringer("contact_mxid", contactMXID).
		Any("custom_attrs", customAttrs).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Acquired create room lock")
	createRoomLock.Lock()
	defer log.Debug().Msg("Released create room lock")
	defer createRoomLock.Unlock()

	// 먼저 이미 존재하는 대화 ID가 있는지 다시 확인
	if conversationID, err := stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, roomID); err == nil {
		log.Info().
			Int("conversation_id", int(conversationID)).
			Msg("대화가 이미 존재합니다")
		return conversationID, nil
	}

	log.Info().Msg("Chatwoot 연락처 ID 조회 중")
	contactID, err := chatwootAPI.ContactIDForMXID(ctx, contactMXID)
	if err != nil {
		log.Warn().
			Err(err).
			Stringer("contact_mxid", contactMXID).
			Msg("사용자에 대한 연락처 ID를 찾을 수 없습니다. 새로 생성을 시도합니다")

		// Twitter 사용자 이름에 대한 특별한 처리
		contactName := ""
		if strings.HasPrefix(contactMXID.Localpart(), "twitter_") {
			memberEventContent := map[string]any{}
			if err := client.StateEvent(ctx, roomID, event.StateMember, contactMXID.String(), &memberEventContent); err == nil {
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
		if contactID, err = chatwootAPI.CreateContact(ctx, contactMXID, contactName); err != nil {
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
	if err := client.StateEvent(ctx, roomID, event.StateRoomName, "", &roomName); err == nil && roomName != "" {
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
	conversation, err := chatwootAPI.CreateConversation(ctx, roomID.String(), contactID, customAttrs)
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
	if err := stateStore.UpdateConversationIDForRoom(ctx, roomID, conversation.ID); err != nil {
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

func GetCustomAttrForDevice(ctx context.Context, evt *event.Event) (string, string) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_custom_attr_for_device").
		Logger()

	clientType, exists := evt.Content.Raw["com.beeper.origin_client_type"]
	if !exists || clientType == nil {
		log.Debug().Msg("No client type found")
		return "", ""
	}

	var clientTypeString, clientVersionString string
	if ct, ok := clientType.(string); ok {
		clientTypeString = fmt.Sprintf("%s version", ct)
	} else {
		log.Warn().Msg("Client type is not a string")
		return "", ""
	}

	clientVersion, exists := evt.Content.Raw["com.beeper.origin_client_version"]
	if !exists && clientVersion == nil {
		log.Debug().Msg("No client version found")
		return "", ""
	}

	if cv, ok := clientVersion.(string); ok {
		clientVersionString = cv
	} else {
		log.Warn().Msg("Client version is not a string")
		return "", ""
	}

	log.Debug().
		Str("client_type", clientTypeString).
		Str("client_version", clientVersionString).
		Msg("got client type and version")
	return clientTypeString, clientVersionString
}

var rageshakeIssueRegex = regexp.MustCompile(`[A-Z]{1,5}-\d+`)

func HandleMessage(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_message").Logger()
	ctx = log.WithContext(ctx)
	
	log.Info().
		Stringer("room_id", evt.RoomID).
		Stringer("sender", evt.Sender).
		Stringer("event_id", evt.ID).
		Any("content", evt.Content).
		Msg("Matrix 메시지 처리 시작")

	// Acquire the lock, so that we don't have race conditions with the
	// Chatwoot handler.
	if _, found := roomSendlocks[evt.RoomID]; !found {
		log.Debug().Msg("creating send lock")
		roomSendlocks[evt.RoomID] = &sync.Mutex{}
	}
	roomSendlocks[evt.RoomID].Lock()
	log.Debug().Msg("acquired send lock")
	defer log.Debug().Msg("released send lock")
	defer roomSendlocks[evt.RoomID].Unlock()

	if messageIDs, err := stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, evt.ID); err == nil && len(messageIDs) > 0 {
		log.Info().Any("message_ids", messageIDs).Msg("event already has chatwoot messages")
		return
	}

	log.Info().Msg("대화 ID 찾기 또는 생성 시도 중")
	conversationID, err := GetOrCreateChatwootConversation(ctx, evt.RoomID, evt)
	if err != nil {
		log.Error().
			Err(err).
			Stringer("room_id", evt.RoomID).
			Stringer("sender", evt.Sender).
			Msg("Chatwoot 대화 가져오기 또는 생성 실패")
		
		// 실패 원인에 따른 상세 로그 추가
		log.Debug().
			Msg("대화 생성 실패를 처리하기 위한 추가 정보 기록")
		
		// Room 멤버 확인
		joinedMembers, memberErr := client.JoinedMembers(ctx, evt.RoomID)
		if memberErr != nil {
			log.Error().Err(memberErr).Msg("룸 멤버 정보 가져오기 실패")
		} else {
			log.Info().
				Int("member_count", len(joinedMembers.Joined)).
				Interface("joined_members", joinedMembers.Joined).
				Msg("룸 멤버 정보")
		}
		
		// 메시지를 자동으로 보내고 새 대화 생성 시도
		log.Info().Msg("룸에 자동 메시지 전송 및 새 대화 생성 시도")
		_, sendErr := client.SendText(ctx, evt.RoomID, "메시지 수신을 위해 Chatwoot 대화를 생성하는 중입니다...")
		if sendErr != nil {
			log.Error().Err(sendErr).Msg("자동 메시지 전송 실패")
		}
		
		// 다시 시도
		conversationID, err = GetOrCreateChatwootConversation(ctx, evt.RoomID, evt)
		if err != nil {
			log.Error().Err(err).Msg("Chatwoot 대화 생성 재시도 실패")
			return
		}
		log.Info().Msg("두 번째 시도에서 대화 생성 성공")
	}
	
	log.Info().
		Int("conversation_id", int(conversationID)).
		Msg("Matrix 룸에 대한 Chatwoot 대화 ID 찾음")

	// Message content 처리
	var content *event.MessageEventContent
	
	// 암호화된 메시지인 경우 먼저 복호화
	if evt.Type == event.EventEncrypted {
		log.Debug().Msg("암호화된 메시지 처리")
		decryptedEvt, err := client.Crypto.Decrypt(ctx, evt)
		if err != nil {
			log.Error().Err(err).Msg("메시지 복호화 실패")
			return
		}
		log.Info().Msg("메시지 성공적으로 복호화됨")
		content = decryptedEvt.Content.AsMessage()
	} else if evt.Type == event.EventMessage {
		log.Debug().Msg("일반 메시지 처리")
		content = evt.Content.AsMessage()
	} else {
		log.Warn().Stringer("event_type", &evt.Type).Msg("지원되지 않는 이벤트 유형")
		return
	}
	
	if content == nil {
		log.Warn().Msg("메시지 컨텐츠를 추출할 수 없음")
		return
	}
	
	// 메시지 전송 시도
	cm, err := HandleMatrixMessageContent(ctx, evt, conversationID, content)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot로 메시지 전송 실패")
		
		// 오류 발생 시 비공개 메시지로 오류 알림 전송
		DoRetry(ctx, fmt.Sprintf("send private error message to %d for %+v", conversationID, err), func(ctx context.Context) (*chatwootapi.Message, error) {
			msg, err := chatwootAPI.SendPrivateMessage(
				ctx,
				conversationID,
				fmt.Sprintf("**Matrix 메시지 수신 중 오류가 발생했습니다. 메시지를 놓쳤을 수 있습니다!**\n\n오류: %+v", err))
			if err != nil {
				return nil, err
			}
			err = chatwootAPI.ToggleStatus(ctx, conversationID, chatwootapi.ConversationStatusOpen)
			return msg, err
		})
		return
	}
	
	if len(cm) > 0 {
		log.Info().
			Int("chatwoot_messages_count", len(cm)).
			Msg("Chatwoot에 메시지 성공적으로 전송됨")
		
		// Matrix 이벤트 ID와 Chatwoot 메시지 ID 관계 저장
		for _, m := range cm {
			stateStore.SetChatwootMessageIDForMatrixEvent(ctx, evt.ID, m.ID)
		}
		
		// Linear 앱 이슈 링크 처리
		if content.MsgType == event.MsgText || content.MsgType == event.MsgNotice {
			linearLinks := []string{}
			for _, match := range rageshakeIssueRegex.FindAllString(content.Body, -1) {
				linearLinks = append(linearLinks, fmt.Sprintf("https://linear.app/beeper/issue/%s", match))
			}
			if len(linearLinks) > 0 {
				chatwootAPI.SendPrivateMessage(ctx, conversationID, strings.Join(linearLinks, "\n\n"))
			}
		}
	} else {
		log.Warn().Msg("Chatwoot에 전송된 메시지 없음")
	}

	// Asynchronously update the conversation attributes
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conversation, err := chatwootAPI.GetChatwootConversation(ctx, conversationID)
		if err != nil {
			log.Err(err).Msg("failed to get conversation to update custom attributes")
			return
		}
		newCustomAttributes := map[string]string{}
		attrWhitelist := []string{
			"reason",
			"category",
			"subcategory",
			"client",
			"network",
			"internal_note",
		}
		for _, attr := range attrWhitelist {
			if val, ok := conversation.CustomAttributes[attr]; ok {
				newCustomAttributes[attr] = val
			} else {
				newCustomAttributes[attr] = ""
			}
		}
		if err := chatwootAPI.SetConversationCustomAttributes(ctx, conversationID, newCustomAttributes); err != nil {
			log.Err(err).Msg("failed to set conversation custom attributes")
		}
	}()
}

func GetOrCreateChatwootConversation(ctx context.Context, roomID id.RoomID, evt *event.Event) (chatwootapi.ConversationID, error) {
	log := zerolog.Ctx(ctx).With().Str("method", "GetOrCreateChatwootConversation").Logger()
	ctx = log.WithContext(ctx)
	
	log.Info().
		Stringer("room_id", roomID).
		Stringer("sender", evt.Sender).
		Msg("대화 ID 찾기 또는 생성 시작")

	conversationID, err := stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, roomID)
	if err == nil {
		log.Info().
			Int("conversation_id", int(conversationID)).
			Msg("기존 대화 ID 발견")
		return conversationID, nil
	}
	
	log.Info().
		Err(err).
		Msg("기존 대화 ID를 찾을 수 없어 새로 생성합니다")

	for i := 0; i < 2; i++ {
		log.Info().Int("attempt", i+1).Msg("대화 생성 시도")
		
		joinedMembers, err := client.StateStore.(*sqlstatestore.SQLStateStore).GetRoomMembers(ctx, roomID, event.MembershipJoin)
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

		if configuration.BridgeIfMembersLessThan >= 0 && memberCount >= configuration.BridgeIfMembersLessThan {
			log.Info().
				Int("member_count", memberCount).
				Int("bridge_if_members_less_than", configuration.BridgeIfMembersLessThan).
				Msg("너무 많은 참가자가 있는 룸을 위한 Chatwoot 대화를 생성하지 않습니다")
			return -1, fmt.Errorf("not creating Chatwoot conversation for room with %d members", memberCount)
		}

		contactMXID := evt.Sender
		if configuration.Username == evt.Sender {
			// 봇으로부터 메시지가 왔습니다. 룸에 있는 다른 사용자를 찾아 사용합니다.
			log.Info().Msg("봇 메시지에 대한 처리: 다른 참가자 검색")
			delete(joinedMembers, evt.Sender)
			if len(joinedMembers) != 1 {
				log.Warn().
					Int("member_count", len(joinedMembers)).
					Msg("DM이 아닌 룸에 대한 Chatwoot 대화를 생성하지 않습니다. 참가자 목록을 다시 가져옵니다")

				// 데이터베이스 상태가 정확하지 않을 수 있으므로, 서버에서 참가자 목록을 다시 가져옵니다.
				membersResp, err := client.JoinedMembers(ctx, roomID)
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
					client.LeaveRoom(ctx, roomID)
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
		deviceTypeKey, deviceVersion := GetCustomAttrForDevice(ctx, evt)
		if deviceTypeKey != "" && deviceVersion != "" {
			customAttrs[deviceTypeKey] = deviceVersion
			log.Info().
				Str("device_type", deviceTypeKey).
				Str("device_version", deviceVersion).
				Msg("사용자 장치 정보 확인")
		}
		
		conversationID, err := createChatwootConversation(ctx, evt.RoomID, contactMXID, customAttrs)
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

func HandleReaction(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_reaction").
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Logger()
	ctx = log.WithContext(ctx)

	// Acquire the lock, so that we don't have race conditions with the
	// Chatwoot handler.
	if _, found := roomSendlocks[evt.RoomID]; !found {
		log.Debug().Msg("creating send lock")
		roomSendlocks[evt.RoomID] = &sync.Mutex{}
	}
	roomSendlocks[evt.RoomID].Lock()
	log.Debug().Msg("acquiring send lock")
	defer log.Debug().Msg("released send lock")
	defer roomSendlocks[evt.RoomID].Unlock()

	if messageIDs, err := stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, evt.ID); err == nil && len(messageIDs) > 0 {
		log.Info().Any("message_ids", messageIDs).Msg("event already has chatwoot messages")
		return
	}

	conversationID, err := stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("no existing Chatwoot conversation found")
		return
	}

	cm, err := DoRetry(ctx, fmt.Sprintf("send notification of reaction to %d", conversationID), func(context.Context) (*chatwootapi.Message, error) {
		reaction := evt.Content.AsReaction()
		reactedEvent, err := client.GetEvent(ctx, evt.RoomID, reaction.RelatesTo.EventID)
		if err != nil {
			return nil, fmt.Errorf("couldn't find reacted to event %s: %w", reaction.RelatesTo.EventID, err)
		}

		if reactedEvent.Type == event.EventEncrypted {
			err := reactedEvent.Content.ParseRaw(reactedEvent.Type)
			if err != nil {
				return nil, err
			}

			decryptedEvent, err := client.Crypto.Decrypt(ctx, reactedEvent)
			if err != nil {
				return nil, err
			}
			reactedEvent = decryptedEvent
		}

		reactedMessage := reactedEvent.Content.AsMessage()
		var reactedMessageText string
		switch reactedMessage.MsgType {
		case event.MsgText, event.MsgNotice, event.MsgAudio, event.MsgFile, event.MsgImage, event.MsgVideo:
			reactedMessageText = reactedMessage.Body
		case event.MsgEmote:
			localpart, _, _ := evt.Sender.Parse()
			reactedMessageText = fmt.Sprintf(" \\* %s %s", localpart, reactedMessage.Body)
		}
		return chatwootAPI.SendTextMessage(
			ctx,
			conversationID,
			fmt.Sprintf("%s reacted with %s to \"%s\"", evt.Sender, reaction.RelatesTo.Key, reactedMessageText),
			chatwootapi.IncomingMessage)
	})
	if err != nil {
		DoRetry(ctx, fmt.Sprintf("send private error message to %d for %+v", conversationID, err), func(ctx context.Context) (*chatwootapi.Message, error) {
			return chatwootAPI.SendPrivateMessage(
				ctx,
				conversationID,
				fmt.Sprintf("**Error occurred while receiving a Matrix reaction. You may have missed a message reaction!**\n\nError: %+v", err))
		})
		return
	}
	stateStore.SetChatwootMessageIDForMatrixEvent(ctx, evt.ID, (*cm).ID)
}

func downloadAndDecryptMedia(ctx context.Context, content *event.MessageEventContent) ([]byte, error) {
	var file *event.EncryptedFileInfo
	rawMXC := content.URL
	if content.File != nil {
		file = content.File
		rawMXC = file.URL
	}
	mxc, err := rawMXC.Parse()
	if err != nil {
		return nil, fmt.Errorf("malformed content URL: %w", err)
	}

	data, err := client.DownloadBytes(ctx, mxc)
	if err != nil {
		return nil, fmt.Errorf("failed to download media: %w", err)
	}

	if file != nil {
		err = file.DecryptInPlace(data)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt media: %w", err)
		}
	}
	return data, nil
}

// HandleMatrixMessageContent 함수는 Matrix 메시지 내용을 처리하여 Chatwoot로 전송합니다
func HandleMatrixMessageContent(ctx context.Context, evt *event.Event, conversationID chatwootapi.ConversationID, content *event.MessageEventContent) ([]*chatwootapi.Message, error) {
	log := zerolog.Ctx(ctx).With().Str("component", "handle_matrix_content").Logger()
	ctx = log.WithContext(ctx)
	
	log.Info().
		Stringer("room_id", evt.RoomID).
		Stringer("sender", evt.Sender).
		Stringer("event_id", evt.ID).
		Str("msg_type", string(content.MsgType)).
		Msg("Matrix 메시지 내용 처리")
	
	if content == nil {
		return nil, fmt.Errorf("메시지 내용이 비어 있습니다")
	}
	
	// 메시지 타입 결정
	messageType := chatwootapi.IncomingMessage
	if configuration.Username == evt.Sender {
		messageType = chatwootapi.OutgoingMessage
	}
	
	return DoRetryArr(ctx, fmt.Sprintf("handle matrix event %s in conversation %d", evt.ID, conversationID), func(ctx context.Context) ([]*chatwootapi.Message, error) {
		switch content.MsgType {
		case event.MsgText, event.MsgNotice:
			log.Debug().Msg("텍스트 메시지 처리")
			msg, err := chatwootAPI.SendTextMessage(ctx, conversationID, content.Body, messageType)
			if err != nil {
				return nil, err
			}
			return []*chatwootapi.Message{msg}, nil
			
		case event.MsgImage:
			log.Debug().Msg("이미지 메시지 처리")
			return handleMediaMessage(ctx, evt, conversationID, content, "image", messageType)
			
		case event.MsgVideo:
			log.Debug().Msg("비디오 메시지 처리")
			return handleMediaMessage(ctx, evt, conversationID, content, "video", messageType)
			
		case event.MsgAudio:
			log.Debug().Msg("오디오 메시지 처리")
			return handleMediaMessage(ctx, evt, conversationID, content, "audio", messageType)
			
		case event.MsgFile:
			log.Debug().Msg("파일 메시지 처리")
			return handleMediaMessage(ctx, evt, conversationID, content, "file", messageType)
			
		default:
			log.Warn().Str("msg_type", string(content.MsgType)).Msg("지원되지 않는 메시지 유형")
			msg, err := chatwootAPI.SendTextMessage(ctx, conversationID, fmt.Sprintf("지원되지 않는 메시지 유형: %s", content.MsgType), messageType)
			if err != nil {
				return nil, err
			}
			return []*chatwootapi.Message{msg}, nil
		}
	})
}

// handleMediaMessage는 미디어 메시지를 처리합니다 (이미지, 비디오, 오디오, 파일)
func handleMediaMessage(ctx context.Context, evt *event.Event, conversationID chatwootapi.ConversationID, content *event.MessageEventContent, mediaType string, messageType chatwootapi.MessageType) ([]*chatwootapi.Message, error) {
	log := zerolog.Ctx(ctx)
	
	// 미디어 다운로드
	data, err := downloadAndDecryptMedia(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("미디어 다운로드 실패: %w", err)
	}
	
	fileName := content.Body
	if content.FileName != "" {
		fileName = content.FileName
	}
	if fileName == "" {
		fileName = fmt.Sprintf("%s_%s", mediaType, evt.ID)
	}
	
	log.Debug().
		Str("file_name", fileName).
		Int("file_size", len(data)).
		Msg("미디어 파일 다운로드됨")
	
	// 메시지 타입에 따라 적절한 처리
	return DoRetryArr(ctx, fmt.Sprintf("send attachment for event %s in conversation %d", evt.ID, conversationID), func(ctx context.Context) ([]*chatwootapi.Message, error) {
		// 텍스트 설명이 있는 경우 (파일명이 아닌)
		var caption string
		if content.Body != "" && content.Body != fileName {
			caption = content.Body
		}
		
		// MIME 타입 결정
		mimeType := "application/octet-stream"
		if content.Info != nil && content.Info.MimeType != "" {
			mimeType = content.Info.MimeType
		}
		
		// Chatwoot로 메시지 전송
		msg, err := chatwootAPI.SendAttachmentMessage(ctx, conversationID, fileName, mimeType, bytes.NewReader(data), messageType)
		if err != nil {
			return nil, fmt.Errorf("첨부 파일 메시지 전송 실패: %w", err)
		}
		
		messages := []*chatwootapi.Message{msg}
		
		// 캡션이 있는 경우 추가 메시지 전송
		if caption != "" {
			captionMsg, captionErr := chatwootAPI.SendTextMessage(ctx, conversationID, fmt.Sprintf("캡션: %s", caption), messageType)
			if captionErr != nil {
				log.Error().Err(captionErr).Msg("캡션 메시지 전송 실패")
			} else {
				messages = append(messages, captionMsg)
			}
		}
		
		return messages, nil
	})
}

func HandleRedaction(ctx context.Context, evt *event.Event) {
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Logger()
	ctx = log.WithContext(ctx)

	// Acquire the lock, so that we don't have race conditions with the
	// Chatwoot handler.
	if _, found := roomSendlocks[evt.RoomID]; !found {
		log.Debug().Msg("creating send lock")
		roomSendlocks[evt.RoomID] = &sync.Mutex{}
	}
	roomSendlocks[evt.RoomID].Lock()
	log.Debug().Msg("acquired send lock")
	defer log.Debug().Msg("released send lock")
	defer roomSendlocks[evt.RoomID].Unlock()

	messageIDs, err := stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, evt.Redacts)
	if err != nil || len(messageIDs) == 0 {
		log.Err(err).Stringer("redacts", evt.Redacts).Msg("no Chatwoot message for redacted event")
		return
	}

	conversationID, err := stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, evt.RoomID)
	if err != nil {
		log.Err(err).Msg("no Chatwoot conversation associated with room")
		return
	}

	for _, messageID := range messageIDs {
		err = chatwootAPI.DeleteMessage(ctx, conversationID, messageID)
		if err != nil {
			log.Err(err).Msg("failed to delete Chatwoot message")
		}
	}
}

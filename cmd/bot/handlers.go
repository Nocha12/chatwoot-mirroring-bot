package main

import (
	"context"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/conversation"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

// SetupMatrixHandlers는 Matrix 이벤트 핸들러를 설정합니다.
func SetupMatrixHandlers(ctx context.Context, appSetup *setup.AppSetup, roomSendlocks RoomSendLocks) {
	for _, client := range appSetup.MatrixClients {
		// Matrix 어뎁터 생성
		matrixClient := matrix.NewMautrixClientAdapter(client)

		// ChatwootAPIs를 func 형태로 변환
		getChatwootAPI := func(accountID chatwootapi.AccountID) *chatwootapi.Client {
			return appSetup.ChatwootAPIs[accountID]
		}

		// ConversationManager 생성
		convManager := conversation.NewManager(matrixClient, appSetup.DB, getChatwootAPI, appSetup.DefaultAccountID, 100)

		// MessageHelper 생성
		messageHelper := matrix.NewMessageHelper(client, getChatwootAPI, false, appSetup.DB)

		// Matrix 핸들러 생성
		matrixHandler := matrix.NewMatrixHandler(
			matrixClient,
			appSetup.ChatwootAPIs,
			appSetup.DefaultAccountID,
			appSetup.DB,
			messageHelper,
			convManager,
		)

		// Syncer 가져오기
		syncer := client.Syncer.(*mautrix.DefaultSyncer)

		// 이벤트 핸들러 등록
		registerEventHandlers(ctx, syncer, matrixHandler, client)
	}
}

// registerEventHandlers는 Matrix 이벤트 핸들러를 등록합니다.
func registerEventHandlers(ctx context.Context, syncer *mautrix.DefaultSyncer, matrixHandler *matrix.MatrixHandler, client *mautrix.Client) {
	// 메시지 이벤트 핸들러
	syncer.OnEventType(event.EventMessage, func(ctx context.Context, evt *event.Event) {
		log := zerolog.Ctx(ctx).With().Str("component", "matrix_message_handler").Logger()
		ctx = log.WithContext(ctx)
		matrixHandler.HandleMessage(ctx, evt)
	})

	// 리액션 이벤트 핸들러
	syncer.OnEventType(event.EventReaction, func(ctx context.Context, evt *event.Event) {
		log := zerolog.Ctx(ctx).With().Str("component", "matrix_reaction_handler").Logger()
		ctx = log.WithContext(ctx)
		matrixHandler.HandleReaction(ctx, evt)
	})

	// 삭제 이벤트 핸들러
	syncer.OnEventType(event.EventRedaction, func(ctx context.Context, evt *event.Event) {
		log := zerolog.Ctx(ctx).With().Str("component", "matrix_redaction_handler").Logger()
		ctx = log.WithContext(ctx)
		matrixHandler.HandleRedaction(ctx, evt)
	})

	// 초대 수락 핸들러
	syncer.OnEventType(event.StateMember, func(ctx context.Context, evt *event.Event) {
		if evt.StateKey != nil && *evt.StateKey == string(client.UserID) && evt.Content.AsMember().Membership == event.MembershipInvite {
			log := zerolog.Ctx(ctx).With().Str("component", "room_invite_handler").Stringer("room_id", evt.RoomID).Logger()
			ctx = log.WithContext(ctx)
			log.Info().Msg("방 초대 받음, 수락 중")

			_, err := client.JoinRoom(ctx, string(evt.RoomID), &mautrix.ReqJoinRoom{})
			if err != nil {
				log.Error().Err(err).Msg("방 참가 실패")
			} else {
				log.Info().Msg("방 참가 성공")
			}
		}
	})
}

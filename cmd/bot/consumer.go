package main

import (
	"context"
	"time"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/chatwoot"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/conversation"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/oci"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
)

// StartConsumerLoop 는 스트림에서 메시지를 읽어 기존 처리 로직을 호출합니다.
func StartConsumerLoop(ctx context.Context, appSetup *setup.AppSetup) {
	producer := appSetup.OCIProducer
	consumer := appSetup.OCIConsumer
	if consumer == nil {
		return
	}

	go func() {
		log := zerolog.Ctx(ctx)
		for {
			events, err := consumer.GetEvents(ctx)
			if err != nil {
				log.Error().Err(err).Msg("스트림 메시지 읽기 실패")
				time.Sleep(time.Second)
				continue
			}
			for _, evt := range events {
				handleQueuedEvent(ctx, appSetup, evt)
			}
		}
	}()
	_ = producer
}

func handleQueuedEvent(ctx context.Context, appSetup *setup.AppSetup, evt oci.QueuedEvent) {
	switch evt.Type {
	case oci.MatrixMessageEvent:
		for _, client := range appSetup.MatrixClients {
			if evt.MatrixEvent != nil {
				mh := matrix.NewMatrixHandler(
					matrix.NewMautrixClientAdapter(client),
					appSetup.ChatwootAPIs,
					appSetup.DefaultAccountID,
					appSetup.DB,
					matrix.NewMessageHelper(client, func(id chatwootapi.AccountID) *chatwootapi.Client { return appSetup.ChatwootAPIs[id] }, false, appSetup.DB),
					conversation.NewManager(matrix.NewMautrixClientAdapter(client), appSetup.DB, func(id chatwootapi.AccountID) *chatwootapi.Client { return appSetup.ChatwootAPIs[id] }, appSetup.DefaultAccountID, 100),
				)
				mh.HandleMessage(ctx, evt.MatrixEvent)
			}
		}
	case oci.MatrixReactionEvent:
		if evt.MatrixEvent != nil {
			// 단일 클라이언트만 사용
			client := appSetup.Client
			mh := matrix.NewMatrixHandler(
				matrix.NewMautrixClientAdapter(client),
				appSetup.ChatwootAPIs,
				appSetup.DefaultAccountID,
				appSetup.DB,
				matrix.NewMessageHelper(client, func(id chatwootapi.AccountID) *chatwootapi.Client { return appSetup.ChatwootAPIs[id] }, false, appSetup.DB),
				conversation.NewManager(matrix.NewMautrixClientAdapter(client), appSetup.DB, func(id chatwootapi.AccountID) *chatwootapi.Client { return appSetup.ChatwootAPIs[id] }, appSetup.DefaultAccountID, 100),
			)
			mh.HandleReaction(ctx, evt.MatrixEvent)
		}
	case oci.MatrixRedactionEvent:
		if evt.MatrixEvent != nil {
			client := appSetup.Client
			mh := matrix.NewMatrixHandler(
				matrix.NewMautrixClientAdapter(client),
				appSetup.ChatwootAPIs,
				appSetup.DefaultAccountID,
				appSetup.DB,
				matrix.NewMessageHelper(client, func(id chatwootapi.AccountID) *chatwootapi.Client { return appSetup.ChatwootAPIs[id] }, false, appSetup.DB),
				conversation.NewManager(matrix.NewMautrixClientAdapter(client), appSetup.DB, func(id chatwootapi.AccountID) *chatwootapi.Client { return appSetup.ChatwootAPIs[id] }, appSetup.DefaultAccountID, 100),
			)
			mh.HandleRedaction(ctx, evt.MatrixEvent)
		}
	case oci.ChatwootMessageEvent:
		if evt.ChatwootEvent != nil {
			mh := chatwoot.NewMessageHandler(
				func(acc chatwootapi.AccountID, inbox chatwootapi.InboxID) *mautrix.Client {
					client, _ := appSetup.MatrixClientForChatwootAccount(ctx, acc, inbox)
					return client
				},
				appSetup.DB,
				appSetup.ChatwootAPIs,
				func(acc chatwootapi.AccountID) *chatwootapi.Client {
					return setup.GetChatwootAPIForAccount(appSetup.ChatwootAPIs, acc, appSetup.DefaultAccountID)
				},
				NewRoomSendLocks(),
			)
			_ = mh.HandleMessageCreated(ctx, *evt.ChatwootEvent)
		}
	}
}

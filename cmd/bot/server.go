package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/chatwoot"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

// StartWebhookServer는 웹훅 서버를 시작합니다.
func StartWebhookServer(ctx context.Context, appSetup *setup.AppSetup, roomSendlocks RoomSendLocks) {
	log := zerolog.Ctx(ctx)
	
	// 웹훅 리스너 설정
	messageHandler := chatwoot.NewMessageHandler(
		appSetup.Client,
		appSetup.DB,
		appSetup.ChatwootAPIs,
		func(accountID chatwootapi.AccountID) *chatwootapi.Client {
			return setup.GetChatwootAPIForAccount(
				appSetup.ChatwootAPIs,
				accountID,
				appSetup.DefaultAccountID,
			)
		},
		roomSendlocks,
	)
	webhookHandler := chatwoot.NewWebhookHandler(messageHandler, appSetup.OCIProducer)

	router := http.NewServeMux()
	router.HandleFunc("/chatwoot", webhookHandler.HandleWebhook)

	// HTTP 로그 핸들러 설정
	handler := hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Debug().Int("status", status).Int("size", size).Dur("duration", duration).Str("method", r.Method).Stringer("url", r.URL).Msg("")
	})(router)

	http.Handle("/", handler)
	http.Handle("/webhook", handler)
	log.Info().Int("listen_port", appSetup.Config.HTTPListenPort).Msg("웹훅 리스너 시작 중")
	
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", appSetup.Config.HTTPListenPort), nil)
		if err != nil {
			log.Error().Err(err).Msg("웹훅 리스너 생성 실패")
		}
	}()
}

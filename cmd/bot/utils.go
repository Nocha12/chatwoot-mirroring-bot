package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/util"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
)

// VerifyFromAuthorizedUser는 사용자가 인증된 사용자인지 확인합니다.
func VerifyFromAuthorizedUser(ctx context.Context, sender id.UserID) bool {
	return setup.VerifyFromAuthorizedUser(ctx, sender)
}

// DoRetry는 지정된 작업을 재시도합니다.
func DoRetry[T any](ctx context.Context, action string, fn func(context.Context) (T, error)) (T, error) {
	return util.DoRetry(ctx, action, fn)
}

// SetupSignalHandler는 종료 신호를 처리하는 핸들러를 설정합니다.
func SetupSignalHandler(ctx context.Context, appSetup *setup.AppSetup) {
	log := zerolog.Ctx(ctx)

	// 정상 종료 보장
	c := make(chan os.Signal, 1)
	signal.Notify(c,
		syscall.SIGABRT,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGQUIT,
		syscall.SIGTERM,
	)
	
	go func() {
		for range c { // 프로세스가 종료될 때
			log.Info().Msg("정리 중...")
			// DB 연결 종료
			if appSetup.DB != nil && appSetup.DB.DB != nil {
				_ = appSetup.DB.DB.Close()
			}
			os.Exit(0)
		}
	}()
}

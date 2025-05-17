// callbacks_and_shutdown.go
package setup

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// SetupCallbacks는 복호화 오류 및 키 공유 콜백을 설정합니다.
func SetupCallbacks(
	cryptoHelper *cryptohelper.CryptoHelper,
	log zerolog.Logger,
	stateStore matrix.StateStore,
	chatwootAPIs map[chatwootapi.AccountID]*chatwootapi.Client,
	defaultAccountID chatwootapi.AccountID,
) {
	// 복호화 오류 콜백
	cryptoHelper.DecryptErrorCallback = func(evt *event.Event, decryptErr error) {
		evtLog := log.With().
			Str("sender", string(evt.Sender)).
			Str("type", evt.Type.Type).
			Stringer("room_id", evt.RoomID).
			Str("event_id", string(evt.ID)).
			Logger()
		ctx := evtLog.WithContext(context.Background())
		evtLog.Error().Err(decryptErr).Msg("메시지 복호화 실패")

		// 최근 이벤트 ID 저장
		if err := stateStore.UpdateMostRecentEventIDForRoom(ctx, evt.RoomID, evt.ID); err != nil {
			evtLog.Error().Err(err).Msg("최근 이벤트 ID 저장 실패")
		}

		// 권한 확인
		if !VerifyFromAuthorizedUser(ctx, evt.Sender) {
			return
		}

		convID, accountID, err := stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, evt.RoomID)
		if err != nil {
			evtLog.Warn().Err(err).Msg("이 방과 연결된 Chatwoot 대화가 없습니다")
			return
		}

		// 세션 키 요청 로깅
		evtLog.Info().Msg("세션 키 요청 시도")
		if enc, ok := evt.Content.Raw["encrypted"].(map[string]interface{}); ok {
			if alg, exists := enc["algorithm"].(string); exists && alg == string(id.AlgorithmMegolmV1) {
				if sid, ok := enc["session_id"].(string); ok {
					evtLog.Info().Str("session_id", sid).Msg("Megolm 세션 키 요청")
				}
			}
		}

		// API 클라이언트 가져오기
		api := GetChatwootAPIForAccount(chatwootAPIs, accountID, defaultAccountID)

		// 비공개 오류 메시지 전송 재시도
		_, retryErr := DoRetry(ctx,
			fmt.Sprintf("send private error message to %d for %+v", convID, decryptErr),
			func(ctx context.Context) (interface{}, error) {
				_, err := api.Messages.SendPrivateMessage(
					ctx,
					convID,
					fmt.Sprintf("**Matrix 이벤트 (%s) 복호화 실패**: %v", evt.ID, decryptErr),
				)
				return nil, err
			},
		)
		if retryErr != nil {
			evtLog.Error().Err(retryErr).Msg("비공개 오류 메시지 전송 재시도 실패")
		}
	}

	// 키 공유 요청 자동 허용
	cryptoHelper.Machine().AllowKeyShare = func(ctx context.Context, device *id.Device, info event.RequestedKeyInfo) *crypto.KeyShareRejection {
		log := zerolog.Ctx(ctx)
		log.Info().
			Str("user_id", device.UserID.String()).
			Str("device_id", device.DeviceID.String()).
			Str("session_id", string(info.SessionID)).
			Msg("키 공유 요청 허용됨")
		return nil
	}
}

// SetupShutdownHandler는 종료 신호 수신 시 자원 정리를 수행합니다.
func SetupShutdownHandler(
	ctx context.Context,
	client interface { /* *mautrix.Client type */
	},
	cryptoHelper *cryptohelper.CryptoHelper,
	stateStore matrix.StateStore,
	log zerolog.Logger,
) {
	var (
		syncCancel context.CancelFunc
		wg         sync.WaitGroup
	)
	_, syncCancel = context.WithCancel(ctx)
	wg.Add(1)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		sig := <-c
		log.Info().Str("signal", sig.String()).Msg("종료 신호 수신, 정리 중...")

		// 동기화 취소
		syncCancel()
		log.Debug().Msg("동기화 중단")

		// 암호화 헬퍼 종료
		if err := cryptoHelper.Close(); err != nil {
			log.Error().Err(err).Msg("암호화 헬퍼 종료 오류")
		}

		// 동기화 종료 대기
		wg.Wait()
		log.Info().Msg("안전하게 종료됨")
		os.Exit(0)
	}()
}

// VerifyFromAuthorizedUser는 사용자가 적절한 권한을 가지고 있는지 확인합니다.
func VerifyFromAuthorizedUser(ctx context.Context, sender id.UserID) bool {
	// TODO: 권한 확인 로직 구현
	return true
}

// DoRetry는 함수 실행을 재시도합니다.
func DoRetry(ctx context.Context, action string, fn func(context.Context) (interface{}, error)) (interface{}, error) {
	log := zerolog.Ctx(ctx)
	var result interface{}
	var err error
	for i := 0; i < 5; i++ {
		if i > 0 {
			log.Debug().Int("attempt", i+1).Msg(fmt.Sprintf("재시도 중: %s", action))
		}
		result, err = fn(ctx)
		if err == nil {
			return result, nil
		}
		log.Error().Err(err).Msg(fmt.Sprintf("실패: %s", action))
	}
	return nil, fmt.Errorf("최대 재시도 초과: %s: %w", action, err)
}

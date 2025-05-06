package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/chatwoot"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/util"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"


	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// 전역 변수 정의
var VERSION = "0.2.1"

// Chatwoot 대화 ID 저장을 위한 상태 이벤트 타입
var chatwootConversationIDType = event.Type{
	Type:  "com.beeper.chatwoot.conversation_id",
	Class: event.StateEventType,
}

// ChatwootConversationIDEventContent는 Chatwoot 대화 ID를 저장하는 이벤트 컨텐츠입니다.
type ChatwootConversationIDEventContent struct {
	ConversationID chatwootapi.ConversationID `json:"conversation_id"`
}

// 방 동기화를 위한 락 관리
var roomSendlocks map[id.RoomID]*sync.Mutex

func main() {
	// 설정 파일 경로 인자 파싱
	configPath := flag.String("config", "./config.yaml", "설정 파일 위치")
	flag.Parse()

	// 초기 로깅 설정
	log.Info().Str("config_path", *configPath).Msg("설정 파일 읽는 중")

	// 애플리케이션 설정 초기화
	appSetup, err := setup.SetupApp(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("애플리케이션 설정 초기화 실패")
	}

	log := appSetup.Log
	ctx := log.WithContext(context.TODO())

	// 방 동기화 락 초기화
	roomSendlocks = map[id.RoomID]*sync.Mutex{}

	// 종료 핸들러 설정
	setup.SetupShutdownHandler(ctx, log, appSetup.Client, appSetup.CryptoHelper)

	// 이벤트 핸들러 등록
	// 매트릭스 핸들러 설정 (현재는 사용하지 않지만 추후 구현을 위해 준비)
	// TODO: Matrix 핸들링 구현 완료 후 주석 해제

	// Make sure that there are conversations for all of the rooms that the bot
	// is in.
	// This is run every 24 hours.
	go func() {
		if !appSetup.Config.Backfill.ChatwootConversations && !appSetup.Config.Backfill.ConversationIDStateEvents {
			return
		}

		for {
			log := log.With().Str("component", "conversation_creation_backfill").Logger()
			ctx := log.WithContext(context.Background())

			log.Info().Msg("시작: 아직 대화가 없는 방에 대한 대화 생성")

			joined, err := appSetup.Client.JoinedRooms(ctx)
			if err != nil {
				log.Fatal().Err(err).Msg("참여한 방 목록 가져오기 실패")
			}

			for _, roomID := range joined.JoinedRooms {
				conversationID, _, err := appSetup.DB.GetChatwootConversationIDFromMatrixRoom(ctx, roomID)
				if err != nil {
					// 이 방에는 아직 Chatwoot 대화가 연결되어 있지 않음
					if appSetup.Config.Backfill.ChatwootConversations {
						err = backfillConversationForRoom(ctx, roomID, appSetup.Client)
						if err != nil {
							log.Warn().Err(err).Msg("방에 대한 대화 백필 실패")
							continue
						}
					}
				} else if appSetup.Config.Backfill.ConversationIDStateEvents {
					// 이미 Chatwoot 대화가 있는 경우, 해당 방에 Chatwoot 대화 ID가 포함된
					// 상태 이벤트가 있는지 확인합니다.
					_, err = appSetup.Client.SendStateEvent(ctx, roomID, chatwootConversationIDType, "", ChatwootConversationIDEventContent{
						ConversationID: conversationID,
					})
					if err != nil {
						log.Warn().Err(err).Msg("대화 ID 상태 이벤트 전송 실패")
					}
				}
			}

			log.Info().Msg("완료: 아직 대화가 없는 방에 대한 대화 생성... 24시간 후 다시 백필 시작")
			time.Sleep(24 * time.Hour)
		}
	}()

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

	// 웹훅 리스너 설정
	// TODO: MessageHandler 생성자 구현 수정 필요
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
	webhookHandler := chatwoot.NewWebhookHandler(messageHandler)

	router := http.NewServeMux()
	router.HandleFunc("/chatwoot", webhookHandler.HandleWebhook)

	// HTTP 로그 핸들러 설정
	handler := hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Debug().Int("status", status).Int("size", size).Dur("duration", duration).Str("method", r.Method).Stringer("url", r.URL).Msg("")
	})(router)

	http.Handle("/", handler)
	http.Handle("/webhook", handler)
	log.Info().Int("listen_port", appSetup.Config.HTTPListenPort).Msg("웹훅 리스너 시작 중")
	err = http.ListenAndServe(fmt.Sprintf(":%d", appSetup.Config.HTTPListenPort), nil)
	if err != nil {
		log.Error().Err(err).Msg("웹훅 리스너 생성 실패")
	}

	// 종료 시 정리
	err = appSetup.CryptoHelper.Close()
	if err != nil {
		log.Error().Err(err).Msg("암호화 헬퍼 닫기 오류")
	}
}

func backfillConversationForRoom(ctx context.Context, roomID id.RoomID, client *mautrix.Client) error {
	log := zerolog.Ctx(ctx).With().Stringer("room_id", roomID).Logger()
	ctx = log.WithContext(ctx)

	log.Info().Msg("방에 대한 대화 생성 중")

	// 대화 생성을 위한 룸 정보 가져오기
	// 룸 이름 가져오기
	var roomName string
	var roomNameContent event.RoomNameEventContent
	var err error
	err = client.StateEvent(ctx, roomID, event.StateRoomName, "", &roomNameContent)
	if err == nil && roomNameContent.Name != "" {
		roomName = roomNameContent.Name
	} else {
		log.Debug().Err(err).Msg("방 이름 이벤트 가져오기 실패")
	}

	// 방 이름이 없는 경우 참가자 수 기반으로 이름 생성
	if roomName == "" {
		// 현재 참가자 목록 가져오기
		members := 0
		joinResp, err := client.JoinedMembers(ctx, roomID)
		if err == nil && joinResp != nil {
			members = len(joinResp.Joined)
		} else {
			log.Debug().Err(err).Msg("방 참가자 목록 가져오기 실패")
			// 기본값 2명(봇 + 사용자)
			members = 2
		}
		roomName = fmt.Sprintf("Matrix 채팅 (%d명 참가자)", members)
	}

	// 기본 계정 ID 사용 (여러 계정 관리는 추후 구현)
	// 이 기능은 아직 구현되지 않았으므로 가장 기본적인 로그만 출력
	log.Info().Str("roomName", roomName).Msg("새 Chatwoot 대화 생성 필요")
	return nil
}

func VerifyFromAuthorizedUser(ctx context.Context, sender id.UserID) bool {
	return setup.VerifyFromAuthorizedUser(ctx, sender)
}

func DoRetry[T any](ctx context.Context, action string, fn func(context.Context) (T, error)) (T, error) {
	return util.DoRetry(ctx, action, fn)
}

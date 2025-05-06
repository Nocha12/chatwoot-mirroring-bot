package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// AppSetup 구조체는 애플리케이션 설정 및 공유 객체를 담고 있습니다.
type AppSetup struct {
	Log              zerolog.Logger
	Config           *config.Configuration
	DB               *database.Database
	Client           *mautrix.Client
	CryptoHelper     *cryptohelper.CryptoHelper
	ChatwootAPIs     map[chatwootapi.AccountID]*chatwootapi.Client
	DefaultAccountID chatwootapi.AccountID
}

// SetupApp는 애플리케이션의 주요 구성 요소를 초기화합니다.
func SetupApp(configPath string) (*AppSetup, error) {
	// 설정 파일 로드
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 로드 실패: %w", err)
	}

	// 로깅 설정
	logLevelStr := cfg.LogLevel
	if logLevelStr == "" {
		logLevelStr = "info" // 기본값
	}
	logLevel, err := zerolog.ParseLevel(logLevelStr)
	if err != nil {
		return nil, fmt.Errorf("로그 레벨 파싱 실패: %w", err)
	}

	zerolog.SetGlobalLevel(logLevel)
	var log zerolog.Logger
	if cfg.LogJSON {
		log = zerolog.New(os.Stdout)
	} else {
		log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	}

	if cfg.LogTime {
		log = log.With().Timestamp().Logger()
	}

	if cfg.LogCaller {
		log = log.With().Caller().Logger()
	}

	log.Info().Any("config", cfg).Msg("설정 로드 완료")
	log.Info().Msg("Chatwoot 미러링 봇 시작 중...")

	// 데이터베이스 초기화
	db, err := dbutil.NewFromConfig("chatwoot", cfg.Database, dbutil.ZeroLogger(log))
	if err != nil {
		return nil, fmt.Errorf("데이터베이스 연결 실패: %w", err)
	}

	// 상태 저장소 초기화
	stateStore := database.NewDatabase()
	if err := stateStore.Connect(cfg.Database.Type, cfg.Database.URI); err != nil {
		return nil, fmt.Errorf("데이터베이스 연결 실패: %w", err)
	}
	ctx := log.WithContext(context.Background())
	if err := stateStore.Upgrade(ctx); err != nil {
		return nil, fmt.Errorf("데이터베이스 업그레이드 실패: %w", err)
	}

	// Matrix 클라이언트 초기화
	client, err := mautrix.NewClient(cfg.Homeserver, "", "")
	if err != nil {
		return nil, fmt.Errorf("Matrix 클라이언트 생성 실패: %w", err)
	}
	client.Log = log

	// 암호화 헬퍼 초기화
	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("chatwoot_cryptostore_key"), db)
	if err != nil {
		return nil, fmt.Errorf("암호화 헬퍼 생성 실패: %w", err)
	}

	// 로그인 정보 설정
	password, err := cfg.GetPassword(&log)
	if err != nil {
		return nil, fmt.Errorf("비밀번호 가져오기 실패: %w", err)
	}

	cryptoHelper.LoginAs = &mautrix.ReqLogin{
		Type:       mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: cfg.Username.String()},
		Password:   password,
	}
	cryptoHelper.DBAccountID = cfg.Username.String()

	// 암호화 초기화
	if err = cryptoHelper.Init(ctx); err != nil {
		return nil, fmt.Errorf("암호화 헬퍼 초기화 실패: %w", err)
	}

	// 클라이언트에 암호화 활성화
	client.Crypto = cryptoHelper

	// Chatwoot API 클라이언트 맵 초기화
	chatwootAPIs := make(map[chatwootapi.AccountID]*chatwootapi.Client)
	var defaultAccountID chatwootapi.AccountID

	// 계정 설정 처리
	for i, accCfg := range cfg.ChatwootAccounts {
		// 토큰 파일 확인
		tokenFilePath := accCfg.AccessTokenFile
		if tokenFilePath == "" {
			return nil, fmt.Errorf("계정 %d의 액세스 토큰 파일이 없습니다", accCfg.AccountID)
		}

		// 토큰 파일 읽기
		tokenBytes, err := os.ReadFile(tokenFilePath)
		if err != nil {
			return nil, fmt.Errorf("액세스 토큰 파일 읽기 실패: %w", err)
		}
		accessToken := strings.TrimSpace(string(tokenBytes))

		// 첫 번째 계정을 기본값으로 설정
		if i == 0 {
			defaultAccountID = accCfg.AccountID
		}

		// API 클라이언트 생성 및 맵에 추가
		baseURL := accCfg.BaseUrl
		if baseURL == "" {
			baseURL = cfg.ChatwootBaseUrl
		}

		// API 클라이언트 생성
		chatwootAPIs[accCfg.AccountID] = chatwootapi.NewClient(
			baseURL,
			accCfg.AccountID,
			accCfg.InboxID,
			accessToken,
		)
	}

	// 클라이언트 맵이 비었으면 오류 반환
	if len(chatwootAPIs) == 0 {
		return nil, errors.New("Chatwoot 계정 설정이 없습니다")
	}

	// 이벤트 핸들러 설정
	setupDecryptErrorCallback(cryptoHelper, log, stateStore, chatwootAPIs, defaultAccountID)
	setupKeyShareCallback(cryptoHelper)

	// AppSetup 반환
	return &AppSetup{
		Log:              log,
		Config:           cfg,
		DB:               stateStore,
		Client:           client,
		CryptoHelper:     cryptoHelper,
		ChatwootAPIs:     chatwootAPIs,
		DefaultAccountID: defaultAccountID,
	}, nil
}

// SetupShutdownHandler는 종료 신호를 처리하는 핸들러를 설정합니다.
func SetupShutdownHandler(ctx context.Context, client *mautrix.Client, cryptoHelper *cryptohelper.CryptoHelper, stateStore matrix.StateStore, log zerolog.Logger) {
	var syncCancel context.CancelFunc
	var syncStopWait sync.WaitGroup

	// 신호 처리를 위한 컨텍스트 생성
	syncCtx, syncCancel := context.WithCancel(ctx)
	syncStopWait.Add(1)

	// 종료 신호 수신 채널 설정
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
		syncStopWait.Wait()
		log.Info().Msg("안전하게 종료됨")
		os.Exit(0)
	}()
}

// setupDecryptErrorCallback은 암호화 이벤트 처리 오류 콜백을 설정합니다.
func setupDecryptErrorCallback(
	cryptoHelper *cryptohelper.CryptoHelper,
	log zerolog.Logger,
	stateStore matrix.StateStore,
	chatwootAPIs map[chatwootapi.AccountID]*chatwootapi.Client,
	defaultAccountID chatwootapi.AccountID,
) {
	// 복호화 오류 콜백에서는 이벤트 리스너를 설정할 필요가 없습니다.

	// 복호화 오류 콜백 설정
	cryptoHelper.DecryptErrorCallback = func(evt *event.Event, decryptErr error) {
		// 이벤트 로그 생성
		evtLog := log.With().
			Str("sender", string(evt.Sender)).
			Str("type", evt.Type.Type).
			Stringer("room_id", evt.RoomID).
			Str("event_id", string(evt.ID)).
			Logger()
		ctx := evtLog.WithContext(context.Background())
		evtLog.Error().Err(decryptErr).Msg("메시지 복호화 실패")

		// 오류 세부 정보 기록
		evtLog.Debug().
			Stringer("room_id", evt.RoomID).
			Stringer("sender", evt.Sender).
			Stringer("event_id", evt.ID).
			Str("error_type", fmt.Sprintf("%T", decryptErr)).
			Msg("복호화 오류 세부 정보")

		stateStore.UpdateMostRecentEventIDForRoom(ctx, evt.RoomID, evt.ID)

		// 권한 확인
		if !VerifyFromAuthorizedUser(ctx, evt.Sender) {
			return
		}

		conversationID, accountIDStr, err := stateStore.GetChatwootConversationIDFromMatrixRoom(ctx, evt.RoomID)
		if err != nil {
			evtLog.Warn().Err(err).Msg("이 방과 연결된 Chatwoot 대화가 없습니다")
			return
		}

		// 세션 키 요청 시도
		evtLog.Info().Msg("세션 키 요청 시도")
		if encryptedEvt, ok := evt.Content.Raw["encrypted"].(map[string]interface{}); ok {
			if alg, exists := encryptedEvt["algorithm"].(string); exists && alg == id.AlgorithmMegolmV1.String() {
				sessionID, _ := encryptedEvt["session_id"].(string)
				evtLog.Info().
					Str("session_id", sessionID).
					Msg("Megolm 세션 키 요청")
			}
		}

		// 계정 ID 변환
		acIDInt, err := strconv.Atoi(accountIDStr)
		if err != nil {
			evtLog.Error().Err(err).Str("account_id", accountIDStr).Msg("계정 ID 변환 실패")
			return
		}
		accountID := chatwootapi.AccountID(acIDInt)

		// API 클라이언트 가져오기
		api := GetChatwootAPIForAccount(chatwootAPIs, accountID, defaultAccountID)

		// 비공개 오류 메시지 전송
		DoRetry(ctx,
			fmt.Sprintf("send private error message to %d for %+v", conversationID, decryptErr),
			func(ctx context.Context) (*chatwootapi.Message, error) {
				return api.SendPrivateMessage(
					ctx,
					conversationID,
					fmt.Sprintf("**Matrix 이벤트 (%s) 복호화 실패. 메시지를 받지 못했을 수 있습니다!**\n\n오류: %+v", evt.ID, decryptErr))
			})
	}
}

// setupKeyShareCallback은 키 공유 허용 설정을 합니다.
func setupKeyShareCallback(cryptoHelper *cryptohelper.CryptoHelper) {
	// 모든 키 공유 요청 허용
	cryptoHelper.Machine().AllowKeyShare = func(ctx context.Context, device *id.Device, info *mautrix.RequestedKeyInfo) *mautrix.KeyShareRejection {
		log := zerolog.Ctx(ctx)

		// 키 공유 요청에 대해 자세한 로그 추가
		log.Info().
			Str("user_id", device.UserID.String()).
			Str("device_id", device.DeviceID.String()).
			Str("session_id", info.SessionID).
			Msg("키 공유 요청 허용됨")

		// 거부 없이 null 반환 = 허용
		return nil
	}
}

// VerifyFromAuthorizedUser는 사용자가 적절한 권한을 가지고 있는지 확인합니다.
func VerifyFromAuthorizedUser(ctx context.Context, sender id.UserID) bool {
	// TODO: 권한 확인 로직 구현
	return true
}

// DoRetry는 함수 실행을 재시도하는 범용 헬퍼 함수입니다.
func DoRetry[T any](ctx context.Context, action string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	log := zerolog.Ctx(ctx)

	var err error
	var result T

	for i := 0; i < 5; i++ {
		if i > 0 {
			log.Debug().Int("attempt", i+1).Msg(fmt.Sprintf("재시도 중: %s", action))
		}

		result, err = fn(ctx)
		if err == nil {
			return result, nil
		}

		log.Error().Err(err).Int("attempt", i+1).Msg(fmt.Sprintf("실패: %s", action))
	}

	return zero, fmt.Errorf("최대 재시도 횟수 초과: %s: %w", action, err)
}

// GetChatwootAPIForAccount는 지정된 계정 ID에 대한 API 클라이언트를 반환합니다.
func GetChatwootAPIForAccount(
	chatwootAPIs map[chatwootapi.AccountID]*chatwootapi.Client,
	accountID chatwootapi.AccountID,
	defaultAccountID chatwootapi.AccountID,
) *chatwootapi.Client {
	if accountID <= 0 {
		// 유효하지 않은 계정 ID는 기본 계정 사용
		accountID = defaultAccountID
	}

	api, exists := chatwootAPIs[accountID]
	if !exists {
		// 해당 계정 ID에 대한 API 클라이언트가 없으면 기본 계정 사용
		api = chatwootAPIs[defaultAccountID]
	}

	return api
}

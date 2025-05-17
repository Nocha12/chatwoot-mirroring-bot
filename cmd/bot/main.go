package main

import (
	"context"
	"flag"
	"os"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/setup"
	"github.com/rs/zerolog"
)

func main() {
	// 설정 파일 경로 인자 파싱
	configPath := flag.String("config", "./config.yaml", "설정 파일 위치")
	useDb := flag.Bool("use-db", false, "데이터베이스에서 설정 불러오기 (활성화시 파일 설정 무시)")
	dbConfigPath := flag.String("db-config", "./db_config.yaml", "DB 설정 파일 경로")
	flag.Parse()

	// 초기 로깅 설정
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// 설정 불러오기 방식 결정
	var actualConfigPath string
	if *useDb {
		logger.Info().Msg("데이터베이스에서 설정 불러오기 모드를 사용합니다")
		if err := os.Setenv("DB_CONFIG_PATH", *dbConfigPath); err != nil {
			logger.Error().Err(err).Msg("환경 변수 설정 실패")
		}
		actualConfigPath = ""
	} else {
		logger.Info().Str("config_path", *configPath).Msg("설정 파일에서 설정 불러오기")
		actualConfigPath = *configPath
	}

	// 애플리케이션 설정 초기화
	appSetup, err := setup.SetupApp(actualConfigPath)
	if err != nil {
		logger.Fatal().Err(err).Msg("애플리케이션 설정 초기화 실패")
	}

	log := appSetup.Log
	ctx := log.WithContext(context.TODO())

	// 방 동기화 락 초기화
	roomSendlocks := NewRoomSendLocks()

	// 종료 핸들러 설정
	setup.SetupShutdownHandler(ctx, appSetup.Client, appSetup.CryptoHelper, appSetup.DB, log)

	// Matrix 이벤트 핸들러 등록
	SetupMatrixHandlers(ctx, appSetup, roomSendlocks)

	// 백필 작업 시작
	StartBackfillProcess(ctx, appSetup)

	// 웹훅 서버 시작
	StartWebhookServer(ctx, appSetup, roomSendlocks)

	// 종료 신호 핸들러 설정
	SetupSignalHandler(ctx, appSetup)

	// 종료 시 정리
	log.Info().Msg("프로그램 종료 대기 중...")
	err = appSetup.CryptoHelper.Close()
	if err != nil {
		log.Error().Err(err).Msg("암호화 헬퍼 닫기 오류")
	}
}

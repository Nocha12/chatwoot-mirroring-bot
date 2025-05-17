// account-manager CLI 도구는 Chatwoot와 Matrix 계정 설정 및 매핑을 관리하기 위한 명령줄 유틸리티입니다.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/Nocha12/chatwoot-mirroring-bot/cmd/account-manager/commands"
	"github.com/Nocha12/chatwoot-mirroring-bot/cmd/account-manager/utils"
)

// CLI 도구에 대한 기본 설명
const appDescription = `
Chatwoot-Matrix 봇용 계정 관리 도구

이 도구는 Chatwoot 계정, Matrix ID 설정, 그리고 이들의 매핑을 관리하기 위한 CLI 프로그램입니다.
사용자 인증 정보와 토큰은 암호화되어 저장됩니다.
`

func main() {
	// 제로로그 설정
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// 플래그 정의
	action := flag.String("action", "", "수행할 작업")
	configPath := flag.String("config", "config.yaml", "설정 파일 경로")
	masterKeyPath := flag.String("master-key", "master.key", "마스터 암호화 키 파일 경로")
	verbose := flag.Bool("verbose", false, "상세 로깅 활성화")

	// Chatwoot 계정 관련 플래그
	chatwootName := flag.String("chatwoot-name", "", "Chatwoot 설정 이름")
	chatwootBaseURL := flag.String("chatwoot-base-url", "", "Chatwoot 기본 URL")
	chatwootAccountID := flag.Int("chatwoot-account-id", 0, "Chatwoot 계정 ID")
	chatwootInboxID := flag.Int("chatwoot-inbox-id", 0, "Chatwoot 인박스 ID")
	chatwootToken := flag.String("chatwoot-token", "", "Chatwoot 접근 토큰")

	// Matrix ID 관련 플래그
	matrixName := flag.String("matrix-name", "", "Matrix 설정 이름")
	matrixHomeserver := flag.String("matrix-homeserver", "", "Matrix 홈서버 URL")
	matrixUserID := flag.String("matrix-user-id", "", "Matrix 사용자 ID")
	matrixPassword := flag.String("matrix-password", "", "Matrix 비밀번호")
	matrixToken := flag.String("matrix-token", "", "Matrix 접근 토큰")
	matrixDeviceID := flag.String("matrix-device-id", "", "Matrix 디바이스 ID")

	// 매핑 관련 플래그
	chatwootConfigID := flag.Int("chatwoot-config-id", 0, "Chatwoot 설정 ID")
	matrixIdentityID := flag.Int("matrix-identity-id", 0, "Matrix 아이덴티티 ID")
	mappingID := flag.Int("mapping-id", 0, "매핑 ID")
	enabled := flag.Bool("enabled", true, "활성화 여부")
	notes := flag.String("notes", "", "메모")

	flag.Parse()

	// 디버그 로그 설정
	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("디버그 로그 활성화됨")
	}

	// 시그널 처리 설정
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 시그널 핸들러 설정
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("종료 신호 수신")
		cancel()
	}()

	// 액션이 지정되지 않았거나 도움말을 요청한 경우 사용법 출력
	if *action == "" || *action == "help" {
		showUsage()
		return
	}

	// 애플리케이션 설정 초기화
	cfg, err := utils.InitConfig(*configPath, *masterKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("설정 초기화 실패")
	}
	defer func() {
		if err := cfg.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close config")
		}
	}()

	// 플래그 값을 맵으로 변환
	flags := map[string]interface{}{
		"chatwoot-name":       *chatwootName,
		"chatwoot-base-url":   *chatwootBaseURL,
		"chatwoot-account-id":  *chatwootAccountID,
		"chatwoot-inbox-id":    *chatwootInboxID,
		"chatwoot-token":       *chatwootToken,
		"matrix-name":          *matrixName,
		"matrix-homeserver":    *matrixHomeserver,
		"matrix-user-id":       *matrixUserID,
		"matrix-password":      *matrixPassword,
		"matrix-token":         *matrixToken,
		"matrix-device-id":     *matrixDeviceID,
		"chatwoot-config-id":   *chatwootConfigID,
		"matrix-identity-id":   *matrixIdentityID,
		"mapping-id":           *mappingID,
		"enabled":              *enabled,
		"notes":                *notes,
	}

	// 명령어 핸들러 생성 및 실행
	handler := commands.CreateHandler(cfg, *action, flags)
	if handler == nil {
		log.Error().Str("action", *action).Msg("알 수 없는 명령어")
		showUsage()
		os.Exit(1)
	}

	// 명령어 실행
	if err := handler.Execute(ctx); err != nil {
		log.Fatal().Err(err).Str("action", *action).Msg("명령어 실행 실패")
	}
}

// showUsage는 도움말을 출력합니다.
func showUsage() {
	fmt.Print(appDescription)
	fmt.Print("\n사용법: account-manager [옵션]\n\n")
	fmt.Println("사용 가능한 액션:")
	fmt.Println("  -action=add-chatwoot-config     새 Chatwoot 계정 설정 추가")
	fmt.Println("  -action=add-matrix-identity     새 Matrix ID 설정 추가")
	fmt.Println("  -action=add-mapping             새 계정 매핑 추가")
	fmt.Println("  -action=add-all                 모든 설정 및 매핑을 한 번에 추가")
	fmt.Println("  -action=list-chatwoot-configs   Chatwoot 계정 설정 목록 조회")
	fmt.Println("  -action=list-matrix-identities  Matrix ID 설정 목록 조회")
	fmt.Print("  -action=list-mappings           계정 매핑 목록 조회")
	fmt.Println("  -action=delete-mapping          계정 매핑 삭제")
	fmt.Println("")
	fmt.Println("옵션:")
	flag.PrintDefaults()
	
	fmt.Println("")
	fmt.Println("예시:")
	fmt.Println("  # Chatwoot 계정 추가:")
	fmt.Println("  account-manager -action=add-chatwoot-config -chatwoot-name=\"내 Chatwoot\" -chatwoot-base-url=\"https://chatwoot.example.com\" -chatwoot-account-id=1 -chatwoot-inbox-id=2 -chatwoot-token=\"your_token\"")
	
	fmt.Println("")
	fmt.Println("  # Matrix ID 추가:")
	fmt.Println("  account-manager -action=add-matrix-identity -matrix-name=\"내 Matrix\" -matrix-homeserver=\"https://matrix.example.org\" -matrix-user-id=\"@user:example.org\" -matrix-password=\"your_password\"")
	
	fmt.Println("")
	fmt.Println("  # 계정 매핑 추가:")
	fmt.Println("  account-manager -action=add-mapping -chatwoot-config-id=1 -matrix-identity-id=1")
	
	fmt.Println("")
	fmt.Println("  # 모든 설정 한 번에 추가:")
	fmt.Println("  account-manager -action=add-all [chatwoot 옵션] [matrix 옵션]")
}

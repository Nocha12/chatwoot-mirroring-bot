// logger.go
package setup

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/rs/zerolog"
)

// SetupLogger는 설정 파일 또는 DB 구성에 따라 zerolog.Logger와 컨텍스트를 초기화합니다.
// configPath이 빈 문자열이면 dbCfg를 사용하고, 그렇지 않으면 cfg를 사용합니다.
func SetupLogger(
	configPath string,
	cfg *config.Configuration,
	dbCfg *config.DbConfiguration,
) (zerolog.Logger, context.Context, error) {
	var (
		log zerolog.Logger
		lvl zerolog.Level
		err error
	)

	// 설정값 선택
	if configPath == "" {
		// DB 기반 설정 사용
		if dbCfg.LogLevel != "" {
			lvl, err = zerolog.ParseLevel(dbCfg.LogLevel)
			if err != nil {
				return zerolog.Logger{}, nil, fmt.Errorf("로그 레벨 파싱 실패 (DB 설정): %w", err)
			}
		} else {
			lvl = zerolog.InfoLevel
		}
		zerolog.SetGlobalLevel(lvl)

		// 출력 포맷
		if dbCfg.LogJSON {
			log = zerolog.New(os.Stdout)
		} else {
			log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
		}

		// 타임스탬프 및 콜러
		if dbCfg.LogTime {
			log = log.With().Timestamp().Logger()
		}
		if dbCfg.LogCaller {
			log = log.With().Caller().Logger()
		}
	} else {
		// 파일 기반 설정 사용
		if cfg.LogLevel != "" {
			lvl, err = zerolog.ParseLevel(cfg.LogLevel)
			if err != nil {
				return zerolog.Logger{}, nil, fmt.Errorf("로그 레벨 파싱 실패 (파일 설정): %w", err)
			}
		} else {
			lvl = zerolog.InfoLevel
		}
		zerolog.SetGlobalLevel(lvl)

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
	}

	ctx := log.With().Logger().WithContext(context.Background())
	log.Info().Str("config_path", configPath).Msg("로깅 설정 완료")
	return log, ctx, nil
}

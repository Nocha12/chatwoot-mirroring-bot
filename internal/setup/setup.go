// setup.go
package setup

import (
	"fmt"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/oci"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/id"
)

// AppSetup는 애플리케이션 실행에 필요한 공유 객체를 담고 있습니다.
type AppSetup struct {
	Log              zerolog.Logger
	Config           *config.Configuration // 파일 기반 설정인 경우에만
	DB               *database.Database
	Client           *mautrix.Client
	CryptoHelper     *cryptohelper.CryptoHelper
	MatrixClients    map[id.UserID]*mautrix.Client
	CryptoHelpers    map[id.UserID]*cryptohelper.CryptoHelper
	ChatwootAPIs     map[chatwootapi.AccountID]*chatwootapi.Client
	DefaultAccountID chatwootapi.AccountID

	// 계정 매핑 관련 필드
	AccountMappings  *config.AccountMappingManager
	ChatwootConfigs  map[int]*config.RuntimeChatwootConfig // ID로 접근하기 위한 Chatwoot 설정 참조
	MatrixIdentities map[int]*config.MatrixIdentityConfig  // ID로 접근하기 위한 Matrix 아이덴티티 참조

	OCIProducer *oci.Producer
	OCIConsumer *oci.Consumer
}

// SetupApp은 설정 파일(configPath) 유무에 따라 적절히 로딩 후
// 로거, DB, Matrix 클라이언트, Chatwoot API 클라이언트를 순차적으로 초기화합니다.
func SetupApp(configPath string) (*AppSetup, error) {
	// 1) 설정 로드 (파일 또는 DB)
	cfg, dbCfg, err := LoadConfigFiles(configPath)
	if err != nil {
		return nil, err
	}

	// 2) 로거 초기화
	log, ctx, err := SetupLogger(configPath, cfg, dbCfg)
	if err != nil {
		return nil, err
	}

	// 3) 데이터베이스 연결 및 마이그레이션
	db, err := SetupDatabase(dbCfg, log)
	if err != nil {
		return nil, err
	}

	// 4) 런타임 설정 로드 (항상 데이터베이스에서 계정 정보 로드)
	var runtimeCfg *config.RuntimeConfig
	// 항상 마스터 키를 로드하고 데이터베이스에서 계정 정보를 로드
	var masterKeyFile string
	if cfg != nil && cfg.MasterEncryptionKeyFile != "" {
		masterKeyFile = cfg.MasterEncryptionKeyFile
	} else {
		masterKeyFile = dbCfg.MasterEncryptionKeyFile
	}

	masterKey, err := config.LoadMasterEncryptionKey(masterKeyFile)
	if err != nil {
		return nil, fmt.Errorf("마스터 암호화 키 로드 실패: %w", err)
	}

	// 데이터베이스에서 계정 정보 로드 시도
	runtimeCfg, err = config.LoadRuntimeConfigFromDb(ctx, db, masterKey, &log)
	if err != nil {
		// 오류가 있더라도 계속 진행 (설정 파일의 정보를 사용)
		log.Warn().Err(err).Msg("데이터베이스에서 런타임 설정 로드 실패, 설정 파일 정보를 사용합니다")
		runtimeCfg = nil
	}

	// 5) Matrix 클라이언트 및 암호화 헬퍼 초기화
	matrixClients := make(map[id.UserID]*mautrix.Client)
	cryptoHelpers := make(map[id.UserID]*cryptohelper.CryptoHelper)
	var client *mautrix.Client
	var cryptoHelper *cryptohelper.CryptoHelper

	identityConfigs, err := queries.GetMatrixIdentities(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("matrix 계정 로드 실패: %w", err)
	}

	for _, ident := range identityConfigs {
		if !ident.IsEnabled {
			continue
		}
		pw, err := queries.DecryptMatrixPassword(ident, masterKey, &log)
		if err != nil {
			log.Error().Err(err).Int("identity_id", ident.ID).Msg("비밀번호 복호화 실패")
			continue
		}

		c, h, err := SetupMatrixClient(ident.HomeserverURL, ident.UserID.String(), pw, db, log)
		if err != nil {
			return nil, err
		}
		matrixClients[ident.UserID] = c
		cryptoHelpers[ident.UserID] = h
		if client == nil {
			client = c
			cryptoHelper = h
		}
	}

	if client == nil {
		return nil, fmt.Errorf("활성화된 Matrix 계정이 없습니다")
	}

	// 6) Chatwoot API 클라이언트 맵 생성
	apis, defaultAccID, err := SetupChatwootAPIs(cfg, runtimeCfg)
	if err != nil {
		return nil, err
	}

	// 7) Matrix 아이덴티티 정보 로드
	matrixIdentities, err := SetupMatrixIdentities(ctx, db, log)
	if err != nil {
		return nil, fmt.Errorf("matrix 아이덴티티 정보 로드 실패: %w", err)
	}

	// 8.5) OCI Streaming 초기화
	producer, consumer := SetupOCIStreaming(cfg)

	// 8) Chatwoot 설정 정보를 ID로 접근할 수 있는 맵으로 변환
	chatwootConfigs := make(map[int]*config.RuntimeChatwootConfig)
	if cfg == nil {
		// DB 기반 설정일 경우
		chatwootDbConfigs, err := queries.GetChatwootConfigs(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("chatwoot 설정 로드 실패: %w", err)
		}

		for _, chatwootConfig := range chatwootDbConfigs {
			if !chatwootConfig.IsEnabled {
				continue
			}

			// runtimeCfg에서 해당 계정에 대한 정보 찾기
			if accCfg, exists := runtimeCfg.ChatwootAccounts[chatwootConfig.AccountID]; exists {
				chatwootConfigs[chatwootConfig.ID] = accCfg
			}
		}
	} else {
		// 파일 기반 설정일 경우 - 현재 이 기능은 지원하지 않음 (추후 구현 예정)
		log.Warn().Msg("파일 기반 설정에서는 계정 매핑 기능을 완전히 지원하지 않습니다")
	}

	// 9) 계정 매핑 정보 로드
	var accountMappings *config.AccountMappingManager
	if cfg == nil {
		// DB 기반 설정일 경우에만 계정 매핑 사용
		accountMappings, err = SetupAccountMappings(ctx, db, chatwootConfigs, matrixIdentities, log)
		if err != nil {
			log.Warn().Err(err).Msg("계정 매핑 정보 로드 실패, 엔티티에 다른 매핑은 사용할 수 없습니다")
			accountMappings = config.NewAccountMappingManager() // 기본 매니저 생성
		}
	} else {
		// 파일 기반 설정일 경우 빈 매니저 생성
		accountMappings = config.NewAccountMappingManager()
	}

	// 10) 콜백 및 종료 핸들러 등록
	for uid, helper := range cryptoHelpers {
		SetupCallbacks(helper, log, db, apis, defaultAccID)
		c := matrixClients[uid]
		SetupShutdownHandler(ctx, c, helper, db, log)
	}

	// 11) AppSetup 조립 및 반환
	app := &AppSetup{
		Log:              log,
		DB:               db,
		Client:           client,
		CryptoHelper:     cryptoHelper,
		MatrixClients:    matrixClients,
		CryptoHelpers:    cryptoHelpers,
		ChatwootAPIs:     apis,
		DefaultAccountID: defaultAccID,
		AccountMappings:  accountMappings,
		ChatwootConfigs:  chatwootConfigs,
		MatrixIdentities: matrixIdentities,
		OCIProducer:      producer,
		OCIConsumer:      consumer,
	}
	if cfg != nil {
		app.Config = cfg
	}

	log.Info().Int("active_mappings", len(accountMappings.GetAllActiveMappings())).Msg("계정 매핑 관리자 초기화 완료")
	return app, nil
}

package config

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// LoadConfig는 지정된 경로에서 설정 파일을 로드합니다.
func LoadConfig(path string) (*Configuration, error) {
	yamlData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("설정 파일 읽기 실패: %w", err)
	}

	cfg := &Configuration{}
	if err := yaml.Unmarshal(yamlData, cfg); err != nil {
		return nil, fmt.Errorf("설정 파일 파싱 실패: %w", err)
	}

	return cfg, nil
}

// LoadDbConfig는 간소화된 DB 설정만 로드합니다.
func LoadDbConfig(path string) (*DbConfiguration, error) {
	yamlData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("DB 설정 파일 읽기 실패: %w", err)
	}

	cfg := &DbConfiguration{}
	if err := yaml.Unmarshal(yamlData, cfg); err != nil {
		return nil, fmt.Errorf("DB 설정 파일 파싱 실패: %w", err)
	}

	return cfg, nil
}

// LoadMasterEncryptionKey는 마스터 암호화 키를 파일에서 읽어옵니다.
func LoadMasterEncryptionKey(keyFilePath string) ([]byte, error) {
	if keyFilePath == "" {
		return nil, fmt.Errorf("마스터 암호화 키 파일 경로가 지정되지 않았습니다")
	}

	keyData, err := os.ReadFile(keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("마스터 암호화 키 파일 읽기 실패: %w", err)
	}

	// 공백과 개행 문자 제거
	keyStr := strings.TrimSpace(string(keyData))
	keyStr = strings.ReplaceAll(keyStr, "\n", "")
	keyStr = strings.ReplaceAll(keyStr, "\r", "")
	keyStr = strings.ReplaceAll(keyStr, " ", "")

	// 16진수 문자열을 바이트 배열로 변환
	keyData, err = hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("마스터 암호화 키가 유효한 16진수 문자열이 아닙니다: %w", err)
	}

	// 16바이트(128비트) 또는 32바이트(256비트) 키가 필요합니다
	if len(keyData) != 16 && len(keyData) != 32 {
		return nil, fmt.Errorf("마스터 암호화 키는 16바이트(128비트) 또는 32바이트(256비트)여야 합니다. 현재 길이: %d바이트", len(keyData))
	}

	return keyData, nil
}

// LoadRuntimeConfigFromDb는 데이터베이스에서 설정을 불러옵니다.
// 오류가 발생하더라도 가능한 한 보가적인 정보를 최대한 사용하여 설정을 구성합니다.
func LoadRuntimeConfigFromDb(ctx context.Context, db *database.Database, masterKey []byte, log *zerolog.Logger) (*RuntimeConfig, error) {
	// 런타임 설정 객체 초기화
	runtimeConfig := &RuntimeConfig{
		ChatwootAccounts: make(map[chatwootapi.AccountID]*RuntimeChatwootConfig),
	}

	// Matrix 계정 설정 불러오기
	matrixConfigs, err := queries.GetMatrixIdentities(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Matrix 계정 설정 로드 실패, 설정 파일의 정보를 사용해야 할 수 있습니다")
		return nil, fmt.Errorf("matrix 계정 설정 로드 실패: %w", err)
	}

	if len(matrixConfigs) == 0 {
		log.Warn().Msg("데이터베이스에 활성화된 Matrix 계정이 없습니다. Matrix 계정을 추가하려면 account-manager 를 사용하세요.")
		return nil, fmt.Errorf("활성화된 Matrix 계정이 없습니다")
	}

	// 첫 번째 Matrix 계정 사용 (현재는 단일 계정만 지원)
	matrixConfig := matrixConfigs[0]
	log.Info().Str("user_id", string(matrixConfig.UserID)).Msg("Matrix 계정 설정 로드됨")

	// Matrix 계정 정보 설정
	runtimeConfig.Homeserver = matrixConfig.HomeserverURL
	runtimeConfig.Username = matrixConfig.UserID
	runtimeConfig.DeviceID = matrixConfig.DeviceID

	// Matrix 비밀번호 또는 접근 토큰 복호화
	var password, accessToken string
	password, err = queries.DecryptMatrixPassword(matrixConfig, masterKey, log)
	if err != nil {
		if len(matrixConfig.EncryptedPassword) > 0 {
			log.Error().Err(err).Msg("Matrix 비밀번호 복호화 실패")
			return nil, fmt.Errorf("matrix 비밀번호 복호화 실패: %w", err)
		} else {
			log.Warn().Msg("Matrix 비밀번호가 없습니다")
		}
	}
	runtimeConfig.Password = password

	accessToken, err = queries.DecryptMatrixAccessToken(matrixConfig, masterKey, log)
	if err != nil {
		if len(matrixConfig.EncryptedAccessToken) > 0 {
			log.Error().Err(err).Msg("Matrix 접근 토큰 복호화 실패")
			// 접근 토큰은 없어도 비밀번호로 로그인 가능하므로 진행
		} else {
			log.Warn().Msg("Matrix 접근 토큰이 없습니다")
		}
	}
	runtimeConfig.AccessToken = accessToken

	// Chatwoot 계정 설정 불러오기
	chatwootConfigs, err := queries.GetChatwootConfigs(ctx, db)
	if err != nil {
		log.Error().Err(err).Msg("Chatwoot 계정 설정 로드 실패")
		return nil, fmt.Errorf("chatwoot 계정 설정 로드 실패: %w", err)
	}

	if len(chatwootConfigs) == 0 {
		log.Warn().Msg("데이터베이스에 Chatwoot 계정 설정이 없습니다. Chatwoot 계정을 추가하려면 account-manager를 사용하세요.")
	}

	// Chatwoot 계정 정보 처리

	// Chatwoot 계정 설정을 맵으로 변환
	for _, cfg := range chatwootConfigs {
		accessToken, err := queries.DecryptChatwootAccessToken(cfg, masterKey, log)
		if err != nil {
			return nil, fmt.Errorf("chatwoot 접근 토큰 복호화 실패 (계정 ID: %d): %w", cfg.AccountID, err)
		}

		runtimeConfig.ChatwootAccounts[cfg.AccountID] = &RuntimeChatwootConfig{
			AccountID:   cfg.AccountID,
			InboxID:     cfg.InboxID,
			BaseURL:     cfg.BaseURL,
			AccessToken: accessToken,
			IsEnabled:   cfg.IsEnabled,
		}

		// 첫 번째 Chatwoot 계정을 기본 URL로 설정
		if runtimeConfig.ChatwootBaseUrl == "" {
			runtimeConfig.ChatwootBaseUrl = cfg.BaseURL
		}
	}

	log.Info().Int("account_count", len(runtimeConfig.ChatwootAccounts)).Msg("Chatwoot 계정 설정 로드됨")

	return runtimeConfig, nil
}

// GetPassword는 비밀번호 파일에서 Matrix 비밀번호를 읽어옵니다.
// 파일이 지정되지 않았거나 없는 경우 빈 문자열을 반환합니다.
func (c *Configuration) GetPassword(log *zerolog.Logger) (string, error) {
	// 파일이 지정되지 않은 경우
	if c.PasswordFile == "" {
		log.Warn().Msg("비밀번호 파일이 지정되지 않았습니다. 데이터베이스의 계정 정보를 사용해야 합니다.")
		return "", fmt.Errorf("비밀번호 파일이 지정되지 않았습니다")
	}

	// 파일 읽기 시도
	data, err := os.ReadFile(c.PasswordFile)
	if err != nil {
		log.Warn().Err(err).Str("file", c.PasswordFile).Msg("비밀번호 파일 읽기 실패")
		return "", fmt.Errorf("비밀번호 파일 읽기 실패: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// GetChatwootAccessTokenByIndex는 특정 계정 인덱스에 대한 Chatwoot 액세스 토큰을 읽어옵니다.
func (c *Configuration) GetChatwootAccessTokenByIndex(log *zerolog.Logger, accountIndex int) (string, error) {
	if accountIndex < 0 || accountIndex >= len(c.ChatwootAccounts) {
		return "", fmt.Errorf("유효하지 않은 계정 인덱스: %d", accountIndex)
	}

	accountConfig := c.ChatwootAccounts[accountIndex]
	data, err := os.ReadFile(accountConfig.AccessTokenFile)
	if err != nil {
		return "", fmt.Errorf("계정 %d의 액세스 토큰 파일 읽기 실패: %w", accountIndex, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// GetChatwootAccessTokenByAccountID는 특정 계정 ID에 대한 Chatwoot 액세스 토큰을 읽어옵니다.
func (c *Configuration) GetChatwootAccessTokenByAccountID(log *zerolog.Logger, accountID chatwootapi.AccountID) (string, error) {
	// 레거시 단일 계정 지원
	if c.ChatwootAccountID == accountID && c.ChatwootAccessTokenFile != "" {
		data, err := os.ReadFile(c.ChatwootAccessTokenFile)
		if err != nil {
			return "", fmt.Errorf("레거시 계정 %d의 액세스 토큰 파일 읽기 실패: %w", accountID, err)
		}
		return strings.TrimSpace(string(data)), nil
	}

	// 다중 계정에서 찾기
	for _, account := range c.ChatwootAccounts {
		if account.AccountID == accountID && account.Enabled {
			data, err := os.ReadFile(account.AccessTokenFile)
			if err != nil {
				return "", fmt.Errorf("계정 %d의 액세스 토큰 파일 읽기 실패: %w", accountID, err)
			}
			return strings.TrimSpace(string(data)), nil
		}
	}

	return "", fmt.Errorf("계정 ID %d에 대한 설정을 찾을 수 없음", accountID)
}

// GetChatwootBaseUrl은 특정 계정의 Chatwoot 기본 URL을 반환합니다.
func (c *Configuration) GetChatwootBaseUrl(accountIndex int) string {
	if accountIndex < 0 || accountIndex >= len(c.ChatwootAccounts) {
		return c.ChatwootBaseUrl // 기본 URL 반환
	}
	if c.ChatwootAccounts[accountIndex].BaseUrl == "" {
		return c.ChatwootBaseUrl // 계정별 URL이 비어있으면 기본 URL 반환
	}
	return c.ChatwootAccounts[accountIndex].BaseUrl
}

// GetAccountIDs는 구성에서 모든 활성화된 계정 ID 목록을 반환합니다.
func (c *Configuration) GetAccountIDs() []chatwootapi.AccountID {
	var ids []chatwootapi.AccountID

	// 레거시 단일 계정 추가 (설정된 경우)
	if c.ChatwootAccountID != 0 && c.ChatwootAccessTokenFile != "" {
		ids = append(ids, c.ChatwootAccountID)
	}

	// 다중 계정 추가
	for _, account := range c.ChatwootAccounts {
		if account.Enabled {
			ids = append(ids, account.AccountID)
		}
	}

	return ids
}

// GetInboxIDForAccount는 특정 계정 ID에 대한 인박스 ID를 반환합니다.
func (c *Configuration) GetInboxIDForAccount(accountID chatwootapi.AccountID) (chatwootapi.InboxID, error) {
	// 레거시 단일 계정 확인
	if c.ChatwootAccountID == accountID {
		return c.ChatwootInboxID, nil
	}

	// 다중 계정에서 찾기
	for _, account := range c.ChatwootAccounts {
		if account.AccountID == accountID && account.Enabled {
			return account.InboxID, nil
		}
	}

	return 0, fmt.Errorf("계정 ID %d에 대한 인박스 ID를 찾을 수 없음", accountID)
}

// GetChatwootAccessToken은 하위 호환성을 위한 함수입니다. (기존 코드가 이 함수를 사용하는 경우)
// 파일이 지정되지 않았거나 없는 경우 빈 문자열을 반환할 수 있습니다.
func (c *Configuration) GetChatwootAccessToken(log *zerolog.Logger) (string, error) {
	if len(c.ChatwootAccounts) > 0 {
		// 새 형식의 설정을 사용하는 경우
		log.Info().Msg("새 형식의 Chatwoot 계정 설정을 사용합니다")
		return c.GetChatwootAccessTokenByIndex(log, 0)
	}

	// 이전 형식의 설정을 사용하는 경우
	if c.ChatwootAccessTokenFile == "" {
		log.Warn().Msg("Chatwoot 토큰 파일이 지정되지 않았습니다. 데이터베이스의 설정을 사용해야 합니다.")
		return "", fmt.Errorf("토큰 파일이 지정되지 않았습니다")
	}

	data, err := os.ReadFile(c.ChatwootAccessTokenFile)
	if err != nil {
		log.Warn().Err(err).Str("file", c.ChatwootAccessTokenFile).Msg("Chatwoot 토큰 파일 읽기 실패")
		return "", fmt.Errorf("Chatwoot 토큰 파일 읽기 실패: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

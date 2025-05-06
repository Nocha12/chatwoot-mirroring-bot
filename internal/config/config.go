package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"

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

// GetPassword는 비밀번호 파일에서 Matrix 비밀번호를 읽어옵니다.
func (c *Configuration) GetPassword(log *zerolog.Logger) (string, error) {
	data, err := os.ReadFile(c.PasswordFile)
	if err != nil {
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
func (c *Configuration) GetChatwootAccessToken(log *zerolog.Logger) (string, error) {
	if c.ChatwootAccessTokenFile == "" {
		// 단일 계정 설정이 없으면 첫 번째 활성화된 계정 사용
		for i, account := range c.ChatwootAccounts {
			if account.Enabled {
				return c.GetChatwootAccessTokenByIndex(log, i)
			}
		}
		return "", fmt.Errorf("활성화된 Chatwoot 계정을 찾을 수 없음")
	}

	data, err := os.ReadFile(c.ChatwootAccessTokenFile)
	if err != nil {
		return "", fmt.Errorf("Chatwoot 액세스 토큰 파일 읽기 실패: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

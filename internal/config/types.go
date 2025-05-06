package config

import (
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

// BackfillConfiguration은 백필 설정을 정의합니다.
type BackfillConfiguration struct {
	ChatwootConversations     bool `yaml:"chatwoot_conversations"`
	ConversationIDStateEvents bool `yaml:"conversation_id_state_events"`
}

// HomeserverWhitelist는 허용된 홈서버 목록 설정을 정의합니다.
type HomeserverWhitelist struct {
	Enable  bool     `yaml:"enable"`
	Allowed []string `yaml:"allowed"`
}

// StartNewChat은 새 채팅 시작 설정을 정의합니다.
type StartNewChat struct {
	Enable   bool   `yaml:"enable"`
	Endpoint string `yaml:"endpoint"`
	Token    string `yaml:"token"`
}

// ChatwootAccountConfig는 단일 Chatwoot 계정에 대한 설정을 정의합니다.
type ChatwootAccountConfig struct {
	BaseUrl         string                `yaml:"base_url,omitempty"` // 개별 계정별 베이스 URL (비어있으면 전역 설정 사용)
	AccessTokenFile string                `yaml:"access_token_file"`  // 계정 접근 토큰 파일 경로
	AccountID       chatwootapi.AccountID `yaml:"account_id"`         // Chatwoot 계정 ID
	InboxID         chatwootapi.InboxID   `yaml:"inbox_id"`           // Chatwoot 인박스 ID
	Enabled         bool                  `yaml:"enabled"`            // 이 계정 활성화 여부
}

// Configuration은 애플리케이션의 주요 설정을 정의합니다.
type Configuration struct {
	// Authentication settings
	Homeserver   string    `yaml:"homeserver"`
	Username     id.UserID `yaml:"username"`
	PasswordFile string    `yaml:"password_file"`

	// Chatwoot Authentication
	ChatwootBaseUrl string `yaml:"chatwoot_base_url"` // 기본 Chatwoot URL (모든 계정의 기본값)

	// 기존 단일 계정 구성 (하위 호환성 유지)
	ChatwootAccessTokenFile string                `yaml:"chatwoot_access_token_file,omitempty"`
	ChatwootAccountID       chatwootapi.AccountID `yaml:"chatwoot_account_id,omitempty"`
	ChatwootInboxID         chatwootapi.InboxID   `yaml:"chatwoot_inbox_id,omitempty"`

	// 다중 계정 구성
	ChatwootAccounts []ChatwootAccountConfig `yaml:"chatwoot_accounts,omitempty"`

	// Bot settings
	MaxMediaWidth    int  `yaml:"max_media_width"`
	MaxMediaHeight   int  `yaml:"max_media_height"`
	MaxMediaPixels   int  `yaml:"max_media_pixels"`
	MaxMediaSize     int  `yaml:"max_media_size"`
	MediaQuality     int  `yaml:"media_quality"`
	MediaConvertWEBP bool `yaml:"media_convert_webp"`

	// Backfill settings
	Backfill BackfillConfiguration `yaml:"backfill"`

	// Logging configuration
	LogLevel  string `yaml:"log_level"`
	LogJSON   bool   `yaml:"log_json"`
	LogTime   bool   `yaml:"log_time"`
	LogCaller bool   `yaml:"log_caller"`

	HomeserverWhitelist HomeserverWhitelist `yaml:"homeserver_whitelist"`

	HTTPListenPort int `yaml:"http_listen_port"`

	StartNewChat StartNewChat `yaml:"start_new_chat"`

	// Database configuration
	Database dbutil.Config `yaml:"database"`
}

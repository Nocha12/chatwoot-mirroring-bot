// Package config는 애플리케이션의 구성 및 설정 관련 구조체와 함수를 제공합니다.
// 계정 매핑 관련 구조체와 함수들은 다음 파일들로 분리되었습니다:
// - account_mapping_types.go: AccountMappingInfo, MatrixIdentityConfig 구조체
// - account_mapping_manager.go: AccountMappingManager 구조체와 관련 메서드
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

// OCIStreamingConfig는 OCI Streaming 연동을 위한 설정을 정의합니다.
type OCIStreamingConfig struct {
	Endpoint    string `yaml:"endpoint"`
	Topic       string `yaml:"topic"`
	Credentials string `yaml:"credentials"`
}

// ChatwootAccountConfig는 단일 Chatwoot 계정에 대한 설정을 정의합니다.
type ChatwootAccountConfig struct {
	BaseUrl         string                `yaml:"base_url,omitempty"`
	AccessTokenFile string                `yaml:"access_token_file"`
	AccountID       chatwootapi.AccountID `yaml:"account_id"`
	InboxID         chatwootapi.InboxID   `yaml:"inbox_id"`
	Enabled         bool                  `yaml:"enabled"`
}

// DbConfiguration은 데이터베이스 설정만 포함하는 간소화된 설정 구조체입니다.
type DbConfiguration struct {
	Database                dbutil.Config `yaml:"database"`
	MasterEncryptionKeyFile string        `yaml:"master_encryption_key_file"`
	LogLevel                string        `yaml:"log_level"`
	LogJSON                 bool          `yaml:"log_json"`
	LogTime                 bool          `yaml:"log_time"`
	LogCaller               bool          `yaml:"log_caller"`
}

// RuntimeConfig는 DB에서 불러온 설정과 실행시간에 필요한 추가 설정을 가지는 구조체입니다.
type RuntimeConfig struct {
	Homeserver  string
	Username    id.UserID
	Password    string
	AccessToken string
	DeviceID    string

	ChatwootBaseUrl  string
	ChatwootAccounts map[chatwootapi.AccountID]*RuntimeChatwootConfig

	MaxMediaWidth    int
	MaxMediaHeight   int
	MaxMediaPixels   int
	MaxMediaSize     int
	MediaQuality     int
	MediaConvertWEBP bool

	Backfill            BackfillConfiguration
	HomeserverWhitelist HomeserverWhitelist
	HTTPListenPort      int
	StartNewChat        StartNewChat
}

// RuntimeChatwootConfig는 실행시간에 사용되는 Chatwoot 계정 설정입니다.
type RuntimeChatwootConfig struct {
	AccountID   chatwootapi.AccountID
	InboxID     chatwootapi.InboxID
	BaseURL     string
	AccessToken string
	IsEnabled   bool
}

// Configuration은 애플리케이션의 주요 설정을 정의합니다.
type Configuration struct {
	Homeserver   string    `yaml:"homeserver"`
	Username     id.UserID `yaml:"username"`
	PasswordFile string    `yaml:"password_file"`

	ChatwootBaseUrl         string                  `yaml:"chatwoot_base_url"`
	ChatwootAccessTokenFile string                  `yaml:"chatwoot_access_token_file,omitempty"`
	ChatwootAccountID       chatwootapi.AccountID   `yaml:"chatwoot_account_id,omitempty"`
	ChatwootInboxID         chatwootapi.InboxID     `yaml:"chatwoot_inbox_id,omitempty"`
	ChatwootAccounts        []ChatwootAccountConfig `yaml:"chatwoot_accounts,omitempty"`

	MasterEncryptionKeyFile string `yaml:"master_encryption_key_file"`

	MaxMediaWidth    int  `yaml:"max_media_width"`
	MaxMediaHeight   int  `yaml:"max_media_height"`
	MaxMediaPixels   int  `yaml:"max_media_pixels"`
	MaxMediaSize     int  `yaml:"max_media_size"`
	MediaQuality     int  `yaml:"media_quality"`
	MediaConvertWEBP bool `yaml:"media_convert_webp"`

	Backfill BackfillConfiguration `yaml:"backfill"`

	LogLevel  string `yaml:"log_level"`
	LogJSON   bool   `yaml:"log_json"`
	LogTime   bool   `yaml:"log_time"`
	LogCaller bool   `yaml:"log_caller"`

	HomeserverWhitelist HomeserverWhitelist `yaml:"homeserver_whitelist"`
	HTTPListenPort      int                 `yaml:"http_listen_port"`
	StartNewChat        StartNewChat        `yaml:"start_new_chat"`

	OCIStreaming OCIStreamingConfig `yaml:"oci_streaming"`

	Database dbutil.Config `yaml:"database"`
}

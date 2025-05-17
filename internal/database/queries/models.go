// models.go - 데이터베이스 모델 구조체 정의 파일
package queries

import (
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"maunium.net/go/mautrix/id"
)

// MatrixIdentityConfig는 데이터베이스에서 조회한 Matrix 계정 설정을 담는 구조체입니다.
type MatrixIdentityConfig struct {
	ID                     int
	ConfigName             string
	HomeserverURL          string
	UserID                 id.UserID
	EncryptedPassword      []byte
	PasswordNonce          []byte
	EncryptedAccessToken   []byte
	AccessTokenNonce       []byte
	DeviceID               string
	IsEnabled              bool
}

// ChatwootAccountConfig는 데이터베이스에서 조회한 Chatwoot 계정 설정을 담는 구조체입니다.
type ChatwootAccountConfig struct {
	ID                  int
	ConfigName          string
	BaseURL             string
	AccountID           chatwootapi.AccountID
	InboxID             chatwootapi.InboxID
	EncryptedAccessToken []byte
	EncryptionNonce     []byte
	IsEnabled           bool
}

// AccountMapping은 Chatwoot 계정과 Matrix ID 사이의 매핑 정보를 담는 구조체입니다.
type AccountMapping struct {
	ID               int
	ChatwootConfigID int
	MatrixIdentityID int
	IsActive         bool
	Notes            string
}

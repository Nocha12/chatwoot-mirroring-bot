package config

import (
	"maunium.net/go/mautrix/id"
)

// AccountMappingInfo는 Chatwoot 계정과 Matrix ID 간의 매핑 정보를 나타내는 구조체입니다.
type AccountMappingInfo struct {
	ID               int  // 매핑 ID
	ChatwootConfigID int  // Chatwoot 설정 ID (bot_chatwoot_configs 테이블의 ID)
	MatrixIdentityID int  // Matrix 아이덴티티 ID (bot_matrix_identities 테이블의 ID)
	IsActive         bool // 활성화 여부
	Notes            string

	// 런타임에 사용되는 참조 정보
	ChatwootConfig *RuntimeChatwootConfig // 관련 Chatwoot 설정에 대한 참조
	MatrixConfig   *MatrixIdentityConfig  // 관련 Matrix 아이덴티티 설정에 대한 참조
}

// MatrixIdentityConfig는 Matrix 계정 정보를 나타내는 구조체입니다.
type MatrixIdentityConfig struct {
	ID            int
	ConfigName    string
	HomeserverURL string
	UserID        id.UserID
	DeviceID      string
	IsEnabled     bool
}

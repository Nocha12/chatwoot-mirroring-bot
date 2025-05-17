// handler.go - 명령어 핸들러 인터페이스 정의
package commands

import (
	"context"

	"github.com/Nocha12/chatwoot-mirroring-bot/cmd/account-manager/utils"
)

// CommandHandler는 명령어 처리를 위한 핸들러 인터페이스입니다.
type CommandHandler interface {
	Execute(ctx context.Context) error
}

// CreateHandler는 명령어에 따른 핸들러를 생성합니다.
func CreateHandler(cfg *utils.AppConfig, action string, flags map[string]interface{}) CommandHandler {
	switch action {
	case "add-chatwoot-config":
		return &AddChatwootConfigCmd{
			DB:                cfg.DB,
			MasterKey:         cfg.MasterKey,
			ChatwootName:      flags["chatwoot-name"].(string),
			ChatwootBaseURL:   flags["chatwoot-base-url"].(string),
			ChatwootAccountID: flags["chatwoot-account-id"].(int),
			ChatwootInboxID:   flags["chatwoot-inbox-id"].(int),
			ChatwootToken:     flags["chatwoot-token"].(string),
			Enabled:           flags["enabled"].(bool),
			Notes:             flags["notes"].(string),
		}
	case "add-matrix-identity":
		return &AddMatrixIdentityCmd{
			DB:                cfg.DB,
			MasterKey:         cfg.MasterKey,
			MatrixName:        flags["matrix-name"].(string),
			MatrixHomeserver:  flags["matrix-homeserver"].(string),
			MatrixUserID:      flags["matrix-user-id"].(string),
			MatrixPassword:    flags["matrix-password"].(string),
			MatrixAccessToken: flags["matrix-token"].(string),
			MatrixDeviceID:    flags["matrix-device-id"].(string),
			Enabled:           flags["enabled"].(bool),
			Notes:             flags["notes"].(string),
		}
	case "add-mapping":
		return &AddMappingCmd{
			DB:               cfg.DB,
			ChatwootConfigID: flags["chatwoot-config-id"].(int),
			MatrixIdentityID: flags["matrix-identity-id"].(int),
			Enabled:          flags["enabled"].(bool),
			Notes:            flags["notes"].(string),
		}
	case "add-all":
		return &AddAllWithMappingCmd{
			DB:                cfg.DB,
			MasterKey:         cfg.MasterKey,
			ChatwootName:      flags["chatwoot-name"].(string),
			ChatwootBaseURL:   flags["chatwoot-base-url"].(string),
			ChatwootAccountID: flags["chatwoot-account-id"].(int),
			ChatwootInboxID:   flags["chatwoot-inbox-id"].(int),
			ChatwootToken:     flags["chatwoot-token"].(string),
			MatrixName:        flags["matrix-name"].(string),
			MatrixHomeserver:  flags["matrix-homeserver"].(string),
			MatrixUserID:      flags["matrix-user-id"].(string),
			MatrixPassword:    flags["matrix-password"].(string),
			MatrixAccessToken: flags["matrix-token"].(string),
			MatrixDeviceID:    flags["matrix-device-id"].(string),
			Enabled:           flags["enabled"].(bool),
			Notes:             flags["notes"].(string),
		}
	case "list-chatwoot-configs":
		return &ListChatwootConfigsCmd{
			DB: cfg.DB,
		}
	case "list-matrix-identities":
		return &ListMatrixIdentitiesCmd{
			DB: cfg.DB,
		}
	case "list-mappings":
		return &ListMappingsCmd{
			DB: cfg.DB,
		}
	case "delete-mapping":
		return &DeleteMappingCmd{
			DB:        cfg.DB,
			MappingID: flags["mapping-id"].(int),
		}
	default:
		return nil
	}
}

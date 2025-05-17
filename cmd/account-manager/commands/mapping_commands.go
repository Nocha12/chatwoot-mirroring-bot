// mapping_commands.go - 계정 매핑 관련 명령어
package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// AddMappingCmd는 새 계정 매핑을 추가합니다.
type AddMappingCmd struct {
	DB               *database.Database
	ChatwootConfigID int
	MatrixIdentityID int
	Enabled          bool
	Notes            string
}

// Execute는 AddMappingCmd 명령을 실행합니다.
func (cmd *AddMappingCmd) Execute(ctx context.Context) error {
	if cmd.ChatwootConfigID <= 0 || cmd.MatrixIdentityID <= 0 {
		return fmt.Errorf("계정 매핑 추가에 필요한 모든 파라미터를 입력해야 합니다")
	}

	id, err := queries.CreateAccountMapping(
		ctx,
		cmd.DB,
		cmd.ChatwootConfigID,
		cmd.MatrixIdentityID,
		cmd.Enabled,
		cmd.Notes,
	)
	if err != nil {
		return err
	}

	zerolog.Ctx(ctx).Info().Int("id", id).
		Int("chatwoot_config_id", cmd.ChatwootConfigID).
		Int("matrix_identity_id", cmd.MatrixIdentityID).
		Msg("계정 매핑이 성공적으로 추가되었습니다")
	return nil
}

// AddAllWithMappingCmd는 모든 설정과 매핑을 한 번에 추가합니다.
type AddAllWithMappingCmd struct {
	DB                *database.Database
	MasterKey         []byte
	ChatwootName      string
	ChatwootBaseURL   string
	ChatwootAccountID int
	ChatwootInboxID   int
	ChatwootToken     string
	MatrixName        string
	MatrixHomeserver  string
	MatrixUserID      string
	MatrixPassword    string
	MatrixAccessToken string
	MatrixDeviceID    string
	Enabled           bool
	Notes             string
}

// Execute는 AddAllWithMappingCmd 명령을 실행합니다.
func (cmd *AddAllWithMappingCmd) Execute(ctx context.Context) error {
	// 필수 파라미터 검증
	if cmd.ChatwootName == "" || cmd.ChatwootBaseURL == "" || cmd.ChatwootAccountID <= 0 || cmd.ChatwootInboxID <= 0 || cmd.ChatwootToken == "" ||
		cmd.MatrixName == "" || cmd.MatrixHomeserver == "" || cmd.MatrixUserID == "" || (cmd.MatrixPassword == "" && cmd.MatrixAccessToken == "") {
		return fmt.Errorf("통합 계정 추가에 필요한 모든 파라미터를 입력해야 합니다")
	}

	config := queries.AccountMappingConfig{
		ChatwootConfigName:   cmd.ChatwootName,
		ChatwootBaseURL:      cmd.ChatwootBaseURL,
		ChatwootAccountID:    chatwootapi.AccountID(cmd.ChatwootAccountID),
		ChatwootInboxID:      chatwootapi.InboxID(cmd.ChatwootInboxID),
		ChatwootAccessToken:  cmd.ChatwootToken,
		
		MatrixConfigName:     cmd.MatrixName,
		MatrixHomeserverURL:  cmd.MatrixHomeserver,
		MatrixUserID:         id.UserID(cmd.MatrixUserID),
		MatrixPassword:       cmd.MatrixPassword,
		MatrixAccessToken:    cmd.MatrixAccessToken,
		MatrixDeviceID:       cmd.MatrixDeviceID,
		
		IsEnabled:            cmd.Enabled,
		Notes:                cmd.Notes,
	}

	chatwootID, matrixID, mappingID, err := queries.AddAccountWithMapping(ctx, cmd.DB, config, cmd.MasterKey)
	if err != nil {
		return err
	}

	zerolog.Ctx(ctx).Info().
		Int("chatwoot_id", chatwootID).
		Int("matrix_id", matrixID).
		Int("mapping_id", mappingID).
		Msg("모든 계정 설정 및 매핑이 성공적으로 추가되었습니다")
	return nil
}

// ListMappingsCmd는 모든 계정 매핑을 나열합니다.
type ListMappingsCmd struct {
	DB *database.Database
}

// Execute는 ListMappingsCmd 명령을 실행합니다.
func (cmd *ListMappingsCmd) Execute(ctx context.Context) error {
	mappings, err := queries.GetAllAccountMappings(ctx, cmd.DB)
	if err != nil {
		return err
	}

	fmt.Println("----- 계정 매핑 목록 -----")
	fmt.Printf("%-5s %-20s %-20s %-10s %-30s\n", "ID", "Chatwoot 설정 ID", "Matrix ID 설정 ID", "활성화", "메모")
	fmt.Println(strings.Repeat("-", 100))

	for _, mapping := range mappings {
		fmt.Printf("%-5d %-20d %-20d %-10t %-30s\n",
			mapping.ID, mapping.ChatwootConfigID, mapping.MatrixIdentityID, mapping.IsActive, mapping.Notes)
	}

	fmt.Printf("\n총 %d개의 계정 매핑이 있습니다.\n", len(mappings))
	return nil
}

// DeleteMappingCmd는 계정 매핑을 삭제합니다.
type DeleteMappingCmd struct {
	DB        *database.Database
	MappingID int
}

// Execute는 DeleteMappingCmd 명령을 실행합니다.
func (cmd *DeleteMappingCmd) Execute(ctx context.Context) error {
	if cmd.MappingID <= 0 {
		return fmt.Errorf("매핑 ID를 지정해야 합니다")
	}

	err := queries.DeleteAccountMapping(ctx, cmd.DB, cmd.MappingID)
	if err != nil {
		return err
	}

	zerolog.Ctx(ctx).Info().Int("id", cmd.MappingID).Msg("계정 매핑이 성공적으로 삭제되었습니다")
	return nil
}

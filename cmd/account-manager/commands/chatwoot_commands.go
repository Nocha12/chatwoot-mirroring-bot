// chatwoot_commands.go - Chatwoot 계정 설정 관련 명령어
package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// AddChatwootConfigCmd는 새 Chatwoot 계정 설정을 추가합니다.
type AddChatwootConfigCmd struct {
	DB                *database.Database
	MasterKey         []byte
	ChatwootName      string
	ChatwootBaseURL   string
	ChatwootAccountID int
	ChatwootInboxID   int
	ChatwootToken     string
	Enabled           bool
	Notes             string
}

// Execute는 AddChatwootConfigCmd 명령을 실행합니다.
func (cmd *AddChatwootConfigCmd) Execute(ctx context.Context) error {
	if cmd.ChatwootName == "" || cmd.ChatwootBaseURL == "" || cmd.ChatwootAccountID <= 0 || cmd.ChatwootInboxID <= 0 || cmd.ChatwootToken == "" {
		return fmt.Errorf("chatwoot 설정 추가에 필요한 모든 파라미터를 입력해야 합니다")
	}

	id, err := queries.CreateChatwootConfig(
		ctx,
		cmd.DB,
		cmd.ChatwootName,
		cmd.ChatwootBaseURL,
		chatwootapi.AccountID(cmd.ChatwootAccountID),
		chatwootapi.InboxID(cmd.ChatwootInboxID),
		cmd.ChatwootToken,
		cmd.MasterKey,
		cmd.Enabled,
		cmd.Notes,
	)
	if err != nil {
		return err
	}

	zerolog.Ctx(ctx).Info().Int("id", id).Str("name", cmd.ChatwootName).Msg("Chatwoot 설정이 성공적으로 추가되었습니다")
	return nil
}

// ListChatwootConfigsCmd는 모든 Chatwoot 계정 설정을 나열합니다.
type ListChatwootConfigsCmd struct {
	DB *database.Database
}

// Execute는 ListChatwootConfigsCmd 명령을 실행합니다.
func (cmd *ListChatwootConfigsCmd) Execute(ctx context.Context) error {
	configs, err := queries.GetChatwootConfigs(ctx, cmd.DB)
	if err != nil {
		return err
	}

	fmt.Println("----- Chatwoot 계정 설정 목록 -----")
	fmt.Printf("%-5s %-30s %-35s %-15s %-15s %-10s\n", "ID", "이름", "기본 URL", "계정 ID", "인박스 ID", "활성화")
	fmt.Println(strings.Repeat("-", 120))

	for _, cfg := range configs {
		fmt.Printf("%-5d %-30s %-35s %-15d %-15d %-10t\n",
			cfg.ID, cfg.ConfigName, cfg.BaseURL, cfg.AccountID, cfg.InboxID, cfg.IsEnabled)
	}

	fmt.Printf("\n총 %d개의 Chatwoot 계정 설정이 있습니다.\n", len(configs))
	return nil
}

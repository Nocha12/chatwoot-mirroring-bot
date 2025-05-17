// matrix_commands.go - Matrix ID 설정 관련 명령어
package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
)

// AddMatrixIdentityCmd는 새 Matrix ID 설정을 추가합니다.
type AddMatrixIdentityCmd struct {
	DB                *database.Database
	MasterKey         []byte
	MatrixName        string
	MatrixHomeserver  string
	MatrixUserID      string
	MatrixPassword    string
	MatrixAccessToken string
	MatrixDeviceID    string
	Enabled           bool
	Notes             string
}

// Execute는 AddMatrixIdentityCmd 명령을 실행합니다.
func (cmd *AddMatrixIdentityCmd) Execute(ctx context.Context) error {
	if cmd.MatrixName == "" || cmd.MatrixHomeserver == "" || cmd.MatrixUserID == "" || (cmd.MatrixPassword == "" && cmd.MatrixAccessToken == "") {
		return fmt.Errorf("matrix ID 설정 추가에 필요한 모든 파라미터를 입력해야 합니다")
	}

	id, err := queries.CreateMatrixIdentity(
		ctx,
		cmd.DB,
		cmd.MatrixName,
		cmd.MatrixHomeserver,
		id.UserID(cmd.MatrixUserID),
		cmd.MatrixPassword,
		cmd.MatrixAccessToken,
		cmd.MatrixDeviceID,
		cmd.MasterKey,
		cmd.Enabled,
		cmd.Notes,
	)
	if err != nil {
		return err
	}

	zerolog.Ctx(ctx).Info().Int("id", id).Str("name", cmd.MatrixName).Msg("Matrix ID 설정이 성공적으로 추가되었습니다")
	return nil
}

// ListMatrixIdentitiesCmd는 모든 Matrix ID 설정을 나열합니다.
type ListMatrixIdentitiesCmd struct {
	DB *database.Database
}

// Execute는 ListMatrixIdentitiesCmd 명령을 실행합니다.
func (cmd *ListMatrixIdentitiesCmd) Execute(ctx context.Context) error {
	identities, err := queries.GetMatrixIdentities(ctx, cmd.DB)
	if err != nil {
		return err
	}

	fmt.Println("----- Matrix ID 설정 목록 -----")
	fmt.Printf("%-5s %-30s %-35s %-35s %-10s\n", "ID", "이름", "홈서버 URL", "사용자 ID", "활성화")
	fmt.Println(strings.Repeat("-", 120))

	for _, identity := range identities {
		fmt.Printf("%-5d %-30s %-35s %-35s %-10t\n",
			identity.ID, identity.ConfigName, identity.HomeserverURL, string(identity.UserID), identity.IsEnabled)
	}

	fmt.Printf("\n총 %d개의 Matrix ID 설정이 있습니다.\n", len(identities))
	return nil
}

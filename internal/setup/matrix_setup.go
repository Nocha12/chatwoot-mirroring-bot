// matrix_setup.go
package setup

import (
	"context"
	"fmt"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
)

// SetupMatrixClient는 homeserver, 사용자 정보, 비밀번호와 상태 저장소 및 로거를
// 받아 Matrix 클라이언트 및 암호화 헬퍼를 초기화합니다.
func SetupMatrixClient(
	homeserver string,
	user string,
	password string,
	db *database.Database,
	log zerolog.Logger,
) (*mautrix.Client, *cryptohelper.CryptoHelper, error) {
	// 컨텍스트 생성
	ctx := log.WithContext(context.Background())

	// Matrix 클라이언트 생성
	client, err := mautrix.NewClient(homeserver, "", "")
	if err != nil {
		return nil, nil, fmt.Errorf("matrix 클라이언트 생성 실패: %w", err)
	}
	client.Log = log

	// 암호화 헬퍼 초기화
	// 1) *sql.DB를 go.mau.fi/util/dbutil.Database로 래핑
	store, err := dbutil.NewWithDB(db.DB, db.DbType)
	if err != nil {
		return nil, nil, fmt.Errorf("dbutil 래퍼 생성 실패: %w", err)
	}

	// 2) 래핑된 store를 넘겨서 암호화 헬퍼 생성
	cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("chatwoot_cryptostore_key"), store)

	//cryptoHelper, err := cryptohelper.NewCryptoHelper(client, []byte("chatwoot_cryptostore_key"), db.DB)
	if err != nil {
		return nil, nil, fmt.Errorf("암호화 헬퍼 생성 실패: %w", err)
	}

	// 로그인 정보 설정
	cryptoHelper.LoginAs = &mautrix.ReqLogin{
		Type:       mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: user},
		Password:   password,
	}
	cryptoHelper.DBAccountID = user

	// 암호화 헬퍼 초기화
	if err := cryptoHelper.Init(ctx); err != nil {
		return nil, nil, fmt.Errorf("암호화 헬퍼 초기화 실패: %w", err)
	}

	// 클라이언트에 암호화 활성화
	client.Crypto = cryptoHelper

	log.Info().Msg("Matrix 클라이언트 및 암호화 헬퍼 초기화 완료")
	return client, cryptoHelper, nil
}

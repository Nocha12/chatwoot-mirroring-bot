// crypto_utils.go - 암호화/복호화 관련 유틸리티 함수
package queries

import (
	"errors"
	"github.com/rs/zerolog"
	
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/crypto"
)

// DecryptMatrixPassword는 Matrix 비밀번호를 복호화합니다.
func DecryptMatrixPassword(config MatrixIdentityConfig, key []byte, log *zerolog.Logger) (string, error) {
	if len(config.EncryptedPassword) == 0 || len(config.PasswordNonce) == 0 {
		log.Warn().Str("user_id", string(config.UserID)).Msg("암호화된 Matrix 비밀번호가 설정되지 않았습니다")
		return "", nil
	}

	return crypto.DecryptData(config.EncryptedPassword, config.PasswordNonce, key)
}

// DecryptMatrixAccessToken은 Matrix 접근 토큰을 복호화합니다.
func DecryptMatrixAccessToken(config MatrixIdentityConfig, key []byte, log *zerolog.Logger) (string, error) {
	if len(config.EncryptedAccessToken) == 0 || len(config.AccessTokenNonce) == 0 {
		log.Warn().Str("user_id", string(config.UserID)).Msg("암호화된 Matrix 접근 토큰이 설정되지 않았습니다")
		return "", nil
	}

	return crypto.DecryptData(config.EncryptedAccessToken, config.AccessTokenNonce, key)
}

// DecryptChatwootAccessToken은 Chatwoot 접근 토큰을 복호화합니다.
func DecryptChatwootAccessToken(config ChatwootAccountConfig, key []byte, log *zerolog.Logger) (string, error) {
	if len(config.EncryptedAccessToken) == 0 || len(config.EncryptionNonce) == 0 {
		log.Warn().Int("account_id", int(config.AccountID)).Msg("암호화된 Chatwoot 접근 토큰이 설정되지 않았습니다")
		return "", errors.New("암호화된 Chatwoot 접근 토큰이 설정되지 않았습니다")
	}

	return crypto.DecryptData(config.EncryptedAccessToken, config.EncryptionNonce, key)
}

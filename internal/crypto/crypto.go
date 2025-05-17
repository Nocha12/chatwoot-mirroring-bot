// Package crypto는 암호화 관련 유틸리티 함수를 제공합니다.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// EncryptData는 데이터를 마스터 키로 암호화합니다.
// AES-GCM 모드를 사용하여 plaintext를 암호화하고, 암호화된 데이터와 사용된 nonce를 반환합니다.
// 반환값: (암호화된 데이터, nonce, 오류)
func EncryptData(plaintext string, key []byte) ([]byte, []byte, error) {
	// 32바이트 키(AES-256)가 필요
	if len(key) != 32 {
		return nil, nil, errors.New("암호화 키는 정확히 32바이트여야 합니다")
	}

	// AES 암호화 객체 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("AES 암호화 객체 생성 실패: %w", err)
	}

	// GCM 모드 설정
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("GCM 모드 설정 실패: %w", err)
	}

	// 랜덤 nonce 생성 (12바이트)
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("nonce 생성 실패: %w", err)
	}

	// 암호화 실행
	ciphertext := aesgcm.Seal(nil, nonce, []byte(plaintext), nil)
	return ciphertext, nonce, nil
}

// DecryptData는 암호화된 데이터를 복호화합니다.
// 암호화에 사용된 것과 동일한 키와 nonce를 사용하여 암호문을 복호화합니다.
// 반환값: (복호화된 문자열, 오류)
func DecryptData(encryptedData []byte, nonce []byte, key []byte) (string, error) {
	// 입력 검증
	if len(encryptedData) == 0 || len(nonce) == 0 {
		return "", errors.New("암호화된 데이터나 nonce가 비어있습니다")
	}

	// 32바이트 키(AES-256)가 필요
	if len(key) != 32 {
		return "", errors.New("복호화 키는 정확히 32바이트여야 합니다")
	}

	// AES 암호화 객체 생성
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("AES 암호화 객체 생성 실패: %w", err)
	}

	// GCM 모드 설정
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM 모드 설정 실패: %w", err)
	}

	// nonce 크기 검증
	if len(nonce) != aesgcm.NonceSize() {
		return "", fmt.Errorf("잘못된 nonce 크기: %d (예상: %d)", len(nonce), aesgcm.NonceSize())
	}

	// 복호화 실행
	plaintext, err := aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return "", fmt.Errorf("데이터 복호화 실패: %w", err)
	}

	return string(plaintext), nil
}

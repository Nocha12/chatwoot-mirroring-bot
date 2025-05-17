package crypto

import (
	"crypto/rand"
	"io"
	"testing"
)

// TestEncryptDecrypt는 암호화 및 복호화 기능이 제대로 작동하는지 테스트합니다.
func TestEncryptDecrypt(t *testing.T) {
	// 테스트 데이터
	plaintexts := []string{
		"안녕하세요",
		"Hello, World!",
		"특수문자 테스트: !@#$%^&*()",
		"긴 문자열 테스트: " + string(make([]byte, 1000)),
		"",
	}

	// 32바이트 키 생성
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("테스트 키 생성 실패: %v", err)
	}

	for i, plaintext := range plaintexts {
		// 암호화
		ciphertext, nonce, err := EncryptData(plaintext, key)
		if err != nil {
			t.Errorf("테스트 케이스 #%d: 암호화 실패: %v", i, err)
			continue
		}

		// 복호화
		decrypted, err := DecryptData(ciphertext, nonce, key)
		if err != nil {
			t.Errorf("테스트 케이스 #%d: 복호화 실패: %v", i, err)
			continue
		}

		// 결과 확인
		if decrypted != plaintext {
			t.Errorf("테스트 케이스 #%d: 복호화된 텍스트가 일치하지 않음\n원본: %q\n결과: %q", i, plaintext, decrypted)
		}
	}
}

// TestEncryptWithInvalidKey는 잘못된 키로 암호화 시 오류가 발생하는지 테스트합니다.
func TestEncryptWithInvalidKey(t *testing.T) {
	invalidKeys := [][]byte{
		make([]byte, 16), // 16바이트 키 (AES-128)
		make([]byte, 24), // 24바이트 키 (AES-192)
		{},               // 빈 키
	}

	plaintext := "테스트 텍스트"

	for i, key := range invalidKeys {
		_, _, err := EncryptData(plaintext, key)
		if err == nil {
			t.Errorf("테스트 케이스 #%d: 잘못된 키를 사용했는데 오류가 발생하지 않음", i)
		}
	}
}

// TestDecryptWithInvalidInputs는 잘못된 입력으로 복호화 시 오류가 발생하는지 테스트합니다.
func TestDecryptWithInvalidInputs(t *testing.T) {
	// 32바이트 키 생성
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		t.Fatalf("테스트 키 생성 실패: %v", err)
	}

	// 유효한 데이터 생성
	plaintext := "테스트 텍스트"
	ciphertext, nonce, err := EncryptData(plaintext, key)
	if err != nil {
		t.Fatalf("테스트 데이터 암호화 실패: %v", err)
	}

	testCases := []struct {
		name        string
		ciphertext  []byte
		nonce       []byte
		key         []byte
		shouldError bool
	}{
		{"빈 암호문", []byte{}, nonce, key, true},
		{"빈 nonce", ciphertext, []byte{}, key, true},
		{"잘못된 키 크기", ciphertext, nonce, make([]byte, 16), true},
		{"잘못된 nonce 크기", ciphertext, make([]byte, 8), key, true},
		{"변조된 암호문", append(ciphertext, 1), nonce, key, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecryptData(tc.ciphertext, tc.nonce, tc.key)
			if (err == nil) == tc.shouldError {
				t.Errorf("%s: 예상된 오류 상태와 다름 (오류 발생 여부: %v, 예상: %v)", tc.name, err != nil, tc.shouldError)
			}
		})
	}
}

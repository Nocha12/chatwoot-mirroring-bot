package chatwootapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
)

// ContactsAPI는 Chatwoot Contact API 엔드포인트와 상호작용하는 메서드를 그룹화합니다.
type ContactsAPI struct {
	client *Client // 부모 Client 구조체에 대한 참조
}

// CreateContactRequestPayload는 연락처 생성 API 요청 페이로드입니다.
type CreateContactRequestPayload struct {
	InboxID    InboxID `json:"inbox_id"`
	Name       string  `json:"name"`
	Identifier string  `json:"identifier"`
}

// CreateContact는 Chatwoot에 새로운 연락처를 생성합니다.
func (api *ContactsAPI) CreateContact(ctx context.Context, userID id.UserID, name string) (ContactID, error) {
	log := zerolog.Ctx(ctx).With().
		Str("user_id", userID.String()).
		Str("name", name).
		Logger()

	if name == "" {
		name = userID.String()
		// Beeper iMessage 브릿지 사용자에 대한 특별 처리
		if userID.Homeserver() == "beeper.local" && strings.HasPrefix(userID.Localpart(), "imessagego_1.") {
			decoded, err := id.DecodeUserLocalpart(strings.TrimPrefix(userID.Localpart(), "imessagego_1."))
			if err == nil {
				name = decoded
			}
		}
	}

	log.Info().Str("name", name).Msg("연락처 생성 중")

	// 요청 페이로드 준비 (구조체 사용)
	payload := CreateContactRequestPayload{
		InboxID:    api.client.InboxID, // 부모 클라이언트에서 InboxID 사용
		Name:       name,
		Identifier: userID.String(),
	}
	jsonValue, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Msg("연락처 생성 페이로드 마샬링 실패")
		return 0, fmt.Errorf("연락처 생성 페이로드 마샬링 실패: %w", err)
	}

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	var contactPayload struct {
		Payload struct {
			Contact struct {
				ID ContactID `json:"id"`
			} `json:"contact"`
		} `json:"payload"`
	}
	err = api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodPost,
		"contacts",
		nil, // 쿼리 파라미터 없음
		bytes.NewBuffer(jsonValue),
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		&contactPayload,
	)
	if err != nil {
		log.Err(err).Msg("연락처 생성 API 요청 실패")
		return 0, fmt.Errorf("연락처 생성 API 요청 실패: %w", err)
	}

	log.Debug().Any("contact_payload", contactPayload).Msg("연락처 페이로드 받음")
	return contactPayload.Payload.Contact.ID, nil
}

// ContactIDForMXID는 Matrix ID를 이용해 Chatwoot 연락처 ID를 찾습니다.
func (api *ContactsAPI) ContactIDForMXID(ctx context.Context, userID id.UserID) (ContactID, error) {
	log := zerolog.Ctx(ctx)
	query := userID.String()
	// Beeper iMessage 브릿지 사용자에 대한 특별 처리
	if userID.Homeserver() == "beeper.local" && strings.HasPrefix(userID.Localpart(), "imessagego_1.") {
		decoded, err := id.DecodeUserLocalpart(strings.TrimPrefix(userID.Localpart(), "imessagego_1."))
		if err == nil {
			query = decoded
		}
	}

	log.Info().Str("query", query).Msg("연락처 검색")

	// 쿼리 파라미터 맵 생성
	queryParams := map[string]string{"q": query}

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	var contactsPayload struct {
		Payload []struct {
			ID          ContactID `json:"id"`
			Name        string    `json:"name"`
			Identifier  string    `json:"identifier"`
			Email       string    `json:"email"`
			PhoneNumber string    `json:"phone_number"`
		} `json:"payload"`
	}

	err := api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodGet,
		"contacts/search",
		queryParams,          // 쿼리 파라미터 전달
		nil,                  // GET 요청은 본문 없음
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		&contactsPayload,
	)
	if err != nil {
		log.Err(err).Msg("연락처 검색 API 요청 실패")
		return 0, fmt.Errorf("연락처 검색 API 요청 실패: %w", err)
	}

	// 응답 페이로드에서 일치하는 연락처 찾기 (이 로직은 doAPIRequest에 포함되지 않음)
	for _, contact := range contactsPayload.Payload {
		if contact.Identifier == query {
			return contact.ID, nil
		} else if contact.Email == query {
			return contact.ID, nil
		} else if contact.PhoneNumber == query {
			return contact.ID, nil
		}
	}

	return 0, fmt.Errorf("사용자 ID %s와 일치하는 연락처를 찾을 수 없습니다", query)
}

package chatwootapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

// ConversationsAPI는 Chatwoot Conversation API 엔드포인트와 상호작용하는 메서드를 그룹화합니다.
type ConversationsAPI struct {
	client *Client // 부모 Client 구조체에 대한 참조
}

// GetConversation는 특정 대화의 정보를 가져옵니다.
func (api *ConversationsAPI) GetConversation(ctx context.Context, conversationID ConversationID) (*Conversation, error) {
	log := zerolog.Ctx(ctx).With().
		Int("conversation_id", int(conversationID)).
		Logger()

	log.Info().Msg("대화 정보 가져오는 중")

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	var conversation Conversation
	err := api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodGet,
		fmt.Sprintf("conversations/%d", conversationID),
		nil,                  // 쿼리 파라미터 없음
		nil,                  // GET 요청은 본문 없음
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		&conversation,
	)
	if err != nil {
		log.Err(err).Msg("대화 정보 가져오기 API 요청 실패")
		return nil, fmt.Errorf("대화 정보 가져오기 API 요청 실패: %w", err)
	}

	return &conversation, nil
}

// CreateConversationRequestPayload는 대화 생성 API 요청 페이로드입니다.
type CreateConversationRequestPayload struct {
	SourceID         string            `json:"source_id"`
	InboxID          InboxID           `json:"inbox_id"`
	ContactID        ContactID         `json:"contact_id"`
	CustomAttributes map[string]string `json:"custom_attributes,omitempty"`
}

// CreateConversation은 새로운 대화를 생성합니다.
func (api *ConversationsAPI) CreateConversation(ctx context.Context, sourceID string, contactID ContactID, additionalAttrs map[string]string) (*Conversation, error) {
	log := zerolog.Ctx(ctx).With().
		Str("source_id", sourceID).
		Int("contact_id", int(contactID)).
		Logger()

	log.Info().Msg("대화 생성 중")

	// 요청 페이로드 준비 (구조체 사용)
	payload := CreateConversationRequestPayload{
		SourceID:         sourceID,
		InboxID:          api.client.InboxID, // 부모 클라이언트에서 InboxID 사용
		ContactID:        contactID,
		CustomAttributes: additionalAttrs,
	}
	jsonValue, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Msg("대화 생성 페이로드 마샬링 실패")
		return nil, fmt.Errorf("대화 생성 페이로드 마샬링 실패: %w", err)
	}

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	var conversation Conversation
	err = api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodPost,
		"conversations",
		nil, // 쿼리 파라미터 없음
		bytes.NewBuffer(jsonValue),
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		&conversation,
	)
	if err != nil {
		log.Err(err).Msg("대화 생성 API 요청 실패")
		return nil, fmt.Errorf("대화 생성 API 요청 실패: %w", err)
	}

	return &conversation, nil
}

// ToggleStatusRequestPayload는 상태 변경 API 요청 페이로드입니다.
type ToggleStatusRequestPayload struct {
	Status string `json:"status"`
}

// ToggleStatus는 대화의 상태를 변경합니다.
func (api *ConversationsAPI) ToggleStatus(ctx context.Context, conversationID ConversationID, status ConversationStatus) error {
	log := zerolog.Ctx(ctx).With().
		Int("conversation_id", int(conversationID)).
		Str("status", string(status)).
		Logger()

	log.Info().Msg("대화 상태 변경 중")

	// 요청 페이로드 준비 (구조체 사용)
	payload := ToggleStatusRequestPayload{
		Status: string(status),
	}
	jsonValue, err := json.Marshal(payload)
	if err != nil {
		log.Err(err).Msg("상태 변경 페이로드 마샬링 실패")
		return fmt.Errorf("상태 변경 페이로드 마샬링 실패: %w", err)
	}

	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	err = api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodPost,
		fmt.Sprintf("conversations/%d/toggle_status", conversationID),
		nil, // 쿼리 파라미터 없음
		bytes.NewBuffer(jsonValue),
		[]int{http.StatusOK}, // 예상 상태 코드 200 OK
		nil,                  // 응답 결과 필요 없음
	)
	if err != nil {
		log.Err(err).Msg("대화 상태 변경 API 요청 실패")
		return fmt.Errorf("대화 상태 변경 API 요청 실패: %w", err)
	}

	return nil
}

// CreateOrGetConversation은 연락처와 소스 ID를 사용해 대화를 찾거나 생성합니다.
func (api *ConversationsAPI) CreateOrGetConversation(ctx context.Context, contactID ContactID, sourceID string) (ConversationID, error) {
	log := zerolog.Ctx(ctx).With().
		Int("contact_id", int(contactID)).
		Str("source_id", sourceID).
		Logger()

	log.Info().Msg("대화 찾기/생성 중")

	// 먼저 연락처의 열린 대화를 찾아봄
	// doAPIRequest를 사용하여 요청 실행 및 응답 처리
	var conversations []Conversation
	err := api.client.doAPIRequest( // 부모 클라이언트의 헬퍼 메서드 호출
		ctx,
		http.MethodGet,
		fmt.Sprintf("contacts/%d/conversations", contactID),
		map[string]string{"status": "open"}, // 쿼리 파라미터 전달
		nil,                                 // GET 요청은 본문 없음
		[]int{http.StatusOK},                // 예상 상태 코드 200 OK
		&conversations,
	)
	if err != nil {
		log.Err(err).Msg("열린 대화 검색 API 요청 실패")
		// 오류 발생 시 생성 로직으로 넘어가지 않고 오류 반환
		return 0, fmt.Errorf("열린 대화 검색 API 요청 실패: %w", err)
	}

	// 검색 결과 확인
	for _, conv := range conversations {
		// ID가 유효하고 sourceID가 일치하거나 비어있는 경우
		if conv.ID > 0 && (sourceID == "" || conv.Meta.SourceID == sourceID) {
			log.Info().Int("conversation_id", int(conv.ID)).Msg("기존 열린 대화 찾음")
			return conv.ID, nil
		}
	}

	log.Info().Msg("기존 열린 대화 찾지 못함, 새로 생성 시도")
	// 열린 대화가 없으면 생성 (CreateConversation 함수 호출)
	// CreateConversation 함수는 이미 doAPIRequest를 사용하도록 리팩토링됨
	conversation, err := api.CreateConversation(ctx, sourceID, contactID, nil) // 동일 API 그룹 내 메서드 호출
	if err != nil {
		log.Err(err).Msg("대화 생성 실패")
		return 0, fmt.Errorf("대화 생성 실패: %w", err)
	}

	log.Info().Int("conversation_id", int(conversation.ID)).Msg("새 대화 생성 성공")
	return conversation.ID, nil
}

// CloseConversation은 대화를 닫습니다.
func (api *ConversationsAPI) CloseConversation(ctx context.Context, conversationID ConversationID) error {
	// ToggleStatus 함수는 이미 doAPIRequest를 사용하도록 리팩토링됨
	return api.ToggleStatus(ctx, conversationID, ConversationStatusResolved) // 동일 API 그룹 내 메서드 호출
}

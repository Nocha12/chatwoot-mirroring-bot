package chatwoot

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog/hlog"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// WebhookHandler는 Chatwoot 웹훅 요청을 처리하는 구조체입니다.
type WebhookHandler struct {
	// 의존성 주입을 위한 필드들
	handler *MessageHandler
}

// NewWebhookHandler는 새로운 WebhookHandler 인스턴스를 생성합니다.
func NewWebhookHandler(handler *MessageHandler) *WebhookHandler {
	return &WebhookHandler{
		handler: handler,
	}
}

// HandleWebhook는 Chatwoot 웹훅 HTTP 요청을 처리하는 함수입니다.
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// 요청 로깅
	logger := hlog.FromRequest(r)
	ctx := logger.WithContext(r.Context())
	logger.Info().Str("method", r.Method).Str("url", r.URL.String()).Msg("웹훅 수신")

	// POST 요청만 처리
	if r.Method != http.MethodPost {
		logger.Warn().Str("method", r.Method).Msg("지원되지 않는 HTTP 메서드")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 요청 본문 읽기
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error().Err(err).Msg("요청 본문 읽기 실패")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// 디버그 로깅
	logger.Debug().Str("body", string(body)).Msg("수신된 웹훅 본문")

	// 이벤트 타입 확인
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		logger.Error().Err(err).Msg("요청 본문 JSON 파싱 실패")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	eventType, ok := data["event"].(string)
	if !ok {
		logger.Warn().Interface("data", data).Msg("이벤트 타입이 없거나 문자열이 아님")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logger.Info().Str("event_type", eventType).Msg("웹훅 이벤트 타입 확인")

	// 이벤트 타입에 따른 처리
	switch eventType {
	case "message_created":
		var mc chatwootapi.MessageCreated
		err = json.Unmarshal(body, &mc)
		if err != nil {
			logger.Error().Err(err).Msg("message_created 이벤트 파싱 실패")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Matrix 메시지 생성 처리를 비동기로 실행
		go func() {
			err := h.handler.HandleMessageCreated(ctx, mc)
			if err != nil {
				logger.Error().Err(err).Msg("메시지 생성 처리 실패")
			}
		}()

	default:
		logger.Debug().Str("event_type", eventType).Msg("처리되지 않는 이벤트 타입")
	}

	// 성공 응답
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"success": true}`)
}

package matrix

import (
	"context"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
)

// MatrixHandler 는 Matrix 이벤트 처리를 위한 구조체입니다.
type MatrixHandler struct {
	client        MatrixClient
	chatwootApis  map[chatwootapi.AccountID]*chatwootapi.Client
	defaultAccID  chatwootapi.AccountID
	stateStore    StateStore
	messageHelper MessageHelper
	convManager   ConversationManager
}

// NewMatrixHandler 는 새로운 MatrixHandler 인스턴스를 생성합니다.
func NewMatrixHandler(
	client MatrixClient,
	chatwootApis map[chatwootapi.AccountID]*chatwootapi.Client,
	defaultAccID chatwootapi.AccountID,
	stateStore StateStore,
	messageHelper MessageHelper,
	convManager ConversationManager,
) *MatrixHandler {
	return &MatrixHandler{
		client:        client,
		chatwootApis:  chatwootApis,
		defaultAccID:  defaultAccID,
		stateStore:    stateStore,
		messageHelper: messageHelper,
		convManager:   convManager,
	}
}

// GetCustomAttrForDevice 는 디바이스 정보를 기반으로 커스텀 속성을 반환합니다.
func (h *MatrixHandler) GetCustomAttrForDevice(ctx context.Context, evt *event.Event) (string, string) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "get_custom_attr_for_device").
		Logger()

	clientType, exists := evt.Content.Raw["com.beeper.origin_client_type"]
	if !exists || clientType == nil {
		log.Debug().Msg("클라이언트 타입 정보 없음")
		return "", ""
	}

	var clientTypeString, clientVersionString string
	if ct, ok := clientType.(string); ok {
		clientTypeString = ct + " version"
	} else {
		log.Warn().Msg("클라이언트 타입이 문자열이 아님")
		return "", ""
	}

	clientVersion, exists := evt.Content.Raw["com.beeper.origin_client_version"]
	if !exists || clientVersion == nil {
		log.Debug().Msg("클라이언트 버전 정보 없음")
		return "", ""
	}

	if cv, ok := clientVersion.(string); ok {
		clientVersionString = cv
	} else {
		log.Warn().Msg("클라이언트 버전이 문자열이 아님")
		return "", ""
	}

	log.Debug().
		Str("client_type", clientTypeString).
		Str("client_version", clientVersionString).
		Msg("클라이언트 타입과 버전 정보 확인")
	return clientTypeString, clientVersionString
}

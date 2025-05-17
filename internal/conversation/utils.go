package conversation

import (
	"context"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
)

// rageshakeIssueRegex는 문제 ID 패턴을 매칭하는 정규표현식입니다.
var rageshakeIssueRegex = regexp.MustCompile(`[A-Z]{1,5}-\d+`)

// GetCustomAttrForDevice는 장치 관련 커스텀 속성을 확인합니다.
func (m *ManagerImpl) GetCustomAttrForDevice(ctx context.Context, evt *event.Event) (string, string) {
	log := zerolog.Ctx(ctx)

	// Rageshake 이슈 ID 확인
	issue := rageshakeIssueRegex.FindString(evt.Content.AsMessage().Body)
	if issue != "" {
		log.Info().Str("issue", issue).Msg("메시지에서 이슈 ID를 발견했습니다")
		return "rageshake_issue", issue
	}

	// 장치 정보 확인
	if strings.Contains(evt.Content.AsMessage().Body, "Browser: ") || strings.Contains(evt.Content.AsMessage().Body, "Platform: ") {
		// rageshake 로그 형식의 디바이스 정보 확인
		return "device_type", "rageshake"
	}

	// 다른 디바이스 정보 확인 로직을 추가할 수 있습니다.

	return "", ""
}

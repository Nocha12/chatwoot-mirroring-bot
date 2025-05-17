package chatwootapi

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

// 파일명에서 인용부호를 이스케이프하기 위한 유틸리티
var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// MakeURI는 Chatwoot API 엔드포인트 URI를 생성합니다.
func (c *Client) MakeURI(endpoint string) string {
	url, err := url.Parse(c.BaseURL)
	if err != nil {
		// BaseURL 파싱 실패는 심각한 설정 오류이므로 패닉 발생
		panic(fmt.Sprintf("Invalid BaseURL: %v", err))
	}
	// path.Join은 자동으로 슬래시를 처리하지만, endpoint가 절대 경로일 수 있으므로 주의
	// Chatwoot API 엔드포인트는 상대 경로라고 가정
	url.Path = path.Join(url.Path, fmt.Sprintf("api/v1/accounts/%d", c.AccountID), endpoint)
	return url.String()
}

// escapeQuotes는 문자열의 인용부호를 이스케이프합니다.
func (c *Client) escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

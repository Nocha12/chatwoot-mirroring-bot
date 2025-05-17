package chatwootapi

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/rs/zerolog"
)

// DownloadAttachment는 Chatwoot 첨부파일을 다운로드합니다.
func (c *Client) DownloadAttachment(ctx context.Context, url string) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("첨부파일에 다운로드 URL이 없습니다")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 요청 생성 실패: %w", err)
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 다운로드 실패: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("resp.Body.Close 에러")
		}
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 오류 응답 본문도 읽어와서 로그에 남기는 것이 좋음
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr == nil {
			zerolog.Ctx(ctx).Error().Int("status_code", resp.StatusCode).Str("response", string(respBody)).Msg("첨부파일 다운로드 실패")
			return nil, fmt.Errorf("첨부파일 다운로드 실패: HTTP %d (응답: %s)", resp.StatusCode, string(respBody))
		}
		zerolog.Ctx(ctx).Error().Int("status_code", resp.StatusCode).Msg("첨부파일 다운로드 실패")
		return nil, fmt.Errorf("첨부파일 다운로드 실패: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("첨부파일 데이터 읽기 실패: %w", err)
	}

	return data, nil
}

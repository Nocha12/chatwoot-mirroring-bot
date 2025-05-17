package chatwootapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
)

// DoRequest는 HTTP 요청을 실행합니다.
// 이 함수는 doAPIRequest 및 doMultipartAPIRequest 내부에서 사용됩니다.
func (c *Client) DoRequest(req *http.Request) (*http.Response, error) {
	req.Header.Add("Api-Access-Token", c.AccessToken)
	return c.HttpClient.Do(req)
}

// doAPIRequest는 Chatwoot API에 대한 HTTP 요청을 생성, 실행, 응답 처리하는 헬퍼 메서드입니다.
// 요청을 생성하고, 공통 헤더를 설정하며, 응답 상태 코드를 검증하고, 응답 본문을 JSON으로 디코딩합니다.
func (c *Client) doAPIRequest(ctx context.Context, method, endpoint string, queryParams map[string]string, body io.Reader, expectedStatusCodes []int, result interface{}) error {
	log := zerolog.Ctx(ctx)

	// 전체 URI 생성
	urlStr := c.MakeURI(endpoint)
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		log.Err(err).Str("url", urlStr).Msg("URL 파싱 실패")
		return fmt.Errorf("URL 파싱 실패: %w", err)
	}

	// 쿼리 파라미터 추가
	if len(queryParams) > 0 {
		q := parsedURL.Query()
		for key, value := range queryParams {
			q.Add(key, value)
		}
		parsedURL.RawQuery = q.Encode()
	}

	// HTTP 요청 생성
	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), body)
	if err != nil {
		log.Err(err).Str("method", method).Str("url", parsedURL.String()).Msg("API 요청 생성 실패")
		return fmt.Errorf("API 요청 생성 실패: %w", err)
	}

	// Content-Type 헤더 설정 (body가 있고 GET 메소드가 아니며 Content-Type이 설정되지 않은 경우)
	// 멀티파트 요청의 경우 Content-Type은 별도로 설정해야 하므로 여기서는 application/json만 처리
	if body != nil && method != http.MethodGet && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// 요청 실행
	resp, err := c.DoRequest(req)
	if err != nil {
		log.Err(err).Str("method", method).Str("url", parsedURL.String()).Msg("API 요청 실행 실패")
		return fmt.Errorf("API 요청 실행 실패: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Err(err).Msg("resp.Body.Close 에러")
		}
	}()

	// 상태 코드 확인
	statusOK := false
	for _, code := range expectedStatusCodes {
		if resp.StatusCode == code {
			statusOK = true
			break
		}
	}

	if !statusOK {
		// 오류 응답 읽기
		respBody, readErr := io.ReadAll(resp.Body)
		errorMsg := fmt.Sprintf("%s %s 요청 실패: 상태 코드 %d", method, endpoint, resp.StatusCode)

		if readErr == nil && len(respBody) > 0 {
			log.Error().Int("status_code", resp.StatusCode).Str("response", string(respBody)).Msg(errorMsg)
			return fmt.Errorf("%s (응답: %s)", errorMsg, string(respBody))
		}

		log.Error().Int("status_code", resp.StatusCode).Msg(errorMsg)
		return fmt.Errorf("%s", errorMsg)
	}

	// 응답 결과가 필요한 경우 JSON 디코딩
	if result != nil {
		// 응답 본문이 비어있을 수 있으므로 먼저 확인
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Err(readErr).Msg("API 응답 본문 읽기 실패")
			return fmt.Errorf("API 응답 본문 읽기 실패: %w", readErr)
		}
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, result); err != nil {
				log.Err(err).Str("response_body", string(respBody)).Msg("API 응답 디코딩 실패")
				return fmt.Errorf("API 응답 디코딩 실패: %w", err)
			}
		} else {
			// 응답 본문이 비어있는데 결과 객체가 필요한 경우 (예외 상황)
			log.Warn().Msg("API 응답 본문이 비어있는데 결과 객체 디코딩 시도")
			// 이 경우 오류로 처리하거나, result가 포인터이고 nil이 아니면 초기화 상태로 유지
		}
	}

	return nil
}

// doMultipartAPIRequest는 Chatwoot API에 대한 멀티파트 HTTP 요청을 생성, 실행, 응답 처리하는 헬퍼 메서드입니다.
// 요청 본문과 Content-Type은 외부에서 생성하여 전달받습니다.
func (c *Client) doMultipartAPIRequest(ctx context.Context, method, endpoint string, body io.Reader, contentType string, expectedStatusCodes []int, result interface{}) error {
	log := zerolog.Ctx(ctx)

	// 전체 URI 생성
	urlStr := c.MakeURI(endpoint)
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		log.Err(err).Str("url", urlStr).Msg("URL 파싱 실패")
		return fmt.Errorf("URL 파싱 실패: %w", err)
	}

	// HTTP 요청 생성
	req, err := http.NewRequestWithContext(ctx, method, parsedURL.String(), body)
	if err != nil {
		log.Err(err).Str("method", method).Str("url", parsedURL.String()).Msg("멀티파트 API 요청 생성 실패")
		return fmt.Errorf("멀티파트 API 요청 생성 실패: %w", err)
	}

	// Content-Type 헤더 설정 (멀티파트 경계 포함)
	req.Header.Set("Content-Type", contentType)

	// 요청 실행
	resp, err := c.DoRequest(req)
	if err != nil {
		log.Err(err).Str("method", method).Str("url", parsedURL.String()).Msg("멀티파트 API 요청 실행 실패")
		return fmt.Errorf("멀티파트 API 요청 실행 실패: %w", err)
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Err(err).Msg("resp.Body.Close 에러")
		}
	}()

	// 상태 코드 확인
	statusOK := false
	for _, code := range expectedStatusCodes {
		if resp.StatusCode == code {
			statusOK = true
			break
		}
	}

	if !statusOK {
		// 오류 응답 읽기
		respBody, readErr := io.ReadAll(resp.Body)
		errorMsg := fmt.Sprintf("%s %s 요청 실패: 상태 코드 %d", method, endpoint, resp.StatusCode)

		if readErr == nil && len(respBody) > 0 {
			log.Error().Int("status_code", resp.StatusCode).Str("response", string(respBody)).Msg(errorMsg)
			return fmt.Errorf("%s (응답: %s)", errorMsg, string(respBody))
		}

		log.Error().Int("status_code", resp.StatusCode).Msg(errorMsg)
		return fmt.Errorf("%s", errorMsg)
	}

	// 응답 결과가 필요한 경우 JSON 디코딩
	if result != nil {
		// 응답 본문이 비어있을 수 있으므로 먼저 확인
		respBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Err(readErr).Msg("멀티파트 API 응답 본문 읽기 실패")
			return fmt.Errorf("멀티파트 API 응답 본문 읽기 실패: %w", readErr)
		}
		if len(respBody) > 0 {
			if err := json.Unmarshal(respBody, result); err != nil {
				log.Err(err).Str("response_body", string(respBody)).Msg("멀티파트 API 응답 디코딩 실패")
				return fmt.Errorf("멀티파트 API 응답 디코딩 실패: %w", err)
			}
		} else {
			log.Warn().Msg("멀티파트 API 응답 본문이 비어있는데 결과 객체 디코딩 시도")
		}
	}

	return nil
}

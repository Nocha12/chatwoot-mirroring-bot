package chatwootapi

import (
	"errors"
	"net/http"
	"time"
)

// Client는 Chatwoot API와 상호작용하기 위한 클라이언트 구조체입니다.
// 각 기능별 API 그룹에 대한 필드를 가집니다.
type Client struct {
	BaseURL     string
	AccountID   AccountID
	InboxID     InboxID
	AccessToken string

	HttpClient *http.Client

	// 기능별 API 그룹 필드
	Contacts      *ContactsAPI
	Conversations *ConversationsAPI
	Messages      *MessagesAPI
	// 필요한 경우 다른 API 그룹 추가
}

// NewClient는 새로운 Chatwoot API 클라이언트를 생성하고 기능별 API 그룹을 초기화합니다.
func NewClient(baseURL string, accountID AccountID, inboxID InboxID, accessToken string) *Client {
	c := &Client{
		BaseURL:     baseURL,
		AccountID:   accountID,
		InboxID:     inboxID,
		AccessToken: accessToken,
		HttpClient: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("too many (>=10) redirects, cancelling request")
				}
				if len(via) > 0 {
					for key, values := range via[len(via)-1].Header {
						req.Header[key] = values
					}
				}
				return nil
			},
		},
	}

	// 기능별 API 그룹 초기화
	c.Contacts = &ContactsAPI{client: c}
	c.Conversations = &ConversationsAPI{client: c}
	c.Messages = &MessagesAPI{client: c}

	return c
}

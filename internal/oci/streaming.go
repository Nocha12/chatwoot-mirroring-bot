package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"maunium.net/go/mautrix/event"
)

// QueuedEventType 은 스트림에 저장되는 이벤트 종류를 정의합니다.
type QueuedEventType string

const (
	// Matrix 측 이벤트
	MatrixMessageEvent   QueuedEventType = "matrix_message"
	MatrixReactionEvent  QueuedEventType = "matrix_reaction"
	MatrixRedactionEvent QueuedEventType = "matrix_redaction"
	// Chatwoot 측 이벤트
	ChatwootMessageEvent QueuedEventType = "chatwoot_message"
)

// QueuedEvent 은 스트림에 저장되는 메시지 구조체입니다.
type QueuedEvent struct {
	Type          QueuedEventType             `json:"type"`
	MatrixEvent   *event.Event                `json:"matrix_event,omitempty"`
	ChatwootEvent *chatwootapi.MessageCreated `json:"chatwoot_event,omitempty"`
}

// Producer 는 OCI Streaming 에 메시지를 게시합니다.
type Producer struct {
	endpoint string
	topic    string
	token    string
	client   *http.Client
}

// NewProducer 는 새로운 Producer 를 생성합니다.
func NewProducer(endpoint, topic, token string) *Producer {
	return &Producer{endpoint: endpoint, topic: topic, token: token, client: &http.Client{}}
}

// Publish 는 이벤트를 스트림에 전송합니다.
func (p *Producer) Publish(ctx context.Context, evt QueuedEvent) error {
	data, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	url := fmt.Sprintf("%s/streams/%s/messages", p.endpoint, p.topic)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("Authorization", p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("publish failed: %s", string(body))
	}
	return nil
}

// Consumer 는 OCI Streaming 에서 메시지를 읽어옵니다.
type Consumer struct {
	endpoint string
	topic    string
	token    string
	client   *http.Client
	cursor   string
}

// NewConsumer 는 새로운 Consumer 를 생성합니다.
func NewConsumer(endpoint, topic, token string) *Consumer {
	return &Consumer{endpoint: endpoint, topic: topic, token: token, client: &http.Client{}}
}

// GetEvents 는 스트림에서 메시지를 읽어 이벤트 배열로 반환합니다.
func (c *Consumer) GetEvents(ctx context.Context) ([]QueuedEvent, error) {
	url := fmt.Sprintf("%s/streams/%s/messages?cursor=%s", c.endpoint, c.topic, c.cursor)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", c.token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("consume failed: %s", string(body))
	}
	var result struct {
		Next   string        `json:"next"`
		Events []QueuedEvent `json:"events"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	c.cursor = result.Next
	return result.Events, nil
}

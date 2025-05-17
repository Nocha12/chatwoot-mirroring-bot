package chatwoot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// createNewChatRoom 새 채팅방을 생성하고 데이터베이스에 매핑 정보를 저장합니다
// nolint:unused
func createNewChatRoom(ctx context.Context, mc chatwootapi.MessageCreated, accountID string, startNewChatCfg config.StartNewChat, stateStore *database.Database, matrixClient *mautrix.Client) (id.RoomID, error) {
	log := zerolog.Ctx(ctx).With().
		Bool("snc_enabled", true).
		Logger()

	// 새 방 생성 API 호출
	type StartNewChatResp struct {
		RoomID id.RoomID `json:"room_id,omitempty"`
		Error  string    `json:"error,omitempty"`
	}

	// Create a new room for this conversation using the start new chat endpoint
	body, err := json.Marshal(mc.Conversation.Meta.Sender)
	if err != nil {
		log.Err(err).Msg("failed to marshal sender to JSON")
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, startNewChatCfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		log.Err(err).Msg("failed to create request")
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", startNewChatCfg.Token))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Err(err).Msg("failed to make request")
		return "", err
	}
	defer func() {
		err := resp.Body.Close()
		if err != nil {
			log.Err(err).Msg("resp.Body.Close 에러")
		}
	}()

	var sncResp StartNewChatResp
	err = json.NewDecoder(resp.Body).Decode(&sncResp)
	if err != nil {
		log.Err(err).Msg("failed to read response body")
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		log.Warn().Int("status_code", resp.StatusCode).Any("resp", sncResp).Msg("failed to create new chat")
		return "", fmt.Errorf("failed to create new chat: %s", sncResp.Error)
	} else if sncResp.RoomID == "" {
		log.Warn().Any("resp", sncResp).Msg("invalid start new chat response")
		return "", fmt.Errorf("invalid start new chat response: %s", sncResp.Error)
	}

	log = log.With().Stringer("room_id", sncResp.RoomID).Logger()
	log.Info().Msg("created new chat for conversation")

	// DB에 방-대화 매핑 저장
	accountIDInt, err := strconv.Atoi(accountID)
	if err != nil {
		log.Err(err).Msg("failed to convert account ID to integer")
		return "", err
	}
	err = stateStore.StoreMatrixRoomForChatwootConversation(ctx, sncResp.RoomID, chatwootapi.ConversationID(mc.Conversation.ID), chatwootapi.AccountID(accountIDInt))
	if err != nil {
		log.Err(err).Msg("failed to store room-conversation mapping")
		return "", err
	}

	// 방 상태 확인
	_, err = matrixClient.State(ctx, sncResp.RoomID)
	if err != nil {
		log.Err(err).Msg("failed to get room state")
		return "", err
	}

	return sncResp.RoomID, nil
}

package chatwoot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/internal/config"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/database/queries"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/matrix"
	"github.com/Nocha12/chatwoot-mirroring-bot/internal/util"
	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// HandleMessageCreated processes new messages from Chatwoot
func HandleMessageCreated(ctx context.Context, mc chatwootapi.MessageCreated, accountID chatwootapi.AccountID, chatwootAPI *chatwootapi.Client, matrixClient *mautrix.Client, stateStore matrix.StateStore, cfg interface{}) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "handle_message_created").
		Int("message_id", int(mc.ID)).
		Int("conversation_id", int(mc.Conversation.ID)).
		Int("account_id", int(accountID)).
		Logger()

	// 컨텍스트 타임아웃 추가
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ctx = log.WithContext(ctx)

	// Skip private messages
	if mc.Private {
		return nil
	}

	// chatwootapi.ConversationID로 변환
	cwConvID := chatwootapi.ConversationID(mc.Conversation.ID)

	roomID, _, err := stateStore.GetMatrixRoomFromChatwootConversation(ctx, cwConvID, accountID)
	if err != nil {
		if errors.Is(err, queries.ErrNotFound) {
			log.Err(err).Msg("couldn't find room for conversation")

			// 새 채팅 시작 기능 활성화 확인
			// 설정 값 추출 - config 패키지의 적절한 메서드 사용 필요
			enableNewChat := false // 기본값
			cfgMap, ok := cfg.(map[string]interface{})
			if ok {
				startNewChat, exists := cfgMap["start_new_chat"]
				if exists {
					if startNewChatMap, ok := startNewChat.(map[string]interface{}); ok {
						if enable, ok := startNewChatMap["enable"].(bool); ok {
							enableNewChat = enable
						}
					}
				}
			}

			if !enableNewChat {
				log.Error().Msg("couldn't find room and start new chat is disabled")
				return errors.New("room not found and start new chat is disabled")
			}

			// 새 채팅방 생성 요청만 하고 구현은 일단 보류
			log.Warn().Msg("createNewChatRoom 기능은 아직 구현되지 않았습니다")
			return errors.New("room creation not implemented yet")
		} else {
			log.Err(err).Msg("error finding room for conversation")
			return err
		}
	}

	log = log.With().Stringer("room_id", roomID).Logger()
	ctx = log.WithContext(ctx)

	// 동시 처리 방지를 위한 락 사용 (rooms.go에서 가져옴)
	matrixRoomLock := matrix.GetOrCreateRoomLock(roomID)
	matrixRoomLock.Lock()
	log.Debug().Msg("acquired send lock")
	defer matrixRoomLock.Unlock()
	defer log.Debug().Msg("released send lock")

	// 이미 처리된 메시지인지 확인
	// 기존 코드는 구현되지 않은 메서드를 호출하고 있으므로 stateStore 인터페이스를 활용
	messageIDs, accountIDInt, err := stateStore.GetChatwootMessageIDsForMatrixEventID(ctx, id.EventID(fmt.Sprintf("%d", mc.ID)))
	hasEvent := err == nil && len(messageIDs) > 0

	// 삭제된 메시지 처리
	if mc.ContentAttributes != nil && mc.ContentAttributes.Deleted {
		log.Info().Int("message_id", int(mc.ID)).Msg("message deleted")

		// 실제 메시지 삭제 처리 - 삭제할 이벤트 ID 목록이 필요하므로 우선 구현 보류
		log.Warn().Msg("메시지 삭제 기능은 아직 구현되지 않았습니다")
		return nil
	}

	// 이미 처리된 메시지인 경우 스킵
	if hasEvent {
		log.Info().
			Any("message_ids", messageIDs).
			Int("account_id", int(accountIDInt)).
			Msg("chatwoot message already processed")
		return nil
	}

	// 메시지 처리
	var resp *mautrix.RespSendEvent
	message := mc.Conversation.Messages[0]

	// 텍스트 메시지 처리
	if message.Content != nil {
		var messageEventContent event.MessageEventContent

		// Sender.AvailableName 필드가 없으므로 대신 Name 사용
		senderName := message.Sender.Name

		messageText := fmt.Sprintf("%s - %s", *message.Content, strings.Split(senderName, " ")[0])

		// 설정 값 추출 - config 패키지의 적절한 메서드 사용 필요
		renderMarkdown := false // 기본값
		cfgMap, ok := cfg.(map[string]interface{})
		if ok {
			if render, ok := cfgMap["render_markdown"].(bool); ok {
				renderMarkdown = render
			}
		}

		if renderMarkdown {
			messageEventContent = format.RenderMarkdown(messageText, true, true)
		} else {
			messageEventContent = event.MessageEventContent{MsgType: event.MsgText, Body: messageText}
		}

		// MatrixClient 인터페이스에 맞게 matrixClient를 래핑
		clientAdapter := matrix.NewMautrixClientAdapter(matrixClient)

		resp, err = matrix.SendMessage(ctx, clientAdapter, roomID, &messageEventContent, map[string]any{
			"com.beeper.chatwoot.message_id": mc.ID,
		})
		if err != nil {
			return err
		}

		// EventID에 대한 MessageID 매핑 저장
		cwMsgID := chatwootapi.MessageID(mc.ID)
		err = stateStore.StoreMatrixEventToChatwootMessage(ctx, accountID, roomID, resp.EventID, cwConvID, cwMsgID)
		if err != nil {
			log.Err(err).Msg("메시지 매핑 저장 실패")
			// 저장 실패해도 전송은 된 상태이므로 오류 무시
		}
	}

	// 첨부파일 처리는 별도 함수로 분리하여 구현할 수 있도록 준비
	for _, a := range message.Attachments {
		// 첨부파일 처리 기능 구현 전까지는 로그만 남김
		log.Info().
			Str("file_type", a.FileType).
			Int("file_size", a.FileSize).
			Str("data_url", a.DataURL).
			Msg("첨부파일 처리 필요")
	}

	return nil
}

// createNewChatRoom 새 채팅방을 생성하고 데이터베이스에 매핑 정보를 저장합니다
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
	defer resp.Body.Close()

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

// handleAttachment processes and sends attachments from Chatwoot to Matrix
func handleAttachment(ctx context.Context, roomID id.RoomID, chatwootMessageID chatwootapi.MessageID, chatwootAttachment chatwootapi.Attachment, accountID string, chatwootAPI *chatwootapi.Client, matrixClient *mautrix.Client, msgEventMap matrix.StateStore) (*mautrix.RespSendEvent, error) {
	log := zerolog.Ctx(ctx).With().
		Str("func", "handleAttachment").
		Int("attachment_id", int(chatwootAttachment.ID)).
		Str("attachment_file_type", chatwootAttachment.FileType).
		Logger()
	ctx = log.WithContext(ctx)

	// 첨부파일 다운로드
	attachmentData, err := util.DoRetryArr(ctx, fmt.Sprintf("Download attachment: %s", chatwootAttachment.DataURL), func(ctx context.Context) ([]byte, error) {
		return chatwootAPI.DownloadAttachment(ctx, chatwootAttachment.DataURL)
	})
	if err != nil {
		return nil, err
	}

	if len(attachmentData) != chatwootAttachment.FileSize {
		return nil, fmt.Errorf("downloaded attachment size (%d) does not match expected size (%d)", len(attachmentData), chatwootAttachment.FileSize)
	}

	// 파일 정보 구성
	mimeType := http.DetectContentType(attachmentData)
	log.Info().Str("mime_type", mimeType).Msg("downloaded attachment")
	info := &event.FileInfo{
		MimeType: mimeType,
		Size:     chatwootAttachment.FileSize,
	}

	// 이미지 크기 계산
	if strings.HasPrefix(mimeType, "image/") {
		img, _, err := image.Decode(bytes.NewReader(attachmentData))
		if err != nil {
			log.Warn().Err(err).Msg("failed to decode image")
		} else {
			bounds := img.Bounds()
			info.Width = bounds.Dx()
			info.Height = bounds.Dy()
		}
	}

	// 썸네일 처리
	if len(chatwootAttachment.ThumbURL) > 0 {
		// 썸네일 다운로드
		thumbnailData, err := util.DoRetryArr(ctx, fmt.Sprintf("Download attachment thumbnail: %s", chatwootAttachment.ThumbURL), func(ctx context.Context) ([]byte, error) {
			return chatwootAPI.DownloadAttachment(ctx, chatwootAttachment.ThumbURL)
		})
		if err != nil {
			return nil, err
		}

		// 썸네일 정보 계산
		thumbnailMimeType := http.DetectContentType(thumbnailData)
		info.ThumbnailInfo = &event.FileInfo{
			MimeType: thumbnailMimeType,
			Size:     len(thumbnailData),
		}

		thumbnailImage, _, err := image.Decode(bytes.NewReader(thumbnailData))
		if err != nil {
			log.Warn().Err(err).Msg("failed to decode image")
		} else {
			bounds := thumbnailImage.Bounds()
			info.ThumbnailInfo.Width = bounds.Dx()
			info.ThumbnailInfo.Height = bounds.Dy()
		}

		// 썸네일 암호화
		info.ThumbnailFile = &event.EncryptedFileInfo{
			EncryptedFile: *attachment.NewEncryptedFile(),
			URL:           "",
		}
		info.ThumbnailFile.EncryptInPlace(thumbnailData)

		// 썸네일 업로드
		uploadedThumbnail, err := util.DoRetry(ctx, "upload thumbnail to Matrix", func(ctx context.Context) (*mautrix.RespMediaUpload, error) {
			return matrixClient.UploadMedia(ctx, mautrix.ReqUploadMedia{
				ContentBytes:  thumbnailData,
				ContentLength: int64(len(thumbnailData)),
				ContentType:   "application/octet-stream",
			})
		})
		if err != nil {
			return nil, err
		}
		info.ThumbnailFile.URL = uploadedThumbnail.ContentURI.CUString()
	}

	// 파일 암호화
	file := &event.EncryptedFileInfo{
		EncryptedFile: *attachment.NewEncryptedFile(),
		URL:           "",
	}
	file.EncryptInPlace(attachmentData)

	// 파일명 추출
	filename := "unknown"
	parsed, err := url.Parse(chatwootAttachment.DataURL)
	if err == nil {
		pathParts := strings.Split(parsed.Path, "/")
		if len(pathParts) > 0 {
			filename = pathParts[len(pathParts)-1]
		}
	}

	// 첨부파일 업로드
	uploadedFile, err := util.DoRetry(ctx, "upload attachment to Matrix", func(ctx context.Context) (*mautrix.RespMediaUpload, error) {
		return matrixClient.UploadMedia(ctx, mautrix.ReqUploadMedia{
			ContentBytes:  attachmentData,
			ContentLength: int64(len(attachmentData)),
			ContentType:   "application/octet-stream",
		})
	})
	if err != nil {
		return nil, err
	}
	file.URL = uploadedFile.ContentURI.CUString()

	// Matrix 메시지 내용 구성
	msgType := event.MsgFile
	if strings.HasPrefix(mimeType, "image/") {
		msgType = event.MsgImage
	} else if strings.HasPrefix(mimeType, "video/") {
		msgType = event.MsgVideo
	} else if strings.HasPrefix(mimeType, "audio/") {
		msgType = event.MsgAudio
	}

	content := &event.MessageEventContent{
		MsgType: msgType,
		Body:    filename,
		Info:    info,
		File:    file,
	}

	// matrixClient를 matrix.MatrixClient 인터페이스로 변환
	matrixAdapter := matrix.NewMautrixClientAdapter(matrixClient)

	// 첨부파일 메시지 전송 및 ID 매핑 저장
	resp, err := matrix.SendMessage(ctx, matrixAdapter, roomID, content, map[string]any{
		"com.beeper.chatwoot.message_id": chatwootMessageID,
	})
	if err != nil {
		return nil, err
	}

	// accountID 타입 변환
	aID, err := strconv.Atoi(accountID)
	if err != nil {
		log.Error().Err(err).Str("account_id", accountID).Msg("accountID 숫자 변환 실패")
		return nil, fmt.Errorf("accountID 변환 오류: %w", err)
	}
	accountIDTyped := chatwootapi.AccountID(aID)
	// StateStore 인터페이스 사용
	conversationID := chatwootapi.ConversationID(0) // 대화 ID를 알 수 없는 경우
	err = msgEventMap.StoreMatrixEventToChatwootMessage(ctx, accountIDTyped, roomID, resp.EventID, conversationID, chatwootMessageID)
	if err != nil {
		log.Error().Err(err).Msg("메시지 매핑 저장 실패")
		// 저장 실패해도 전송은 된 상태이므로 오류 무시
	}
	return resp, nil
}

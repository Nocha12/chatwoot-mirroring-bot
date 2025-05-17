package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"
)

// GetChatwootMessageIDsForMatrixEventID는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID 목록을 반환합니다.
func (d *Database) GetChatwootMessageIDsForMatrixEventID(ctx context.Context, eventID id.EventID) ([]chatwootapi.MessageID, chatwootapi.AccountID, error) {
	rows, err := d.DB.QueryContext(ctx, `
        SELECT chatwoot_message_id, chatwoot_account_id
          FROM chatwoot_message_to_matrix_event
         WHERE matrix_event_id = $1`, eventID)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		if err := rows.Close(); err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("rows 닫기 실패")
		}
	}()

	var messageIDs []chatwootapi.MessageID
	var accountID int
	for rows.Next() {
		var messageID int
		if err := rows.Scan(&messageID, &accountID); err != nil {
			return nil, 0, err
		}
		messageIDs = append(messageIDs, chatwootapi.MessageID(messageID))
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(messageIDs) == 0 {
		return nil, 0, ErrNotFound
	}
	return messageIDs, chatwootapi.AccountID(accountID), nil
}

// GetMatrixEventIDsForChatwootMessage는 Chatwoot 메시지 ID에 대한 Matrix 이벤트 ID 목록을 반환합니다.
func (d *Database) GetMatrixEventIDsForChatwootMessage(ctx context.Context, accountID int, messageID chatwootapi.MessageID) ([]id.EventID, error) {
	rows, err := d.DB.QueryContext(ctx, `
        SELECT matrix_event_id
          FROM chatwoot_message_to_matrix_event
         WHERE chatwoot_account_id = $1 AND chatwoot_message_id = $2`, accountID, int(messageID))
	if err != nil {
		return nil, fmt.Errorf("matrix 이벤트 ID 조회 실패: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			zerolog.Ctx(ctx).Error().Err(err).Msg("rows 닫기 실패")
		}
	}()

	var eventIDs []id.EventID
	for rows.Next() {
		var eventID id.EventID
		if err := rows.Scan(&eventID); err != nil {
			return nil, fmt.Errorf("이벤트 ID 스캔 실패: %w", err)
		}
		eventIDs = append(eventIDs, eventID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("이벤트 ID 반복 중 오류: %w", err)
	}
	if len(eventIDs) == 0 {
		return nil, ErrNotFound
	}
	return eventIDs, nil
}

// StoreMatrixEventToChatwootMessage는 Matrix 이벤트와 Chatwoot 메시지 매핑을 저장합니다.
func (d *Database) StoreMatrixEventToChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, eventID id.EventID, messageID chatwootapi.MessageID) error {
	_, err := d.DB.ExecContext(ctx, `
        INSERT INTO chatwoot_message_to_matrix_event
            (chatwoot_account_id, matrix_event_id, chatwoot_message_id)
            VALUES ($1, $2, $3)
    `, int(accountID), eventID, int(messageID))
	if err != nil {
		return fmt.Errorf("이벤트-메시지 매핑 저장 실패: %w", err)
	}
	return nil
}

// DeleteMatrixEventForChatwootMessage는 Chatwoot 메시지 ID에 대한 Matrix 이벤트 매핑을 삭제합니다.
func (d *Database) DeleteMatrixEventForChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, messageID chatwootapi.MessageID) error {
	_, err := d.DB.ExecContext(ctx, `
        DELETE FROM chatwoot_message_to_matrix_event
         WHERE chatwoot_account_id = $1 AND chatwoot_message_id = $2
    `, int(accountID), int(messageID))
	if err != nil {
		return fmt.Errorf("이벤트-메시지 매핑 삭제 실패: %w", err)
	}
	return nil
}

// SetChatwootMessageIDForMatrixEvent는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID를 설정합니다.
func (d *Database) SetChatwootMessageIDForMatrixEvent(ctx context.Context, accountID int, eventID id.EventID, messageID chatwootapi.MessageID) error {
	_, err := d.DB.ExecContext(ctx, `
        INSERT INTO chatwoot_message_to_matrix_event
            (chatwoot_account_id, matrix_event_id, chatwoot_message_id)
            VALUES ($1, $2, $3)
        ON CONFLICT (chatwoot_account_id, matrix_event_id) DO UPDATE
            SET chatwoot_message_id = EXCLUDED.chatwoot_message_id
    `, accountID, eventID, messageID)
	return err
}

// GetChatwootMessageFromMatrixEvent는 Matrix 이벤트 ID로부터 Chatwoot 대화 및 메시지 ID를 조회합니다.
func (d *Database) GetChatwootMessageFromMatrixEvent(ctx context.Context, roomID id.RoomID, eventID id.EventID) (chatwootapi.ConversationID, chatwootapi.MessageID, error) {
	convID, _, err := d.GetChatwootConversationIDFromMatrixRoom(ctx, roomID)
	if err != nil {
		return 0, 0, fmt.Errorf("방 ID에서 대화 ID 조회 실패: %w", err)
	}
	row := d.DB.QueryRowContext(ctx, `
        SELECT chatwoot_message_id
          FROM chatwoot_message_to_matrix_event
         WHERE matrix_event_id = $1
         LIMIT 1`, eventID)
	var msgID chatwootapi.MessageID
	if err := row.Scan(&msgID); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("matrix 이벤트에 대한 chatwoot 메시지 ID 조회 실패: %w", err)
	}
	return convID, msgID, nil
}

// GetMatrixEventFromChatwootMessage는 Chatwoot 메시지 정보로부터 Matrix 방 및 이벤트 ID를 조회합니다.
func (d *Database) GetMatrixEventFromChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) (id.RoomID, id.EventID, error) {
	rowRoom, _, err := d.GetMatrixRoomFromChatwootConversation(ctx, conversationID, accountID)
	if err != nil {
		return "", "", fmt.Errorf("대화 ID에서 방 ID 조회 실패: %w", err)
	}
	row := d.DB.QueryRowContext(ctx, `
        SELECT matrix_event_id
          FROM chatwoot_message_to_matrix_event
         WHERE chatwoot_account_id = $1 AND chatwoot_message_id = $2
         LIMIT 1`, int(accountID), int(messageID))
	var evtID id.EventID
	if err := row.Scan(&evtID); err != nil {
		if err == sql.ErrNoRows {
			return rowRoom, "", ErrNotFound
		}
		return rowRoom, "", fmt.Errorf("chatwoot 메시지에 대한 matrix 이벤트 ID 조회 실패: %w", err)
	}
	return rowRoom, evtID, nil
}

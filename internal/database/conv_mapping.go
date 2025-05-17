package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
	"maunium.net/go/mautrix/id"
)

// GetChatwootConversationIDFromMatrixRoom은 Matrix 방 ID로부터 Chatwoot 대화 ID와 계정 ID를 찾습니다.
func (d *Database) GetChatwootConversationIDFromMatrixRoom(ctx context.Context, roomID id.RoomID) (chatwootapi.ConversationID, chatwootapi.AccountID, error) {
	row := d.DB.QueryRowContext(ctx, `
        SELECT chatwoot_conversation_id, chatwoot_account_id
          FROM chatwoot_conversation_to_matrix_room
         WHERE matrix_room_id = $1`, roomID)
	var convID, accID int
	if err := row.Scan(&convID, &accID); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("chatwoot 대화 ID 조회 실패: %w", err)
	}
	return chatwootapi.ConversationID(convID), chatwootapi.AccountID(accID), nil
}

// GetMatrixRoomFromChatwootConversation은 Chatwoot 대화 ID와 계정 ID로부터 Matrix 방 ID를 찾습니다.
func (d *Database) GetMatrixRoomFromChatwootConversation(ctx context.Context, conversationID chatwootapi.ConversationID, accountID chatwootapi.AccountID) (id.RoomID, chatwootapi.AccountID, error) {
	row := d.DB.QueryRowContext(ctx, `
        SELECT matrix_room_id, chatwoot_account_id
          FROM chatwoot_conversation_to_matrix_room
         WHERE chatwoot_conversation_id = $1 AND chatwoot_account_id = $2`,
		int(conversationID), int(accountID))
	var roomID id.RoomID
	var dbAccID int
	if err := row.Scan(&roomID, &dbAccID); err != nil {
		if err == sql.ErrNoRows {
			return "", 0, ErrNotFound
		}
		return "", 0, fmt.Errorf("matrix 방 ID 조회 실패: %w", err)
	}
	return roomID, chatwootapi.AccountID(dbAccID), nil
}

// StoreMatrixRoomForChatwootConversation은 Matrix 방과 Chatwoot 대화 매핑을 저장합니다.
func (d *Database) StoreMatrixRoomForChatwootConversation(ctx context.Context, roomID id.RoomID, conversationID chatwootapi.ConversationID, accountID chatwootapi.AccountID) error {
	_, err := d.DB.ExecContext(ctx, `
        INSERT INTO chatwoot_conversation_to_matrix_room
            (matrix_room_id, chatwoot_conversation_id, chatwoot_account_id, chatwoot_inbox_id)
            VALUES ($1, $2, $3, $4)
        ON CONFLICT (matrix_room_id) DO UPDATE
            SET chatwoot_conversation_id = EXCLUDED.chatwoot_conversation_id,
                chatwoot_account_id = EXCLUDED.chatwoot_account_id,
                chatwoot_inbox_id = EXCLUDED.chatwoot_inbox_id
    `, roomID, int(conversationID), int(accountID))
	return err
}

// DeleteMatrixRoomForChatwootConversation은 Chatwoot 대화 ID에 대한 Matrix 방 매핑을 삭제합니다.
func (d *Database) DeleteMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) error {
	_, err := d.DB.ExecContext(ctx, `
        DELETE FROM chatwoot_conversation_to_matrix_room
         WHERE chatwoot_account_id = $1 AND chatwoot_conversation_id = $2
    `, accountID, int(conversationID))
	return err
}

// UpdateConversationIDForRoom은 방 ID에 대한 대화 ID를 업데이트합니다.
func (d *Database) UpdateConversationIDForRoom(ctx context.Context, roomID id.RoomID, accountID int, inboxID int, conversationID chatwootapi.ConversationID) error {
	_, err := d.DB.ExecContext(ctx, `
        UPDATE chatwoot_conversation_to_matrix_room
           SET chatwoot_conversation_id = $2, chatwoot_account_id = $3, chatwoot_inbox_id = $4
         WHERE matrix_room_id = $1
    `, roomID, int(conversationID), accountID, inboxID)
	return err
}

// UpdateMostRecentEventIDForRoom은 방 ID에 대한 가장 최근 이벤트 ID를 업데이트합니다.
func (d *Database) UpdateMostRecentEventIDForRoom(ctx context.Context, roomID id.RoomID, mostRecentEventID id.EventID) error {
	_, err := d.DB.ExecContext(ctx, `
        UPDATE chatwoot_conversation_to_matrix_room
           SET most_recent_event_id = $2
         WHERE matrix_room_id = $1
    `, roomID, mostRecentEventID)
	return err
}

// GetAccountAndInboxIDForConversation은 Matrix 방 ID로부터 Chatwoot 계정 ID와 인박스 ID를 반환합니다.
func (d *Database) GetAccountAndInboxIDForConversation(ctx context.Context, roomID id.RoomID) (chatwootapi.AccountID, chatwootapi.InboxID, error) {
	row := d.DB.QueryRowContext(ctx, `
        SELECT chatwoot_account_id, chatwoot_inbox_id
          FROM chatwoot_conversation_to_matrix_room
         WHERE matrix_room_id = $1
    `, roomID)

	var accID, inboxID int
	if err := row.Scan(&accID, &inboxID); err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("계정 및 인박스 ID 조회 실패: %w", err)
	}

	return chatwootapi.AccountID(accID), chatwootapi.InboxID(inboxID), nil
}

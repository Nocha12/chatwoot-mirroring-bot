package queries

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/chatwootapi"
)

// GetChatwootConversationIDFromMatrixRoom은 Matrix 방 ID로부터 Chatwoot 대화 ID를 찾습니다.
func GetChatwootConversationIDFromMatrixRoom(ctx context.Context, db *sql.DB, roomID id.RoomID) (chatwootapi.ConversationID, int, error) {
	row := db.QueryRowContext(ctx, `
		SELECT chatwoot_conversation_id, chatwoot_account_id
		  FROM chatwoot_conversation_to_matrix_room
		 WHERE matrix_room_id = $1`, roomID)
	var chatwootConversationID chatwootapi.ConversationID
	var accountID int
	if err := row.Scan(&chatwootConversationID, &accountID); err != nil {
		return -1, -1, err
	}
	return chatwootConversationID, accountID, nil
}

// GetMatrixRoomFromChatwootConversation은 Chatwoot 대화 ID로부터 Matrix 방 ID를 찾습니다.
func GetMatrixRoomFromChatwootConversation(ctx context.Context, db *sql.DB, accountID int, conversationID chatwootapi.ConversationID) (id.RoomID, id.EventID, error) {
	row := db.QueryRowContext(ctx, `
		SELECT matrix_room_id, most_recent_event_id
		  FROM chatwoot_conversation_to_matrix_room
		 WHERE chatwoot_account_id = $1 AND chatwoot_conversation_id = $2`, accountID, conversationID)
	var roomID id.RoomID
	var mostRecentEventIDStr sql.NullString
	if err := row.Scan(&roomID, &mostRecentEventIDStr); err != nil {
		return "", "", err
	}
	if mostRecentEventIDStr.Valid {
		return roomID, id.EventID(mostRecentEventIDStr.String), nil
	} else {
		return roomID, id.EventID(""), nil
	}
}

// UpdateMostRecentEventIDForRoom은 Room에 대한 가장 최근 이벤트 ID를 업데이트합니다.
func UpdateMostRecentEventIDForRoom(ctx context.Context, db *sql.DB, roomID id.RoomID, mostRecentEventID id.EventID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "update_most_recent_event_id_for_room").
		Stringer("most_recent_event_id", mostRecentEventID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("setting most recent event ID for room")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	update := `
		UPDATE chatwoot_conversation_to_matrix_room
		SET most_recent_event_id = $2
		WHERE matrix_room_id = $1
	`
	if _, err := tx.ExecContext(ctx, update, roomID, mostRecentEventID); err != nil {
		return fmt.Errorf("failed to update most recent event ID: %w", err)
	}

	return tx.Commit()
}

// UpdateConversationIDForRoom은 Room에 대한 Chatwoot 대화 ID를 업데이트합니다.
func UpdateConversationIDForRoom(ctx context.Context, db *sql.DB, roomID id.RoomID, accountID int, inboxID int, conversationID chatwootapi.ConversationID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "update_conversation_id_for_room").
		Int("account_id", accountID).
		Int("inbox_id", inboxID).
		Int("conversation_id", int(conversationID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("setting conversation ID for room")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsert := `
		INSERT INTO chatwoot_conversation_to_matrix_room (matrix_room_id, chatwoot_account_id, chatwoot_inbox_id, chatwoot_conversation_id)
			VALUES ($1, $2, $3, $4)
		ON CONFLICT (matrix_room_id) DO UPDATE
			SET chatwoot_account_id = $2, chatwoot_inbox_id = $3, chatwoot_conversation_id = $4
	`
	_, err = tx.ExecContext(ctx, upsert, roomID, accountID, inboxID, conversationID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteMatrixRoomForChatwootConversation은 지정된 Chatwoot 대화 ID에 대한 Matrix 방 매핑을 데이터베이스에서 삭제합니다.
func DeleteMatrixRoomForChatwootConversation(ctx context.Context, db *sql.DB, accountID int, conversationID chatwootapi.ConversationID) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "delete_matrix_room_for_chatwoot_conversation").
		Int("account_id", accountID).
		Int("conversation_id", int(conversationID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Info().Msg("Chatwoot 대화에 대한 Matrix 방 매핑 삭제")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	delete := `
		DELETE FROM chatwoot_conversation_to_matrix_room
		WHERE chatwoot_account_id = $1 AND chatwoot_conversation_id = $2
	`
	result, err := tx.ExecContext(ctx, delete, accountID, conversationID)
	if err != nil {
		return fmt.Errorf("매핑 삭제 실패: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Warn().Err(err).Msg("영향 받은 행 수를 확인할 수 없습니다")
	} else if rowsAffected == 0 {
		log.Warn().Msg("삭제할 매핑이 없습니다")
	} else {
		log.Info().Int64("deleted_rows", rowsAffected).Msg("매핑이 성공적으로 삭제되었습니다")
	}

	return tx.Commit()
}

// StoreMatrixRoomForChatwootConversation은 Chatwoot 대화 ID와 Matrix 방 ID 간의 매핑을 저장합니다.
func StoreMatrixRoomForChatwootConversation(ctx context.Context, db *sql.DB, accountID int, inboxID int, conversationID chatwootapi.ConversationID, roomID id.RoomID, sender string) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "store_matrix_room_for_chatwoot_conversation").
		Int("account_id", accountID).
		Int("inbox_id", inboxID).
		Int("conversation_id", int(conversationID)).
		Stringer("room_id", roomID).
		Str("sender", sender).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 대화에 대한 Matrix 방 저장")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	upsert := `
		INSERT INTO chatwoot_conversation_to_matrix_room (chatwoot_account_id, chatwoot_inbox_id, chatwoot_conversation_id, matrix_room_id)
			VALUES ($1, $2, $3, $4)
		ON CONFLICT (chatwoot_account_id, chatwoot_conversation_id) DO UPDATE
			SET matrix_room_id = $4
	`
	_, err = tx.ExecContext(ctx, upsert, accountID, inboxID, conversationID, roomID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// 헬퍼 함수 - Database 구조체에서 호출
// GetChatwootConversationIDFromMatrixRoomHelper는 Matrix 방 ID로부터 Chatwoot 대화 ID를 찾는 헬퍼 함수입니다.
func GetChatwootConversationIDFromMatrixRoomHelper(ctx context.Context, db *sql.DB, roomID id.RoomID) (chatwootapi.ConversationID, int, error) {
	return GetChatwootConversationIDFromMatrixRoom(ctx, db, roomID)
}

// GetMatrixRoomFromChatwootConversationHelper는 Chatwoot 대화 ID로부터 Matrix 방 ID를 찾는 헬퍼 함수입니다.
func GetMatrixRoomFromChatwootConversationHelper(ctx context.Context, db *sql.DB, accountID int, conversationID chatwootapi.ConversationID) (id.RoomID, id.EventID, error) {
	return GetMatrixRoomFromChatwootConversation(ctx, db, accountID, conversationID)
}

// UpdateMostRecentEventIDForRoomHelper는 Room에 대한 가장 최근 이벤트 ID를 업데이트하는 헬퍼 함수입니다.
func UpdateMostRecentEventIDForRoomHelper(ctx context.Context, db *sql.DB, roomID id.RoomID, mostRecentEventID id.EventID) error {
	return UpdateMostRecentEventIDForRoom(ctx, db, roomID, mostRecentEventID)
}

// UpdateConversationIDForRoomHelper는 Room에 대한 Chatwoot 대화 ID를 업데이트하는 헬퍼 함수입니다.
func UpdateConversationIDForRoomHelper(ctx context.Context, db *sql.DB, roomID id.RoomID, accountID int, inboxID int, conversationID chatwootapi.ConversationID) error {
	return UpdateConversationIDForRoom(ctx, db, roomID, accountID, inboxID, conversationID)
}

// DeleteMatrixRoomForChatwootConversationHelper는 지정된 Chatwoot 대화 ID에 대한 Matrix 방 매핑을 삭제하는 헬퍼 함수입니다.
func DeleteMatrixRoomForChatwootConversationHelper(ctx context.Context, db *sql.DB, accountID int, conversationID chatwootapi.ConversationID) error {
	return DeleteMatrixRoomForChatwootConversation(ctx, db, accountID, conversationID)
}

// StoreMatrixRoomForChatwootConversationHelper는 Chatwoot 대화 ID와 Matrix 방 ID 간의 매핑을 저장하는 헬퍼 함수입니다.
func StoreMatrixRoomForChatwootConversationHelper(ctx context.Context, db *sql.DB, accountID int, inboxID int, conversationID chatwootapi.ConversationID, roomID id.RoomID, sender string) error {
	return StoreMatrixRoomForChatwootConversation(ctx, db, accountID, inboxID, conversationID, roomID, sender)
}

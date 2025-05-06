package queries

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// ErrNotFound는 레코드를 찾을 수 없을 때 반환되는 오류입니다.
var ErrNotFound = errors.New("레코드를 찾을 수 없습니다")

// SetChatwootMessageIDForMatrixEvent은 Matrix 이벤트에 대한 Chatwoot 메시지 ID를 설정합니다.
func SetChatwootMessageIDForMatrixEvent(ctx context.Context, db *sql.DB, accountID int, eventID id.EventID, chatwootMessageID chatwootapi.MessageID) error {
	log := zerolog.Ctx(ctx).With().
		Int("account_id", accountID).
		Stringer("event_id", eventID).
		Int("chatwoot_message_id", int(chatwootMessageID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("setting chatwoot message ID for matrix event")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insert := `
		INSERT INTO chatwoot_message_to_matrix_event (chatwoot_account_id, matrix_event_id, chatwoot_message_id)
			VALUES ($1, $2, $3)
	`
	_, err = tx.ExecContext(ctx, insert, accountID, eventID, chatwootMessageID)
	if err != nil {
		return fmt.Errorf("failed to insert chatwoot message ID for matrix event: %w", err)
	}
	return tx.Commit()
}

// GetMatrixEventIDsForChatwootMessage는 Chatwoot 메시지에 대한 Matrix 이벤트 ID 목록을 반환합니다.
func GetMatrixEventIDsForChatwootMessage(ctx context.Context, db *sql.DB, accountID int, chatwootMessageID chatwootapi.MessageID) []id.EventID {
	log := zerolog.Ctx(ctx).With().
		Int("account_id", accountID).
		Int("message_id", int(chatwootMessageID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("getting Matrix event IDs for chatwoot message")
	rows, err := db.QueryContext(ctx, `
		SELECT matrix_event_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_account_id = $1 AND chatwoot_message_id = $2`, accountID, chatwootMessageID)
	eventIDs := make([]id.EventID, 0)
	if err != nil {
		log.Err(err).Msg("failed to get Matrix event IDs for chatwoot message")
		return eventIDs
	}
	defer rows.Close()

	var eventID id.EventID
	for rows.Next() {
		if err := rows.Scan(&eventID); err == nil {
			eventIDs = append(eventIDs, eventID)
		}
	}
	return eventIDs
}

// GetChatwootMessageIDsForMatrixEventID는 주어진 Matrix 이벤트 ID에 대한 메시지 ID와 계정 ID 목록을 반환합니다.
func GetChatwootMessageIDsForMatrixEventID(ctx context.Context, db *sql.DB, matrixEventID id.EventID) (accountIDs []int, messageIDs []chatwootapi.MessageID, err error) {
	log := zerolog.Ctx(ctx)

	log.Debug().Msg("getting chatwoot message IDs for matrix event ID")
	rows, err := db.QueryContext(ctx, `
		SELECT chatwoot_account_id, chatwoot_message_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE matrix_event_id = $1`, matrixEventID)
	if err != nil {
		log.Err(err).Msg("failed to get chatwoot message IDs for matrix event ID")
		return nil, nil, err
	}
	defer rows.Close()

	var accountID int
	var messageID chatwootapi.MessageID
	for rows.Next() {
		if err := rows.Scan(&accountID, &messageID); err == nil {
			accountIDs = append(accountIDs, accountID)
			messageIDs = append(messageIDs, messageID)
		}
	}
	log.Debug().Any("account_ids", accountIDs).Any("message_ids", messageIDs).Msg("found chatwoot message IDs for matrix event ID")
	return accountIDs, messageIDs, rows.Err()
}

// GetChatwootMessageIDsForMatrixEventIDWithAccount는 특정 계정에 대한 Matrix 이벤트 ID의 메시지 ID 목록을 반환합니다.
func GetChatwootMessageIDsForMatrixEventIDWithAccount(ctx context.Context, db *sql.DB, accountID int, matrixEventID id.EventID) (messageIDs []chatwootapi.MessageID, err error) {
	log := zerolog.Ctx(ctx).With().Int("account_id", accountID).Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("getting chatwoot message IDs for matrix event ID with specific account")
	rows, err := db.QueryContext(ctx, `
		SELECT chatwoot_message_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_account_id = $1 AND matrix_event_id = $2`, accountID, matrixEventID)
	if err != nil {
		log.Err(err).Msg("failed to get chatwoot message IDs for matrix event ID with specific account")
		return nil, err
	}
	defer rows.Close()

	var messageID chatwootapi.MessageID
	for rows.Next() {
		if err := rows.Scan(&messageID); err == nil {
			messageIDs = append(messageIDs, messageID)
		}
	}
	log.Debug().Any("message_ids", messageIDs).Msg("found chatwoot message IDs for matrix event ID with specific account")
	return messageIDs, rows.Err()
}

// GetMatrixEventFromChatwootMessage는 Chatwoot 메시지 ID에 대한 Matrix 이벤트 ID를 반환합니다.
func GetMatrixEventFromChatwootMessage(ctx context.Context, db *sql.DB, accountID int, chatwootMessageID chatwootapi.MessageID) (id.EventID, error) {
	log := zerolog.Ctx(ctx).With().Int("account_id", accountID).Int("message_id", int(chatwootMessageID)).Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("getting matrix event ID for chatwoot message")
	row := db.QueryRowContext(ctx, `
		SELECT matrix_event_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_account_id = $1 AND chatwoot_message_id = $2
		 LIMIT 1`, accountID, chatwootMessageID)
	var eventID id.EventID
	if err := row.Scan(&eventID); err != nil {
		return "", err
	}
	return eventID, nil
}

// GetChatwootMessageFromMatrixEvent는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID와 계정 ID를 반환합니다.
func GetChatwootMessageFromMatrixEvent(ctx context.Context, db *sql.DB, eventID id.EventID) (chatwootapi.MessageID, int, error) {
	log := zerolog.Ctx(ctx).With().Stringer("event_id", eventID).Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("getting chatwoot message ID for matrix event")
	row := db.QueryRowContext(ctx, `
		SELECT chatwoot_message_id, chatwoot_account_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE matrix_event_id = $1
		 LIMIT 1`, eventID)
	var messageID chatwootapi.MessageID
	var accountID int
	if err := row.Scan(&messageID, &accountID); err != nil {
		return -1, -1, err
	}
	return messageID, accountID, nil
}

// StoreMatrixEventForChatwootMessage는 Chatwoot 메시지에 대한 Matrix 이벤트 ID를 저장합니다.
func StoreMatrixEventForChatwootMessage(ctx context.Context, db *sql.DB, accountID int, messageID chatwootapi.MessageID, eventID id.EventID) error {
	log := zerolog.Ctx(ctx).With().
		Int("account_id", accountID).
		Int("message_id", int(messageID)).
		Stringer("event_id", eventID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("storing matrix event for chatwoot message")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	insert := `
		INSERT INTO chatwoot_message_to_matrix_event (chatwoot_account_id, chatwoot_message_id, matrix_event_id)
			VALUES ($1, $2, $3)
	`
	_, err = tx.ExecContext(ctx, insert, accountID, messageID, eventID)
	if err != nil {
		return fmt.Errorf("failed to store matrix event for chatwoot message: %w", err)
	}
	return tx.Commit()
}

// DeleteMatrixEventForChatwootMessage는 Chatwoot 메시지에 대한 Matrix 이벤트 매핑을 삭제합니다.
func DeleteMatrixEventForChatwootMessage(ctx context.Context, db *sql.DB, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error {
	log := zerolog.Ctx(ctx).With().
		Int("account_id", int(accountID)).
		Int("conversation_id", int(conversationID)).
		Int("message_id", int(messageID)).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("Chatwoot 메시지에 대한 Matrix 이벤트 매핑 삭제 중")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	del := `
		DELETE FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_account_id = $1 AND chatwoot_conversation_id = $2 AND chatwoot_message_id = $3
	`
	_, err = tx.ExecContext(ctx, del, int(accountID), int(conversationID), int(messageID))
	if err != nil {
		return fmt.Errorf("failed to delete matrix events for chatwoot message: %w", err)
	}
	return tx.Commit()
}

// 헬퍼 함수 - Database 구조체에서 호출
// StoreMatrixEventForChatwootMessageHelper는 Chatwoot 메시지에 대한 Matrix 이벤트 ID를 저장하는 헬퍼 함수입니다.
func StoreMatrixEventForChatwootMessageHelper(ctx context.Context, db *sql.DB, accountID int, messageID chatwootapi.MessageID, eventID id.EventID) error {
	return StoreMatrixEventForChatwootMessage(ctx, db, accountID, messageID, eventID)
}

// GetMatrixEventFromChatwootMessageHelper는 Chatwoot 메시지 ID에 대한 Matrix 이벤트 ID를 반환하는 헬퍼 함수입니다.
func GetMatrixEventFromChatwootMessageHelper(ctx context.Context, db *sql.DB, accountID int, messageID chatwootapi.MessageID) (id.EventID, error) {
	return GetMatrixEventFromChatwootMessage(ctx, db, accountID, messageID)
}

// GetChatwootMessageFromMatrixEventHelper는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID와 계정 ID를 반환하는 헬퍼 함수입니다.
func GetChatwootMessageFromMatrixEventHelper(ctx context.Context, db *sql.DB, eventID id.EventID) (chatwootapi.MessageID, int, error) {
	return GetChatwootMessageFromMatrixEvent(ctx, db, eventID)
}

// DeleteMatrixEventForChatwootMessageHelper는 Chatwoot 메시지에 대한 Matrix 이벤트 매핑을 삭제하는 헬퍼 함수입니다.
func DeleteMatrixEventForChatwootMessageHelper(ctx context.Context, db *sql.DB, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error {
	return DeleteMatrixEventForChatwootMessage(ctx, db, accountID, conversationID, messageID)
}

// SetChatwootMessageIDForMatrixEventHelper는 Matrix 이벤트에 대한 Chatwoot 메시지 ID를 설정하는 헬퍼 함수입니다.
func SetChatwootMessageIDForMatrixEventHelper(ctx context.Context, db *sql.DB, accountID int, eventID id.EventID, chatwootMessageID chatwootapi.MessageID) error {
	return SetChatwootMessageIDForMatrixEvent(ctx, db, accountID, eventID, chatwootMessageID)
}

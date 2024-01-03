package database

import (
	"context"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

func (store *Database) SetChatwootMessageIDForMatrixEvent(ctx context.Context, eventID id.EventID, chatwootMessageID int) error {
	log := zerolog.Ctx(ctx).With().
		Stringer("event_id", eventID).
		Int("chatwoot_message_id", chatwootMessageID).
		Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("setting chatwoot message ID for matrix event")
	tx, err := store.DB.Begin()
	if err != nil {
		tx.Rollback()
		return err
	}

	insert := `
		INSERT INTO chatwoot_message_to_matrix_event (matrix_event_id, chatwoot_message_id)
			VALUES ($1, $2)
	`
	if _, err := tx.ExecContext(ctx, insert, eventID, chatwootMessageID); err != nil {
		log.Err(err).Msg("failed to set chatwoot message ID for matrix event")
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func (store *Database) GetMatrixEventIDsForChatwootMessage(ctx context.Context, chatwootMessageID int) []id.EventID {
	log := zerolog.Ctx(ctx).With().Int("message_id", chatwootMessageID).Logger()
	ctx = log.WithContext(ctx)

	log.Debug().Msg("getting Matrix event IDs for chatwoot message")
	rows, err := store.DB.QueryContext(ctx, `
		SELECT matrix_event_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_message_id = $1`, chatwootMessageID)
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

func (store *Database) GetChatwootMessageIDsForMatrixEventID(ctx context.Context, matrixEventID id.EventID) (messageIDs []int, err error) {
	log := zerolog.Ctx(ctx)

	log.Debug().Msg("getting chatwoot message IDs for matrix event ID")
	var rows dbutil.Rows
	rows, err = store.DB.QueryContext(ctx, `
		SELECT chatwoot_message_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE matrix_event_id = $1`, matrixEventID)
	if err != nil {
		log.Err(err).Msg("failed to get chatwoot message IDs for matrix event ID")
		return
	}
	defer rows.Close()

	var messageID int
	for rows.Next() {
		if err := rows.Scan(&messageID); err == nil {
			messageIDs = append(messageIDs, messageID)
		}
	}
	log.Debug().Interface("message_ids", messageIDs).Msg("found chatwoot message IDs for matrix event ID")
	return messageIDs, rows.Err()
}

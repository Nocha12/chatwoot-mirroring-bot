package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"

	"github.com/Nocha12/chatwoot-mirroring-bot/pkg/chatwootapi"
)

// ErrNotFound는 레코드를 찾을 수 없을 때 반환되는 오류입니다.
var ErrNotFound = errors.New("레코드를 찾을 수 없습니다")

//go:embed schema/*.sql
var rawUpgrades embed.FS

var upgradeTable dbutil.UpgradeTable

func init() {
	upgradeTable.RegisterFS(rawUpgrades)
}

// Store는 데이터베이스 작업을 위한 인터페이스입니다.
type Store interface {
	// matrix.StateStore와 호환되는 메서드
	GetChatwootConversationIDFromMatrixRoom(ctx context.Context, roomID id.RoomID) (chatwootapi.ConversationID, chatwootapi.AccountID, error)
	GetMatrixRoomFromChatwootConversation(ctx context.Context, conversationID chatwootapi.ConversationID, accountID string) (id.RoomID, string, error)
	StoreMatrixRoomForChatwootConversation(ctx context.Context, roomID id.RoomID, conversationID chatwootapi.ConversationID, accountID string) error
	GetAccountAndInboxIDForConversation(ctx context.Context, roomID id.RoomID) (chatwootapi.AccountID, chatwootapi.InboxID, error)
	GetChatwootMessageIDsForMatrixEventID(ctx context.Context, eventID id.EventID) ([]chatwootapi.MessageID, int, error)
	StoreMatrixEventToChatwootMessage(ctx context.Context, accountID int, roomID id.RoomID, eventID id.EventID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error
	DeleteMatrixEventForChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error

	// 추가 데이터베이스 작업 메서드
	UpdateMostRecentEventIDForRoom(ctx context.Context, roomID id.RoomID, mostRecentEventID id.EventID) error
	UpdateConversationIDForRoom(ctx context.Context, roomID id.RoomID, accountID int, inboxID int, conversationID chatwootapi.ConversationID) error
	DeleteMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) error
	GetMatrixEventIDsForChatwootMessage(ctx context.Context, accountID int, messageID chatwootapi.MessageID) ([]id.EventID, error)
	SetChatwootMessageIDForMatrixEvent(ctx context.Context, accountID int, eventID id.EventID, messageID chatwootapi.MessageID) error

	// 데이터베이스 연결 및 관리 메서드
	Connect(dbType, uri string) error
	Init(ctx context.Context) error
	Upgrade(ctx context.Context) error
	Close() error
}

// Database는 Store 인터페이스를 구현하는 구조체입니다.
type Database struct {
	// DB는 데이터베이스 연결을 관리하는 객체입니다.
	DB     *sql.DB
	dbType string
	uri    string
}

// NewDatabase는 새로운 Database 인스턴스를 생성합니다.
func NewDatabase() *Database {
	return &Database{}
}

// Connect는 데이터베이스에 연결합니다.
func (d *Database) Connect(dbType, uri string) error {
	log.Info().Str("db_type", dbType).Str("uri", uri).Msg("데이터베이스에 연결합니다")

	d.dbType = dbType
	d.uri = uri

	db, err := sql.Open(dbType, uri)
	if err != nil {
		return fmt.Errorf("데이터베이스 연결 실패: %w", err)
	}

	d.DB = db
	return nil
}

// Init은 데이터베이스를 초기화합니다.
func (d *Database) Init(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("데이터베이스를 초기화합니다")

	// 필요한 테이블 및 초기 데이터 설정
	_, err := d.DB.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS chatwoot_version (
version INTEGER PRIMARY KEY
)
	`)
	if err != nil {
		log.Error().Err(err).Msg("버전 테이블 생성 실패")
		return fmt.Errorf("버전 테이블 생성 실패: %w", err)
	}

	return nil
}

// Upgrade는 데이터베이스 스키마를 업그레이드합니다.
func (d *Database) Upgrade(ctx context.Context) error {
	log := zerolog.Ctx(ctx)
	log.Info().Msg("데이터베이스 스키마를 업그레이드합니다")

	// SQL 스크립트로 업그레이드 실행
	// 이 함수는 schema/ 디렉터리의 SQL 파일을 순서대로 실행합니다.
	schemaDir, err := rawUpgrades.ReadDir("schema")
	if err != nil {
		log.Error().Err(err).Msg("스키마 디렉터리 읽기 실패")
		return fmt.Errorf("스키마 디렉터리 읽기 실패: %w", err)
	}

	for _, entry := range schemaDir {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sql" {
			log.Info().Str("file", entry.Name()).Msg("스키마 파일 실행")

			filePath := filepath.Join("schema", entry.Name())
			content, err := rawUpgrades.ReadFile(filePath)
			if err != nil {
				log.Error().Err(err).Str("file", entry.Name()).Msg("스키마 파일 읽기 실패")
				return fmt.Errorf("스키마 파일 읽기 실패 (%s): %w", entry.Name(), err)
			}

			_, err = d.DB.ExecContext(ctx, string(content))
			if err != nil {
				log.Error().Err(err).Str("file", entry.Name()).Msg("스키마 파일 실행 실패")
				return fmt.Errorf("스키마 파일 실행 실패 (%s): %w", entry.Name(), err)
			}
		}
	}

	return nil
}

// Close는 데이터베이스 연결을 닫습니다.
func (d *Database) Close() error {
	if d.DB != nil {
		return d.DB.Close()
	}
	return nil
}

// GetChatwootConversationIDFromMatrixRoom은 Matrix 방 ID로부터 Chatwoot 대화 ID와 계정 ID를 찾습니다.
func (d *Database) GetChatwootConversationIDFromMatrixRoom(ctx context.Context, roomID id.RoomID) (chatwootapi.ConversationID, chatwootapi.AccountID, error) {
	row := d.DB.QueryRowContext(ctx, `
		SELECT chatwoot_conversation_id, chatwoot_account_id
		  FROM chatwoot_conversation_to_matrix_room
		 WHERE matrix_room_id = $1`, roomID)

	var chatwootConversationID int
	var accountID int
	err := row.Scan(&chatwootConversationID, &accountID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("Chatwoot 대화 ID 조회 실패: %w", err)
	}

	return chatwootapi.ConversationID(chatwootConversationID), chatwootapi.AccountID(accountID), nil
}

// GetMatrixRoomFromChatwootConversation은 Chatwoot 대화 ID와 계정 ID로부터 Matrix 방 ID를 찾습니다.
func (d *Database) GetMatrixRoomFromChatwootConversation(ctx context.Context, conversationID chatwootapi.ConversationID, accountID string) (id.RoomID, string, error) {
	accID, err := strconv.Atoi(accountID)
	if err != nil {
		return "", "", fmt.Errorf("계정 ID 변환 실패: %w", err)
	}

	row := d.DB.QueryRowContext(ctx, `
		SELECT matrix_room_id, chatwoot_message_id
		  FROM chatwoot_conversation_to_matrix_room
		 WHERE chatwoot_conversation_id = $1 AND chatwoot_account_id = $2`,
		int(conversationID), accID)

	var roomID id.RoomID
	var mostRecentMessageID string
	err = row.Scan(&roomID, &mostRecentMessageID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrNotFound
		}
		return "", "", fmt.Errorf("Matrix 방 ID 조회 실패: %w", err)
	}

	return roomID, mostRecentMessageID, nil
}

// StoreMatrixRoomForChatwootConversation은 Matrix 방과 Chatwoot 대화 매핑을 저장합니다.
func (d *Database) StoreMatrixRoomForChatwootConversation(ctx context.Context, roomID id.RoomID, conversationID chatwootapi.ConversationID, accountID string) error {
	accID, err := strconv.Atoi(accountID)
	if err != nil {
		return fmt.Errorf("계정 ID 변환 실패: %w", err)
	}

	_, err = d.DB.ExecContext(ctx, `
		INSERT INTO chatwoot_conversation_to_matrix_room
		(matrix_room_id, chatwoot_conversation_id, chatwoot_account_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (chatwoot_conversation_id, chatwoot_account_id) DO UPDATE
		SET matrix_room_id = $1`, roomID, int(conversationID), accID)

	if err != nil {
		return fmt.Errorf("대화-방 매핑 저장 실패: %w", err)
	}
	return nil
}

// GetAccountAndInboxIDForConversation은 방 ID로부터 계정 ID와 인박스 ID를 찾습니다.
func (d *Database) GetAccountAndInboxIDForConversation(ctx context.Context, roomID id.RoomID) (chatwootapi.AccountID, chatwootapi.InboxID, error) {
	row := d.DB.QueryRowContext(ctx, `
		SELECT chatwoot_account_id, chatwoot_inbox_id
		  FROM chatwoot_conversation_to_matrix_room
		 WHERE matrix_room_id = $1`, roomID)

	var accountID, inboxID int
	err := row.Scan(&accountID, &inboxID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, 0, ErrNotFound
		}
		return 0, 0, fmt.Errorf("계정/인박스 ID 조회 실패: %w", err)
	}

	return chatwootapi.AccountID(accountID), chatwootapi.InboxID(inboxID), nil
}

// GetChatwootMessageIDsForMatrixEventID는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID와 계정 ID를 반환합니다.
func (d *Database) GetChatwootMessageIDsForMatrixEventID(ctx context.Context, eventID id.EventID) ([]chatwootapi.MessageID, int, error) {
	rows, err := d.DB.QueryContext(ctx, `
		SELECT chatwoot_message_id, chatwoot_account_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE matrix_event_id = $1`, eventID)
	if err != nil {
		return nil, 0, fmt.Errorf("Chatwoot 메시지 ID 조회 실패: %w", err)
	}
	defer rows.Close()

	var messageIDs []chatwootapi.MessageID
	var accountID int

	for rows.Next() {
		var messageID int
		err = rows.Scan(&messageID, &accountID)
		if err != nil {
			return nil, 0, fmt.Errorf("메시지 ID 스캔 실패: %w", err)
		}
		messageIDs = append(messageIDs, chatwootapi.MessageID(messageID))
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("메시지 ID 반복 중 오류: %w", err)
	}

	if len(messageIDs) == 0 {
		return nil, 0, ErrNotFound
	}

	return messageIDs, accountID, nil
}

// StoreMatrixEventToChatwootMessage는 Matrix 이벤트와 Chatwoot 메시지 매핑을 저장합니다.
func (d *Database) StoreMatrixEventToChatwootMessage(ctx context.Context, accountID int, roomID id.RoomID, eventID id.EventID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error {
	_, err := d.DB.ExecContext(ctx, `
		INSERT INTO chatwoot_message_to_matrix_event
		(chatwoot_account_id, matrix_room_id, matrix_event_id, chatwoot_conversation_id, chatwoot_message_id)
		VALUES ($1, $2, $3, $4, $5)`,
		accountID, roomID, eventID, int(conversationID), int(messageID))

	if err != nil {
		return fmt.Errorf("이벤트-메시지 매핑 저장 실패: %w", err)
	}
	return nil
}

// GetMatrixEventIDsForChatwootMessage는 Chatwoot 메시지 ID에 대한 Matrix 이벤트 ID 목록을 반환합니다.
func (d *Database) GetMatrixEventIDsForChatwootMessage(ctx context.Context, accountID int, messageID chatwootapi.MessageID) ([]id.EventID, error) {
	rows, err := d.DB.QueryContext(ctx, `
		SELECT matrix_event_id
		  FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_account_id = $1 AND chatwoot_message_id = $2`,
		accountID, int(messageID))
	if err != nil {
		return nil, fmt.Errorf("Matrix 이벤트 ID 조회 실패: %w", err)
	}
	defer rows.Close()

	var eventIDs []id.EventID
	for rows.Next() {
		var eventID id.EventID
		err = rows.Scan(&eventID)
		if err != nil {
			return nil, fmt.Errorf("이벤트 ID 스캔 실패: %w", err)
		}
		eventIDs = append(eventIDs, eventID)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("이벤트 ID 반복 중 오류: %w", err)
	}

	if len(eventIDs) == 0 {
		return nil, ErrNotFound
	}

	return eventIDs, nil
}

// UpdateMostRecentEventIDForRoom은 방 ID에 대한 가장 최근 이벤트 ID를 업데이트합니다.
func (d *Database) UpdateMostRecentEventIDForRoom(ctx context.Context, roomID id.RoomID, mostRecentEventID id.EventID) error {
	_, err := d.DB.ExecContext(ctx, `
		UPDATE chatwoot_conversation_to_matrix_room
		   SET chatwoot_message_id = $2
		 WHERE matrix_room_id = $1`,
		roomID, mostRecentEventID)

	if err != nil {
		return fmt.Errorf("가장 최근 이벤트 ID 업데이트 실패: %w", err)
	}
	return nil
}

// UpdateConversationIDForRoom은 방 ID에 대한 대화 ID를 업데이트합니다.
func (d *Database) UpdateConversationIDForRoom(ctx context.Context, roomID id.RoomID, accountID int, inboxID int, conversationID chatwootapi.ConversationID) error {
	_, err := d.DB.ExecContext(ctx, `
		UPDATE chatwoot_conversation_to_matrix_room
		   SET chatwoot_conversation_id = $2, chatwoot_account_id = $3, chatwoot_inbox_id = $4
		 WHERE matrix_room_id = $1`,
		roomID, int(conversationID), accountID, inboxID)

	if err != nil {
		return fmt.Errorf("대화 ID 업데이트 실패: %w", err)
	}
	return nil
}

// DeleteMatrixRoomForChatwootConversation은 Chatwoot 대화 ID에 대한 Matrix 방 매핑을 삭제합니다.
func (d *Database) DeleteMatrixRoomForChatwootConversation(ctx context.Context, accountID int, conversationID chatwootapi.ConversationID) error {
	_, err := d.DB.ExecContext(ctx, `
		DELETE FROM chatwoot_conversation_to_matrix_room
		 WHERE chatwoot_account_id = $1 AND chatwoot_conversation_id = $2`,
		accountID, int(conversationID))

	if err != nil {
		return fmt.Errorf("방-대화 매핑 삭제 실패: %w", err)
	}
	return nil
}

// DeleteMatrixEventForChatwootMessage는 Chatwoot 메시지 ID에 대한 Matrix 이벤트 매핑을 삭제합니다.
func (d *Database) DeleteMatrixEventForChatwootMessage(ctx context.Context, accountID chatwootapi.AccountID, conversationID chatwootapi.ConversationID, messageID chatwootapi.MessageID) error {
	_, err := d.DB.ExecContext(ctx, `
		DELETE FROM chatwoot_message_to_matrix_event
		 WHERE chatwoot_account_id = $1 AND chatwoot_conversation_id = $2 AND chatwoot_message_id = $3`,
		int(accountID), int(conversationID), int(messageID))

	if err != nil {
		return fmt.Errorf("이벤트-메시지 매핑 삭제 실패: %w", err)
	}
	return nil
}

// SetChatwootMessageIDForMatrixEvent는 Matrix 이벤트 ID에 대한 Chatwoot 메시지 ID를 설정합니다.
func (d *Database) SetChatwootMessageIDForMatrixEvent(ctx context.Context, accountID int, eventID id.EventID, messageID chatwootapi.MessageID) error {
	_, err := d.DB.ExecContext(ctx, `
		UPDATE chatwoot_message_to_matrix_event
		   SET chatwoot_message_id = $3
		 WHERE chatwoot_account_id = $1 AND matrix_event_id = $2`,
		accountID, eventID, int(messageID))

	if err != nil {
		return fmt.Errorf("메시지 ID 설정 실패: %w", err)
	}
	return nil
}

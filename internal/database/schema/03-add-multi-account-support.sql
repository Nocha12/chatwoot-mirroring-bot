-- v3: Add multi-account support

-- Add columns to chatwoot_conversation_to_matrix_room
ALTER TABLE chatwoot_conversation_to_matrix_room ADD COLUMN chatwoot_account_id INTEGER;
ALTER TABLE chatwoot_conversation_to_matrix_room ADD COLUMN chatwoot_inbox_id INTEGER;

-- Add column to chatwoot_message_to_matrix_event
ALTER TABLE chatwoot_message_to_matrix_event ADD COLUMN chatwoot_account_id INTEGER;

-- !! 중요 !!
-- 여기에서 기존 데이터를 업데이트해야 합니다.
-- 아래 값들은 마이그레이션 *이전*의 config.yaml에 설정되어 있던 값으로 직접 바꿔야 합니다.
-- 예시: 기존 account_id가 3이고 inbox_id가 2였다면:
UPDATE chatwoot_conversation_to_matrix_room SET chatwoot_account_id = 3, chatwoot_inbox_id = 2;
UPDATE chatwoot_message_to_matrix_event SET chatwoot_account_id = 3;
-- 만약 기존 데이터가 없다면 이 UPDATE 문은 실행되지 않아도 됩니다.

-- Add NOT NULL constraints after updating existing data
ALTER TABLE chatwoot_conversation_to_matrix_room ALTER COLUMN chatwoot_account_id SET NOT NULL;
-- inbox_id는 필수 정보가 아닐 수 있으므로 NOT NULL을 걸지 않거나, 필요시 설정합니다.
-- ALTER TABLE chatwoot_conversation_to_matrix_room ALTER COLUMN chatwoot_inbox_id SET NOT NULL;
ALTER TABLE chatwoot_message_to_matrix_event ALTER COLUMN chatwoot_account_id SET NOT NULL;

-- Update constraints for chatwoot_conversation_to_matrix_room
-- 먼저 기존 제약 조건 삭제 (제약 조건 이름은 시스템마다 다를 수 있으므로 확인 필요)
-- 예: PostgreSQL에서 이름 확인: SELECT conname FROM pg_constraint WHERE conrelid = 'chatwoot_conversation_to_matrix_room'::regclass;
-- 아래는 일반적인 이름 예시입니다. 실제 이름으로 변경해야 합니다.
ALTER TABLE chatwoot_conversation_to_matrix_room DROP CONSTRAINT IF EXISTS chatwoot_conversation_to_matrix_room_pkey;
ALTER TABLE chatwoot_conversation_to_matrix_room DROP CONSTRAINT IF EXISTS chatwoot_conversation_to_matrix_room_chatwoot_conversation_id_key;
ALTER TABLE chatwoot_conversation_to_matrix_room DROP CONSTRAINT IF EXISTS chatwoot_conversation_to_matrix_room_matrix_room_id_key; -- matrix_room_id UNIQUE 제약조건이 있었다면

-- 새로운 제약 조건 추가
ALTER TABLE chatwoot_conversation_to_matrix_room ADD PRIMARY KEY (matrix_room_id); -- matrix_room_id가 고유하다고 가정
ALTER TABLE chatwoot_conversation_to_matrix_room ADD CONSTRAINT unique_chatwoot_conversation_per_account UNIQUE (chatwoot_account_id, chatwoot_conversation_id);

-- Update constraints for chatwoot_message_to_matrix_event
-- 기존 기본 키 제약 조건 삭제
ALTER TABLE chatwoot_message_to_matrix_event DROP CONSTRAINT IF EXISTS chatwoot_message_to_matrix_event_pkey;

-- 새로운 기본 키 제약 조건 추가
ALTER TABLE chatwoot_message_to_matrix_event ADD PRIMARY KEY (chatwoot_account_id, chatwoot_message_id, matrix_event_id);

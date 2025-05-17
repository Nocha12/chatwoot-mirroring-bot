-- v2: Migrate to mautrix crypto store

-- 1) membership 타입이 이미 있으면 EXCEPTION으로 잡아 무시
DO $$
	BEGIN
		CREATE TYPE membership AS ENUM (
			'join','leave','invite','ban','knock'
			);
	EXCEPTION
		WHEN duplicate_object THEN
			-- 이미 존재하면 아무 작업도 하지 않음
			NULL;
	END
$$ LANGUAGE plpgsql;

-- 2. 기본 테이블 생성
CREATE TABLE IF NOT EXISTS mx_registrations (
												user_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS mx_user_profile (
											   room_id     TEXT,
											   user_id     TEXT,
											   membership  membership NOT NULL,
											   displayname TEXT NOT NULL DEFAULT '',
											   avatar_url  TEXT NOT NULL DEFAULT '',
											   PRIMARY KEY (room_id, user_id)
);

CREATE TABLE IF NOT EXISTS mx_room_state (
											 room_id      TEXT PRIMARY KEY,
											 power_levels jsonb,
											 encryption   jsonb
);

CREATE TABLE IF NOT EXISTS mx_version (
										  version INTEGER PRIMARY KEY
);

-- 3. 버전 정보 삽입 (충돌 무시)
INSERT INTO mx_version (version) VALUES (4)
ON CONFLICT DO NOTHING;

-- 4. 기존 데이터 마이그레이션
DROP TABLE IF EXISTS user_filter_ids;

CREATE TABLE IF NOT EXISTS crypto_account (
											  account_id TEXT PRIMARY KEY,
											  device_id  TEXT NOT NULL,
											  shared     BOOLEAN NOT NULL,
											  sync_token TEXT NOT NULL,
											  account    bytea NOT NULL
);

-- 4.1. sync_token 업데이트 (서브쿼리 FROM 절 활용)
UPDATE crypto_account AS ca
SET sync_token = ubt.next_batch_token
FROM (
		 SELECT next_batch_token FROM user_batch_tokens
	 ) AS ubt;

DROP TABLE IF EXISTS user_batch_tokens;

-- 4.2. 방 상태 및 프로필 데이터 삽입
INSERT INTO mx_room_state (room_id, encryption)
SELECT room_id, encryption_event::jsonb FROM rooms
ON CONFLICT (room_id) DO UPDATE
	SET encryption = EXCLUDED.encryption;

INSERT INTO mx_user_profile (room_id, user_id, membership)
SELECT room_id, user_id, 'join' FROM room_members
ON CONFLICT (room_id, user_id) DO NOTHING;

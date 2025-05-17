-- 버전 4 (부분 1): 계정 설정을 위한 테이블 생성

BEGIN;

-- 테이블: bot_chatwoot_configs
-- 설명: 봇이 연결할 다양한 Chatwoot 인스턴스 및 계정/인박스 설정을 저장합니다.
CREATE TABLE IF NOT EXISTS public.bot_chatwoot_configs (
   id SERIAL PRIMARY KEY,                          -- 각 설정의 고유 ID (봇 내부 식별용)
   config_name TEXT UNIQUE NOT NULL,               -- 이 설정에 대한 사람이 읽기 쉬운 고유 이름 (예: "고객지원팀_A팀_인박스")
   base_url TEXT NOT NULL,                         -- Chatwoot 인스턴스의 기본 URL
   chatwoot_native_account_id INTEGER NOT NULL,    -- Chatwoot 시스템 내에 등록된 실제 계정 ID
   inbox_id INTEGER NOT NULL,                      -- Chatwoot 인박스 ID
   encrypted_access_token BYTEA NOT NULL,          -- 암호화된 Chatwoot API 접근 토큰
   encryption_nonce BYTEA NOT NULL,                -- 접근 토큰 암호화 시 사용된 Nonce 값
   is_enabled BOOLEAN NOT NULL DEFAULT TRUE,       -- 이 설정의 활성화 여부 (봇이 사용할지 여부)
   notes TEXT,                                     -- 이 설정에 대한 추가적인 설명 (선택 사항)
   created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- 생성 시각
   updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP  -- 마지막 수정 시각
);

COMMENT ON TABLE public.bot_chatwoot_configs IS '봇이 다양한 Chatwoot 계정/인박스에 연결하기 위한 설정을 저장하는 테이블입니다.';
COMMENT ON COLUMN public.bot_chatwoot_configs.id IS 'Chatwoot 설정 항목의 기본 키(PK)입니다.';
COMMENT ON COLUMN public.bot_chatwoot_configs.config_name IS '이 Chatwoot 설정을 식별하기 위한 고유하고 사람이 읽을 수 있는 이름입니다.';
COMMENT ON COLUMN public.bot_chatwoot_configs.chatwoot_native_account_id IS 'Chatwoot 시스템 자체에 등록된 계정의 ID입니다.';
COMMENT ON COLUMN public.bot_chatwoot_configs.encrypted_access_token IS 'Chatwoot API 접근 토큰으로, 저장 전에 애플리케이션 레벨에서 암호화됩니다.';
COMMENT ON COLUMN public.bot_chatwoot_configs.encryption_nonce IS 'encrypted_access_token 필드를 암호화할 때 사용된 Nonce 값입니다. 복호화 시 필수적입니다.';
COMMENT ON COLUMN public.bot_chatwoot_configs.is_enabled IS '봇이 이 Chatwoot 설정을 사용할지 여부를 나타내는 플래그입니다.';


-- 테이블: bot_matrix_identities
-- 설명: 봇이 사용할 수 있는 다양한 Matrix 사용자 ID(페르소나) 및 관련 인증 설정을 저장합니다.
CREATE TABLE IF NOT EXISTS public.bot_matrix_identities (
	id SERIAL PRIMARY KEY,                          -- 각 Matrix ID 설정의 고유 ID (봇 내부 식별용)
	config_name TEXT UNIQUE NOT NULL,               -- 이 설정에 대한 사람이 읽기 쉬운 고유 이름 (예: "헬프데스크_봇_Matrix계정")
	homeserver_url TEXT NOT NULL,                   -- Matrix 홈서버 URL
	user_id TEXT NOT NULL UNIQUE,                   -- Matrix 사용자 ID (예: @bot1:example.com)
	encrypted_password BYTEA,                       -- 암호화된 Matrix 계정 비밀번호 (비밀번호 인증 방식 사용 시)
	password_encryption_nonce BYTEA,                -- 비밀번호 암호화 시 사용된 Nonce 값
	encrypted_access_token BYTEA,                   -- 암호화된 Matrix 접근 토큰 (접근 토큰 인증 방식 사용 시)
	access_token_encryption_nonce BYTEA,            -- 접근 토큰 암호화 시 사용된 Nonce 값
	device_id TEXT,                                 -- 이 Matrix ID가 사용하는 Matrix 디바이스 ID (첫 로그인 후 채워지거나 미리 설정 가능)
	is_enabled BOOLEAN NOT NULL DEFAULT TRUE,       -- 이 Matrix ID 설정의 활성화 여부 (봇이 사용할지 여부)
	notes TEXT,                                     -- 이 설정에 대한 추가적인 설명 (선택 사항)
	created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- 생성 시각
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP  -- 마지막 수정 시각
);

COMMENT ON TABLE public.bot_matrix_identities IS '봇 애플리케이션이 사용할 수 있는 다양한 Matrix ID(봇 사용자)의 설정을 저장하는 테이블입니다.';
COMMENT ON COLUMN public.bot_matrix_identities.id IS 'Matrix ID 설정 항목의 기본 키(PK)입니다.';
COMMENT ON COLUMN public.bot_matrix_identities.config_name IS '이 Matrix ID 설정을 식별하기 위한 고유하고 사람이 읽을 수 있는 이름입니다.';
COMMENT ON COLUMN public.bot_matrix_identities.user_id IS 'Matrix 사용자 ID입니다 (예: @bot_user:homeserver.tld).';
COMMENT ON COLUMN public.bot_matrix_identities.encrypted_password IS 'Matrix 계정 비밀번호로, 저장 전에 애플리케이션 레벨에서 암호화됩니다. 접근 토큰 인증 사용 시 NULL일 수 있습니다.';
COMMENT ON COLUMN public.bot_matrix_identities.password_encryption_nonce IS 'encrypted_password 필드를 암호화할 때 사용된 Nonce 값입니다. 비밀번호가 설정되지 않으면 NULL입니다.';
COMMENT ON COLUMN public.bot_matrix_identities.encrypted_access_token IS 'Matrix 접근 토큰으로, 저장 전에 애플리케이션 레벨에서 암호화됩니다. 비밀번호 인증 사용 시 NULL일 수 있습니다.';
COMMENT ON COLUMN public.bot_matrix_identities.access_token_encryption_nonce IS 'encrypted_access_token 필드를 암호화할 때 사용된 Nonce 값입니다. 접근 토큰이 설정되지 않으면 NULL입니다.';
COMMENT ON COLUMN public.bot_matrix_identities.is_enabled IS '봇이 이 Matrix ID를 사용할지 여부를 나타내는 플래그입니다.';

COMMIT;

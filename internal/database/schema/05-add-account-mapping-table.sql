-- 버전 5: Chatwoot 계정과 Matrix ID 간의 매핑 테이블 추가

BEGIN;

-- 테이블: bot_account_mapping
-- 설명: Chatwoot 계정 설정과 Matrix ID 간의 매핑을 저장하는 테이블입니다.
CREATE TABLE IF NOT EXISTS public.bot_account_mapping (
    id SERIAL PRIMARY KEY,                          -- 각 매핑의 고유 ID
    chatwoot_config_id INTEGER NOT NULL,            -- Chatwoot 설정 ID (bot_chatwoot_configs.id 참조)
    matrix_identity_id INTEGER NOT NULL,            -- Matrix ID 설정 ID (bot_matrix_identities.id 참조)
    is_active BOOLEAN NOT NULL DEFAULT TRUE,        -- 이 매핑의 활성화 여부
    notes TEXT,                                     -- 이 매핑에 대한 추가적인 설명 (선택 사항)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- 생성 시각
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, -- 마지막 수정 시각

    -- 외래 키 제약 조건
    CONSTRAINT fk_chatwoot_config
        FOREIGN KEY (chatwoot_config_id)
        REFERENCES public.bot_chatwoot_configs(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_matrix_identity
        FOREIGN KEY (matrix_identity_id)
        REFERENCES public.bot_matrix_identities(id)
        ON DELETE CASCADE,

    -- 유니크 제약 조건 (하나의 Chatwoot 설정은 하나의 Matrix ID에만 매핑 가능)
    CONSTRAINT unique_chatwoot_matrix_pair UNIQUE (chatwoot_config_id, matrix_identity_id)
);

COMMENT ON TABLE public.bot_account_mapping IS 'Chatwoot 계정 설정과 Matrix ID 간의 매핑을 저장하는 테이블입니다.';
COMMENT ON COLUMN public.bot_account_mapping.id IS '매핑 항목의 기본 키(PK)입니다.';
COMMENT ON COLUMN public.bot_account_mapping.chatwoot_config_id IS 'Chatwoot 설정의 ID입니다. bot_chatwoot_configs 테이블을 참조합니다.';
COMMENT ON COLUMN public.bot_account_mapping.matrix_identity_id IS 'Matrix ID 설정의 ID입니다. bot_matrix_identities 테이블을 참조합니다.';
COMMENT ON COLUMN public.bot_account_mapping.is_active IS '이 매핑의 활성화 여부를 나타내는 플래그입니다.';
COMMENT ON COLUMN public.bot_account_mapping.notes IS '이 매핑에 대한 추가적인 설명입니다.';

-- 인덱스 추가 (조회 성능 향상을 위해)
CREATE INDEX IF NOT EXISTS idx_bot_account_mapping_chatwoot_config_id ON public.bot_account_mapping(chatwoot_config_id);
CREATE INDEX IF NOT EXISTS idx_bot_account_mapping_matrix_identity_id ON public.bot_account_mapping(matrix_identity_id);
CREATE INDEX IF NOT EXISTS idx_bot_account_mapping_is_active ON public.bot_account_mapping(is_active);

COMMIT;

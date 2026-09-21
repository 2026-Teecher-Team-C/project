-- ============================================================================
-- 프록시 기반 악성코드 다운로드 탐지 플랫폼 — 서버 스키마 (PostgreSQL)
--
--   대상   : RDS PostgreSQL (검사 서버). 5주 전체 기능 기준.
--   설계서 : docs/superpowers/specs/2026-09-17-erd-review-and-revision.md
--   주의   : 로컬 에이전트에는 DB가 없다 (SQLite 미사용 — 설계서 5장).
--            스풀 상태는 에이전트 인메모리로만 관리하며 이 스키마에 없다.
--
-- ── ERD Cloud 등 다이어그램 툴에 붙여넣는 방법 ──────────────────────────────
--   1) [1] CREATE TABLE 섹션만 복사해 붙여넣으면 테이블과 관계선이 그려진다.
--   2) [2] ALTER / [3] INDEX / [4] COMMENT 섹션은 다이어그램에 필요 없다.
--      툴이 파싱 에러를 내면 이 세 섹션을 제외하고 [1]만 넣으면 된다.
--   3) 툴이 아래 타입을 못 읽으면 치환해도 ERD 구조는 동일하다:
--        TIMESTAMPTZ -> TIMESTAMP     INET -> VARCHAR(45)
--        UUID        -> CHAR(36)
--      실제 DB 적용 시에는 치환하지 말고 원본 타입을 쓸 것.
-- ============================================================================


-- ============================================================================
-- [1] CREATE TABLE  — FK 의존 순서대로 나열 (위에서 아래로 그대로 실행 가능)
-- ============================================================================

-- 1. 관리자 계정 (관리 콘솔)
CREATE TABLE admin_users (
    admin_id      UUID         NOT NULL,
    username      VARCHAR(64)  NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(16)  NOT NULL DEFAULT 'VIEWER',
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_admin_users PRIMARY KEY (admin_id),
    CONSTRAINT uq_admin_users_username UNIQUE (username),
    CONSTRAINT ck_admin_users_role CHECK (role IN ('ADMIN','ANALYST','VIEWER'))
);

-- 2. 물리 장비 (PC 1대 = 1행. OS 재설치로도 바뀌지 않는 단위)
--    설치 인스턴스(agents)와 분리한다 — 재설치하면 agents에 새 행이 생기지만
--    devices는 그대로이므로 장비 단위 이력이 끊기지 않는다.
CREATE TABLE devices (
    device_id     UUID         NOT NULL,
    hardware_uuid VARCHAR(64),                  -- SMBIOS UUID / IOPlatformUUID. 에이전트 보고값
    hostname      VARCHAR(255) NOT NULL,        -- 표시용. 변경·중복 가능하므로 키로 쓰지 않는다
    os_platform   VARCHAR(16)  NOT NULL,
    status        VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_devices PRIMARY KEY (device_id),
    CONSTRAINT ck_devices_os CHECK (os_platform IN ('WINDOWS','MACOS','LINUX')),
    CONSTRAINT ck_devices_status CHECK (status IN ('ACTIVE','RETIRED'))
);
-- hardware_uuid에 UNIQUE를 걸지 않는 이유: 에이전트가 보고하는 값이라 위조 가능하다.
-- UNIQUE면 남의 UUID를 보고하는 것만으로 정상 장비의 등록을 막을 수 있다(DoS).
-- 중복은 허용하고, 재설치 시 기존 장비로 잇는 판단은 관리자가 콘솔에서 수동으로 한다.
-- MAC 주소는 저장하지 않는다 — 랜덤화·다중 어댑터·위조로 식별자 역할을 못 하며,
-- 목적 없이 개인식별성 있는 값을 보관하지 않는다는 원칙에도 어긋난다.

-- 3. 에이전트 = 설치 인스턴스 (하트비트 / 인증)
--    재설치하면 같은 device_id 아래 새 행이 생긴다.
CREATE TABLE agents (
    agent_id              UUID         NOT NULL,
    device_id             UUID         NOT NULL,
    agent_version         VARCHAR(32)  NOT NULL,
    enrollment_token_hash VARCHAR(255) NOT NULL, -- 평문 토큰 저장 금지
    status                VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    last_heartbeat_at     TIMESTAMPTZ,           -- 등록 직후 NULL
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_agents PRIMARY KEY (agent_id),
    CONSTRAINT fk_agents_device FOREIGN KEY (device_id)
        REFERENCES devices (device_id),
    CONSTRAINT ck_agents_status CHECK (status IN ('ACTIVE','INACTIVE','REVOKED'))
);
-- deleted_at을 두지 않는다: 장비 폐기는 devices.status = RETIRED,
-- 설치 인스턴스 무효화는 agents.status = REVOKED로 역할이 갈린다.

-- 4. YARA 룰셋 버전 (활성 룰셋은 항상 1개 — [3] 섹션의 부분 유니크 인덱스로 강제)
CREATE TABLE yara_rulesets (
    rulesets_version INTEGER NOT NULL,
    rule_count   INTEGER     NOT NULL DEFAULT 0,
    is_active    BOOLEAN     NOT NULL DEFAULT FALSE,
    activated_at TIMESTAMPTZ,
    activated_by UUID,
    notes        TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_yara_rulesets PRIMARY KEY (rulesets_version),
    CONSTRAINT fk_yara_rulesets_activated_by FOREIGN KEY (activated_by)
        REFERENCES admin_users (admin_id)
);

-- 5. 개별 YARA 룰
CREATE TABLE yara_rules (
    rule_id         UUID         NOT NULL,
    rulesets_version INTEGER     NOT NULL,
    rule_name       VARCHAR(128) NOT NULL,
    severity        VARCHAR(16)  NOT NULL DEFAULT 'MEDIUM',
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_yara_rules PRIMARY KEY (rule_id),
    CONSTRAINT uq_yara_rules_name UNIQUE (rulesets_version, rule_name),
    CONSTRAINT fk_yara_rules_ruleset FOREIGN KEY (rulesets_version)
        REFERENCES yara_rulesets (rulesets_version) ON DELETE CASCADE,
    CONSTRAINT ck_yara_rules_severity CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

-- 6. ★ 해시 단위 판정 캐시 — 이 스키마의 중심
--    "해시 조회 -> 캐시 히트"의 조회 대상이자 블룸 필터의 원천 데이터.
--    판정이 다운로드 인스턴스가 아니라 파일 해시에 귀속되는 것이 핵심이다.
CREATE TABLE file_verdicts (
    sha256             CHAR(64)    NOT NULL,
    file_size          BIGINT,
    detected_file_type VARCHAR(32),
    verdict            VARCHAR(16) NOT NULL,
    verdict_source     VARCHAR(16) NOT NULL,
    rulesets_version   INTEGER,
    is_stale           BOOLEAN     NOT NULL DEFAULT FALSE,
    analysis_count     INTEGER     NOT NULL DEFAULT 0,
    hit_count          BIGINT      NOT NULL DEFAULT 0,
    first_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verdict_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_file_verdicts PRIMARY KEY (sha256),
    CONSTRAINT fk_file_verdicts_ruleset FOREIGN KEY (rulesets_version)
        REFERENCES yara_rulesets (rulesets_version),
    CONSTRAINT ck_file_verdicts_verdict
        CHECK (verdict IN ('CLEAN','MALICIOUS','SUSPICIOUS','UNKNOWN','ERROR')),
    CONSTRAINT ck_file_verdicts_source
        CHECK (verdict_source IN ('WHITELIST','BLACKLIST','ENGINE','MANUAL'))
);

-- 7. 다운로드 이벤트 (인스턴스 이력 + 성능 지표)
--    ※ 다운로드로 판별된 응답만 INSERT. 일반 트래픽은 행을 만들지 않는다.
CREATE TABLE download_events (
    event_id            UUID         NOT NULL,
    agent_id            UUID         NOT NULL,
    sha256              CHAR(64),
    request_host        VARCHAR(255) NOT NULL,
    url                 TEXT         NOT NULL,
    filename            VARCHAR(512),
    mime_type           VARCHAR(255),
    content_disposition TEXT,
    file_size           BIGINT,
    pipeline_status     VARCHAR(16)  NOT NULL,
    decision            VARCHAR(16),
    decision_source     VARCHAR(16),
    cache_hit           BOOLEAN,
    bytes_uploaded      BIGINT       NOT NULL DEFAULT 0,
    held_at             TIMESTAMPTZ  NOT NULL,
    decided_at          TIMESTAMPTZ,
    hold_duration_ms    INTEGER,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_download_events PRIMARY KEY (event_id),
    CONSTRAINT fk_download_events_agent FOREIGN KEY (agent_id)
        REFERENCES agents (agent_id),
    CONSTRAINT fk_download_events_sha256 FOREIGN KEY (sha256)
        REFERENCES file_verdicts (sha256),
    CONSTRAINT ck_download_events_pipeline CHECK (pipeline_status IN
        ('HELD','HASHED','LOOKUP','UPLOADED','ANALYZING','COMPLETED','FAILED')),
    CONSTRAINT ck_download_events_decision CHECK (decision IN
        ('RELEASED','BLOCKED','BYPASSED','FAIL_CLOSE')),
    CONSTRAINT ck_download_events_decision_source CHECK (decision_source IN
        ('WHITELIST','BLACKLIST','CACHE','ENGINE','POLICY','FALLBACK')),
    CONSTRAINT ck_download_events_completed
        CHECK (pipeline_status <> 'COMPLETED' OR decision IS NOT NULL)
);

-- 8. 검사 실행 기록 (탐지 엔진 1회 실행)
--    크래시/타임아웃도 행으로 남긴다 — "크래시 시 해당 파일만 실패 처리"의 근거.
--    event_id NULL = 다운로드 없이 룰셋 갱신으로 재검사한 경우.
CREATE TABLE analyses (
    analysis_id         UUID        NOT NULL,
    sha256              CHAR(64)    NOT NULL,
    event_id            UUID,
    rulesets_version    INTEGER     NOT NULL,
    engine_version      VARCHAR(32) NOT NULL,
    status              VARCHAR(16) NOT NULL,
    verdict             VARCHAR(16) NOT NULL,
    detected_file_type  VARCHAR(32),
    pe_parsed           BOOLEAN     NOT NULL DEFAULT FALSE,
    max_section_entropy NUMERIC(4,3),
    duration_ms         INTEGER     NOT NULL,
    error_message       TEXT,
    analyzed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_analyses PRIMARY KEY (analysis_id),
    CONSTRAINT fk_analyses_sha256 FOREIGN KEY (sha256)
        REFERENCES file_verdicts (sha256),
    CONSTRAINT fk_analyses_event FOREIGN KEY (event_id)
        REFERENCES download_events (event_id),
    CONSTRAINT fk_analyses_ruleset FOREIGN KEY (rulesets_version)
        REFERENCES yara_rulesets (rulesets_version),
    CONSTRAINT ck_analyses_status
        CHECK (status IN ('SUCCESS','TIMEOUT','CRASH','OOM','UNSUPPORTED')),
    CONSTRAINT ck_analyses_verdict
        CHECK (verdict IN ('CLEAN','MALICIOUS','SUSPICIOUS','UNKNOWN','ERROR'))
);

-- 9. 룰 매칭 결과 (어떤 룰이 매칭됐는가 — 차단 사유 표시용)
CREATE TABLE analysis_matches (
    match_id        UUID         NOT NULL,
    analysis_id     UUID         NOT NULL,
    rule_id         UUID,
    rule_name       VARCHAR(128) NOT NULL,
    severity        VARCHAR(16)  NOT NULL,
    matched_strings TEXT,          -- JSON 문자열. 상한을 걸어 저장할 것 (매칭 폭탄 방지)
    CONSTRAINT pk_analysis_matches PRIMARY KEY (match_id),
    CONSTRAINT uq_analysis_matches UNIQUE (analysis_id, rule_name),
    CONSTRAINT fk_analysis_matches_analysis FOREIGN KEY (analysis_id)
        REFERENCES analyses (analysis_id) ON DELETE CASCADE,
    CONSTRAINT fk_analysis_matches_rule FOREIGN KEY (rule_id)
        REFERENCES yara_rules (rule_id)
);

-- 10. 해시 블랙리스트 (삭제 대신 is_active=FALSE로 비활성화 — 이력 보존)
CREATE TABLE hash_blacklist (
    hash_type      VARCHAR(16)  NOT NULL DEFAULT 'SHA256',
    hash_value     VARCHAR(128) NOT NULL,
    reason         TEXT         NOT NULL,
    severity       VARCHAR(16)  NOT NULL DEFAULT 'HIGH',
    source         VARCHAR(32)  NOT NULL DEFAULT 'MANUAL',
    added_by       UUID,
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMPTZ,
    CONSTRAINT pk_hash_blacklist PRIMARY KEY (hash_type, hash_value),
    CONSTRAINT fk_hash_blacklist_added_by FOREIGN KEY (added_by)
        REFERENCES admin_users (admin_id),
    CONSTRAINT ck_hash_blacklist_type CHECK (hash_type IN ('SHA256','TLSH')),
    CONSTRAINT ck_hash_blacklist_severity
        CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL'))
);

-- 11. 해시 화이트리스트 (오탐 복원 / 예외)
--     블룸 필터는 삭제가 불가능하므로, 조회 순서상 블룸 필터보다 먼저 확인되는
--     별도 레이어로 존재해야 한다 (설계서 4.1).
CREATE TABLE hash_whitelist (
    hash_type            VARCHAR(16)  NOT NULL DEFAULT 'SHA256',
    hash_value           VARCHAR(128) NOT NULL,
    reason               TEXT         NOT NULL,
    origin_quarantine_id UUID,
    added_by             UUID         NOT NULL,
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    expires_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_hash_whitelist PRIMARY KEY (hash_type, hash_value),
    CONSTRAINT fk_hash_whitelist_added_by FOREIGN KEY (added_by)
        REFERENCES admin_users (admin_id),
    CONSTRAINT ck_hash_whitelist_type CHECK (hash_type IN ('SHA256','TLSH'))
    -- origin_quarantine_id -> quarantine_files FK는 [2] 섹션에서 추가 (순환 참조 회피)
);

-- 12. 격리 파일 (S3 보관 — 배포 아키텍처 문서 2장)
CREATE TABLE quarantine_files (
    quarantine_id     UUID          NOT NULL,
    event_id          UUID          NOT NULL,
    sha256            CHAR(64)      NOT NULL,
    agent_id          UUID          NOT NULL,
    original_filename VARCHAR(512),
    file_size         BIGINT        NOT NULL,
    s3_bucket         VARCHAR(63)   NOT NULL,
    s3_key            VARCHAR(1024) NOT NULL,
    status            VARCHAR(16)   NOT NULL DEFAULT 'QUARANTINED',
    quarantined_at    TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ,
    restored_at       TIMESTAMPTZ,
    restored_by       UUID,
    restore_reason    TEXT,
    CONSTRAINT pk_quarantine_files PRIMARY KEY (quarantine_id),
    CONSTRAINT uq_quarantine_files_event UNIQUE (event_id),
    CONSTRAINT uq_quarantine_files_s3 UNIQUE (s3_bucket, s3_key),
    CONSTRAINT fk_quarantine_files_event FOREIGN KEY (event_id)
        REFERENCES download_events (event_id),
    CONSTRAINT fk_quarantine_files_sha256 FOREIGN KEY (sha256)
        REFERENCES file_verdicts (sha256),
    CONSTRAINT fk_quarantine_files_agent FOREIGN KEY (agent_id)
        REFERENCES agents (agent_id),
    CONSTRAINT fk_quarantine_files_restored_by FOREIGN KEY (restored_by)
        REFERENCES admin_users (admin_id),
    CONSTRAINT ck_quarantine_files_status
        CHECK (status IN ('QUARANTINED','RESTORED','DELETED','EXPIRED')),
    -- 복원 상태면 누가·언제 복원했는지가 반드시 있어야 한다
    CONSTRAINT ck_quarantine_files_restored
        CHECK (status <> 'RESTORED' OR (restored_at IS NOT NULL AND restored_by IS NOT NULL))
);

-- 13. 바이패스 도메인 (인증서 피닝 / 보안 기능 보호)
CREATE TABLE bypass_domains (
    bypass_id      UUID         NOT NULL,
    domain_pattern VARCHAR(255) NOT NULL,
    category       VARCHAR(24)  NOT NULL,
    reason         TEXT         NOT NULL,
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by     UUID,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_bypass_domains PRIMARY KEY (bypass_id),
    CONSTRAINT uq_bypass_domains_pattern UNIQUE (domain_pattern),
    CONSTRAINT ck_bypass_domains_category CHECK (category IN ('PINNED','SECURITY_UPDATE')),
    -- 와일드카드 금지: *.google.com은 drive.google.com까지 면제해 검사 구멍을 만든다
    CONSTRAINT ck_bypass_domains_exact_host CHECK (domain_pattern NOT LIKE '%*%'),
    CONSTRAINT fk_bypass_domains_created_by FOREIGN KEY (created_by)
        REFERENCES admin_users (admin_id)
);

-- 14. 파일 타입별 검사 정책 (검사 수준 + "N MB 초과 파일 정책")
CREATE TABLE file_type_policies (
    file_type_policy_id    UUID        NOT NULL,
    file_type              VARCHAR(32) NOT NULL,
    inspection_level       VARCHAR(16) NOT NULL,
    max_inspect_size_bytes BIGINT,
    oversize_action        VARCHAR(16) NOT NULL DEFAULT 'BLOCK',
    is_active              BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_by             UUID,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_file_type_policies PRIMARY KEY (file_type_policy_id),
    CONSTRAINT uq_file_type_policies_type UNIQUE (file_type),
    CONSTRAINT fk_file_type_policies_updated_by FOREIGN KEY (updated_by)
        REFERENCES admin_users (admin_id),
    CONSTRAINT ck_file_type_policies_level
        CHECK (inspection_level IN ('NONE','HASH_ONLY','FULL')),
    CONSTRAINT ck_file_type_policies_oversize
        CHECK (oversize_action IN ('PASS','BLOCK','WARN'))
);

-- 15. 감사 로그 (관리자 행위 추적)
CREATE TABLE audit_logs (
    log_id      BIGSERIAL   NOT NULL,
    actor_id    UUID,
    action      VARCHAR(48) NOT NULL,
    target_type VARCHAR(32) NOT NULL,
    target_id   VARCHAR(128),
    detail      TEXT,        -- JSON 문자열
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT pk_audit_logs PRIMARY KEY (log_id),
    CONSTRAINT fk_audit_logs_actor FOREIGN KEY (actor_id)
        REFERENCES admin_users (admin_id)
);


-- ============================================================================
-- [2] 순환 참조 FK — 테이블이 모두 만들어진 뒤에 추가
-- ============================================================================

ALTER TABLE hash_whitelist
    ADD CONSTRAINT fk_hash_whitelist_quarantine
    FOREIGN KEY (origin_quarantine_id) REFERENCES quarantine_files (quarantine_id);


-- ============================================================================
-- [3] 인덱스 — 다이어그램에는 불필요, 실제 DB 적용 시에만 실행
-- ============================================================================

-- 활성 룰셋은 항상 1개만 존재하도록 강제 (부분 유니크 인덱스)
CREATE UNIQUE INDEX uq_yara_rulesets_active ON yara_rulesets (is_active)
    WHERE is_active;

-- 재설치 시 기존 장비 후보 검색 (자동 매칭이 아니라 관리자에게 제안하는 용도)
CREATE INDEX idx_devices_hardware_uuid ON devices (hardware_uuid)
    WHERE hardware_uuid IS NOT NULL;

-- 온라인 PC 현황 조회
CREATE INDEX idx_agents_heartbeat ON agents (last_heartbeat_at DESC)
    WHERE status = 'ACTIVE';

-- 블룸 필터 재구축 시 악성 해시만 스캔
CREATE INDEX idx_file_verdicts_malicious ON file_verdicts (last_verdict_at DESC)
    WHERE verdict = 'MALICIOUS' AND NOT is_stale;

-- 콘솔 이벤트 스트림(SSE) / PC별 조회 / 해시 역조회 / 차단 이력
CREATE INDEX idx_events_stream  ON download_events (created_at DESC);
CREATE INDEX idx_events_agent   ON download_events (agent_id, created_at DESC);
CREATE INDEX idx_events_sha256  ON download_events (sha256);
CREATE INDEX idx_events_blocked ON download_events (created_at DESC)
    WHERE decision = 'BLOCKED';

-- 해시별 검사 이력
CREATE INDEX idx_analyses_sha256 ON analyses (sha256, analyzed_at DESC);

-- 감사 로그 조회
CREATE INDEX idx_audit_actor ON audit_logs (actor_id, created_at DESC);


-- ============================================================================
-- [4] 테이블 설명 (선택 — 툴이 COMMENT를 못 읽으면 이 섹션만 제외)
-- ============================================================================

COMMENT ON TABLE admin_users         IS '관리 콘솔 계정';
COMMENT ON TABLE devices             IS '물리 장비 (OS 재설치로 바뀌지 않는 식별 단위)';
COMMENT ON TABLE agents              IS '에이전트 설치 인스턴스 (하트비트/인증)';
COMMENT ON TABLE yara_rulesets       IS 'YARA 룰셋 버전 (활성 1개)';
COMMENT ON TABLE yara_rules          IS '개별 YARA 룰';
COMMENT ON TABLE file_verdicts       IS '해시 단위 판정 캐시 (블룸 필터 원천)';
COMMENT ON TABLE download_events     IS '다운로드 1건의 파이프라인 이력 및 성능 지표';
COMMENT ON TABLE analyses            IS '탐지 엔진 1회 실행 기록 (실패/크래시 포함)';
COMMENT ON TABLE analysis_matches    IS '매칭된 YARA 룰 (차단 사유)';
COMMENT ON TABLE hash_blacklist      IS '알려진 악성 해시';
COMMENT ON TABLE hash_whitelist      IS '오탐 복원/예외 해시 (블룸 필터 앞단 레이어)';
COMMENT ON TABLE quarantine_files    IS 'S3 격리 보관 및 복원 상태';
COMMENT ON TABLE bypass_domains      IS '검사 바이패스 도메인 (피닝 / 보안 기능 보호)';
COMMENT ON TABLE file_type_policies  IS '파일 타입별 검사 수준 및 크기 초과 정책';
COMMENT ON TABLE audit_logs          IS '관리자 행위 감사 로그';

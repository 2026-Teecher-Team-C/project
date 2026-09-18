# 감사 로그 기록 규격 (`audit_logs`)

- 날짜: 2026-09-18
- 목적: `audit_logs`의 `action` / `target_type` / `target_id` / `detail`에 **무엇을 어떤 형식으로
  넣을지** 고정한다. 이 규격이 없으면 구현자마다 다른 문자열을 써서 나중에 집계·추적이 불가능해진다.
- 관련 문서:
  [`2026-09-17-erd-review-and-revision.md`](2026-09-17-erd-review-and-revision.md) (테이블 정의),
  [`docs/schema/schema.sql`](../../schema/schema.sql) (DDL),
  [`2026-09-18-system-flow.md`](2026-09-18-system-flow.md) (시스템 흐름),
  [`2026-09-15-architecture-review-and-5week-plan.md`](2026-09-15-architecture-review-and-5week-plan.md) 3.1 (인증 — 이 로그가 필요한 이유)

## 0. 왜 이 규격이 필요한가

`action`과 `target_type`은 `VARCHAR` 자유 문자열이다. `RESTORE_QUARANTINE` / `restore_quarantine` /
`격리복원`이 섞이면 **"화이트리스트를 누가 언제 조작했나"를 쿼리로 뽑을 수 없다.**

이 로그의 존재 이유는 관리 콘솔에 **탐지를 무력화하는 조작이 존재**하기 때문이다 — 화이트리스트
추가, 격리 복원, 바이패스 도메인 등록, 블랙리스트 해제. 각 테이블의 `added_by` 컬럼만으로는
**삭제된 항목을 추적할 수 없다**(넣고 쓰고 지우면 흔적이 사라진다). 그 공백을 메우는 것이 이 표다.

---

## 1. `target_type` — 11종

관리자가 조작할 수 있는 대상만 들어간다.

| `target_type` | 대상 테이블 | `target_id` 형식 |
|---|---|---|
| `ADMIN_USER` | `admin_users` | UUID (인증 실패 시는 예외 — 3장) |
| `AGENT` | `agents` | UUID |
| `WHITELIST` | `hash_whitelist` | **`<해시종류>:<해시값>`** |
| `BLACKLIST` | `hash_blacklist` | **`<해시종류>:<해시값>`** |
| `QUARANTINE` | `quarantine_files` | UUID |
| `RULESET` | `yara_rulesets` | 정수 문자열 (`"5"`) |
| `YARA_RULE` | `yara_rules` | UUID |
| `BYPASS_DOMAIN` | `bypass_domains` | UUID |
| `FILE_TYPE_POLICY` | `file_type_policies` | UUID |
| `FILE_VERDICT` | `file_verdicts` | SHA-256 64자 |
| `CACHE` | (테이블 없음 — Redis 직접 무효화) | 무효화 대상 값 또는 NULL |

### 감사 대상이 아닌 테이블

`download_events`, `analyses`, `analysis_matches` — 시스템이 기록하는 것이고 관리자는 조회만 한다.

### `FILE_VERDICT`이 목록에 있는 이유

`file_verdicts.verdict_source`에 **`MANUAL`** 값이 있다. 관리자가 판정을 직접 지정할 수 있다는
뜻이므로 감사 대상이다.

---

## 2. `action` — 19종

⚠️ 표시는 **탐지를 무력화하는 조작**이다. 알림·별도 검토 대상으로 다뤄야 한다.

### 인증

| `action` | `target_type` | `target_id` | `actor_id` |
|---|---|---|---|
| `LOGIN` | `ADMIN_USER` | 본인 `admin_id` | 본인 |
| `LOGIN_FAILED` | `ADMIN_USER` | **시도한 계정명** | **NULL** |
| `LOGOUT` | `ADMIN_USER` | 본인 `admin_id` | 본인 |

### 계정 관리

| `action` | `target_type` | `target_id` |
|---|---|---|
| `CREATE_ADMIN` | `ADMIN_USER` | 생성된 `admin_id` |
| `UPDATE_ADMIN_ROLE` | `ADMIN_USER` | 대상 `admin_id` |
| `DEACTIVATE_ADMIN` | `ADMIN_USER` | 대상 `admin_id` |

### 해시 리스트

| `action` | `target_type` | `target_id` | |
|---|---|---|---|
| `ADD_WHITELIST` | `WHITELIST` | `SHA256:44d886...` | ⚠️ |
| `REMOVE_WHITELIST` | `WHITELIST` | `SHA256:44d886...` | |
| `ADD_BLACKLIST` | `BLACKLIST` | `SHA256:44d886...` | |
| `REMOVE_BLACKLIST` | `BLACKLIST` | `SHA256:44d886...` | ⚠️ |

### 격리

| `action` | `target_type` | `target_id` | |
|---|---|---|---|
| `RESTORE_QUARANTINE` | `QUARANTINE` | `quarantine_id` | ⚠️ |
| `DELETE_QUARANTINE` | `QUARANTINE` | `quarantine_id` | |

### 룰셋 / 룰

| `action` | `target_type` | `target_id` | |
|---|---|---|---|
| `ACTIVATE_RULESET` | `RULESET` | `"5"` | |
| `ENABLE_YARA_RULE` | `YARA_RULE` | `rule_id` | |
| `DISABLE_YARA_RULE` | `YARA_RULE` | `rule_id` | ⚠️ |

### 정책

| `action` | `target_type` | `target_id` | |
|---|---|---|---|
| `ADD_BYPASS_DOMAIN` | `BYPASS_DOMAIN` | `bypass_id` | ⚠️ |
| `REMOVE_BYPASS_DOMAIN` | `BYPASS_DOMAIN` | `bypass_id` | |
| `UPDATE_FILE_TYPE_POLICY` | `FILE_TYPE_POLICY` | `file_type_policy_id` | ⚠️ |

### 판정 / 에이전트 / 캐시

| `action` | `target_type` | `target_id` | |
|---|---|---|---|
| `SET_MANUAL_VERDICT` | `FILE_VERDICT` | SHA-256 | ⚠️ |
| `REVOKE_AGENT` | `AGENT` | `agent_id` | |
| `INVALIDATE_CACHE` | `CACHE` | 대상 값 또는 NULL | |

### ⚠️ 항목이 무력화 조작인 이유

| `action` | 결과 |
|---|---|
| `ADD_WHITELIST` | 그 해시가 조회 사슬 ①에서 **영구 통과** |
| `REMOVE_BLACKLIST` | 알려진 악성이 통과 |
| `RESTORE_QUARANTINE` | 악성 판정을 뒤집음 |
| `ADD_BYPASS_DOMAIN` | 그 도메인 전체가 **무검사** |
| `UPDATE_FILE_TYPE_POLICY` | `inspection_level`을 `NONE`으로 바꾸면 해당 타입 전체 무검사 |
| `SET_MANUAL_VERDICT` | 엔진 판정을 사람이 덮어씀 |
| `DISABLE_YARA_RULE` | 그 룰로 잡던 악성코드가 통과 |

---

## 3. `target_id` 형식 규칙

`target_type`이 `target_id`의 형식을 결정한다. `audit_logs.target_id`는 **FK가 아니다** —
대상 테이블마다 PK 타입이 달라 하나의 FK로 묶을 수 없는 **다형성 참조**다.

### 복합키 대상은 조립한다

`hash_whitelist`와 `hash_blacklist`만 PK가 복합키 `(hash_type, hash_value)`다. 한 칼럼으로
가리킬 수 없으므로 **`:`로 이어붙인다.**

```
target_id = 'SHA256:44d88612fea8a8f36de82e1278abb02f...'
target_id = 'TLSH:T1A2B3C4...'
```

해시값만 넣으면 안 된다 — 나중에 TLSH 항목이 생겼을 때 어느 리스트의 어느 종류인지 구분되지 않는다.

### 인증 실패는 예외

`LOGIN_FAILED`는 **존재하지 않는 계정으로도 발생**한다. 그 경우 `admin_id`가 없으므로:

- `target_id` = 시도한 **계정명 문자열**
- `actor_id` = **NULL** (인증이 실패했으므로 주체가 확정되지 않았다)

`actor_id`가 NULL인 다른 경우는 **시스템 자동 행위**(격리 파일 보관기간 만료 처리 등)다. 둘을
`action` 값으로 구분할 수 있게 명명한다.

---

## 4. `detail` — 변경 전/후

`action`만 있으면 "누가 뭘 했다"까지만 알 수 있다. **"어떻게 바뀌었나"가 `detail`에 있어야
감사 로그의 가치가 온전해진다.**

`TEXT`에 JSON 문자열로 넣는다 (이식성 위해 `JSONB` 대신 `TEXT`).

### 기본 구조

```json
{"before": {...}, "after": {...}}
```

### 예시

```json
// ADD_WHITELIST
{"after": {"hash_type":"SHA256","hash_value":"44d886...","reason":"사내 배포 도구 오탐",
           "expires_at":"2026-12-31T00:00:00Z","origin_quarantine_id":"a1b2c3-..."}}

// RESTORE_QUARANTINE
{"before": {"status":"QUARANTINED"},
 "after":  {"status":"RESTORED","restore_reason":"오탐 확인 — 사내 빌드 산출물"}}

// UPDATE_FILE_TYPE_POLICY
{"before": {"inspection_level":"FULL"}, "after": {"inspection_level":"NONE"}}

// LOGIN_FAILED
{"attempted_username":"admin","reason":"BAD_PASSWORD","attempt_count":3}
```

### 담지 말아야 할 것

- **비밀번호·토큰** (평문이든 해시든)
- 파일 내용 자체 (해시와 파일명까지만)
- `original_filename`을 넣을 때는 **공격자가 정한 값**임을 기억할 것 — 콘솔 표시 시 이스케이프

---

## 5. 기록 원칙

| 원칙 | 내용 |
|---|---|
| **append 전용** | `UPDATE` / `DELETE`를 하지 않는다. DB 권한에서도 막는 것이 원칙이며, 스키마로는 강제할 수 없다 |
| **장기 보관** | `download_events`(브라우징 이력, 보존기간 짧게)와 **반대**다. 조사 목적상 오래 남긴다 |
| **실패도 기록** | `LOGIN_FAILED`처럼 성공하지 않은 시도도 남긴다. 콘솔이 인터넷에 열려 있으므로 무단 접근 시도가 보여야 한다 |
| **판정 자체는 기록하지 않는다** | 엔진의 악성/안전 판정은 `analyses`·`file_verdicts`의 일이다. 여기는 **사람의 조작**만 남긴다 |

---

## 6. 아직 결정하지 않은 것

### 6.1 `target_type`에 CHECK 제약을 걸지

| | 장점 | 단점 |
|---|---|---|
| CHECK 추가 | 표기 불일치·오타 차단 | 대상이 늘면 제약 수정 필요 |
| 자유 문자열 유지 | 유연 | `WHITELIST` / `whitelist` 혼재 위험 |

대상 목록이 테이블 수만큼 고정돼 있어 자주 바뀌지 않는다. **`target_type`에는 CHECK를 걸고
`action`은 자유 문자열로 두는** 쪽을 권한다 — `action`은 종류가 많고 기능 추가 시 늘어난다.

### 6.2 `ip_address`를 `INET` → `VARCHAR(45)`로 바꿀지

`INET`은 PostgreSQL 전용 타입이다. `JSONB` → `TEXT` 전환과 **같은 이식성 기준**을 적용하면 바꾸는
것이 일관된다. `INET`의 이점은 서브넷 연산(`<<=`)인데 현재 계획에 그런 조회가 없다.

### 6.3 ⚠️ 조작 알림을 보낼지

`⚠️` 표시된 7개 `action`은 **보안을 끄는 조작**이다. Slack 알림 대상에 포함할지 정해야 한다.
현재 Slack 알림은 악성 탐지 시에만 전송하도록 설계돼 있다(배포 문서 8장).

---

## 전달 상태

- [ ] `action` / `target_type` 목록 팀 합의
- [ ] 6장 미결정 3건 결정
- [ ] 콘솔 구현(3주차)에 이 규격 반영

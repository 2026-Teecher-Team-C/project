# 프록시 기반 악성코드 다운로드 탐지 플랫폼

> 다운로드 파일을 디스크에 닿기 전 프록시가 가로채 격리 검사한 뒤, 안전한 파일만 브라우저로
> 전달하는 시스템

브라우저는 소켓에서 데이터가 도착하는 대로 디스크에 쓴다. 바이트가 브라우저에 닿는 순간 파일은
이미 존재하므로 **받고 나서 검사할 여지가 없다.** 그래서 프록시가 응답을 붙잡고 있는 것이 유일한
방법이다. OS 프록시 계층에 두었으므로 브라우저뿐 아니라 `curl`·런처·업데이터까지 같은 통로로
덮는다.

**이 저장소는 설계 문서만 담는다.** 동작하는 코드는 PoC 저장소에 있다.

| 저장소 | 검증 대상 | 언어 |
|---|---|---|
| [`poc1-response-holding`](https://github.com/2026-Teecher-Team-C/poc1-response-holding) | 응답 보류 · 다운로드 판별 · 이벤트 대시보드 | Python (mitmproxy) |
| [`poc2-streaming-hash-spool`](https://github.com/2026-Teecher-Team-C/poc2-streaming-hash-spool) | 스트리밍 SHA-256 + 스풀 단일 패스 | Java (WebFlux) |
| [`poc3-yara-detection`](https://github.com/2026-Teecher-Team-C/poc3-yara-detection) | 해시 대조 + YARA 매칭 판정 | Python |
| [`poc1-response-holding-java`](https://github.com/2026-Teecher-Team-C/poc1-response-holding-java) | 응답 보류 재검증 (참고용 — 리버스 프록시라 에이전트 구조와 불일치) | Java |

---

## 현재 상태 (2026-09-26)

| | 항목 | 근거 |
|---|---|---|
| ✅ | **응답 보류** — HTTP/HTTPS, 실제 인터넷 오리진, 체크섬 일치. 차단 시 `chrome://downloads`에 항목 자체가 생기지 않는다 | PoC 1 |
| ✅ | **보류 상한** — Chrome·curl 모두 300초 초과. 검사 파이프라인의 시간 예산은 브라우저 제약을 받지 않는다 | PoC 1 |
| ✅ | **다운로드 판별** — `Sec-Fetch-Mode` 기반 재설계로 오탐 139건 → 3건 | PoC 1 재측정 |
| ✅ | **이벤트 대시보드** — SSE 실시간 스트림 | PoC 1 Part B |
| ✅ | **스트리밍 SHA-256 + 스풀 단일 패스** — 32MiB를 64KiB × 512 chunk로, 전체 집계 없이. 오류·크기 초과 시 미완성 파일 삭제 | PoC 2 |
| ✅ | **서버 판정** — EICAR → `malicious` 0.255ms, 일반 텍스트 → `safe` 0.121ms. YARA 단독 경로도 변종으로 분리 검증 | PoC 3 |
| ⬜ | **스풀 파일 보호 규칙** — `UUID.tmp` 파일명, `0600`·실행 비트 제거, XOR 인코딩, 인덱싱 제외 | 미착수 (제품 설계 7장) |
| ⚠️ | **에이전트 측 스풀링** — mitmproxy는 버퍼링으로만 헤더를 붙잡는다. `stream`을 켜면 200이 즉시 나가므로 헤더를 붙잡은 채 디스크로 스풀할 수 없다. 버퍼링 + `body_size_limit`으로 간다 (메모리 본문 × 2.3) | [`2026-09-26-header-timing.md`](docs/superpowers/specs/2026-09-26-header-timing.md) |
| 🔨 | **에이전트 S1 파이프라인** — 판별 → 보류 → `CheckHash`/`SubmitFile` → 통과/403 → `ReportEvent`. 가짜 서버로 E2E 통과, 리뷰 중 | platform-agent #2 · #3 · #4 |
| ⬜ | 검사 서버 전체(블룸 필터·판정 API), 관리 콘솔, 배포 | 미착수 |

**게이트는 통과했다.** 설계 전체가 기대던 "헤더 전송 전에 응답을 붙잡을 수 있는가"가 실측으로
닫혔다. 남은 것은 구현이다.

---

## 읽는 순서

| | 무엇을 알게 되나 | 문서 |
|---|---|---|
| **1** | 무엇을 만드는가, 왜 이 구조인가, 무엇을 안 하는가 | [`프록시-악성코드-탐지-플랫폼.md`](프록시-악성코드-탐지-플랫폼.md) |
| **2** | 다운로드 1건이 요청부터 릴리스/차단까지 지나는 경로 | [`2026-09-18-system-flow.md`](docs/superpowers/specs/2026-09-18-system-flow.md) |
| **3** | 지금 어디까지 왔고 무엇이 열려 있는가 | [`2026-09-21-poc1-results-and-download-detection.md`](docs/superpowers/specs/2026-09-21-poc1-results-and-download-detection.md) |

1번만 읽어도 시스템은 이해된다. 3번이 가장 최신 상태다.

## 목적별 색인

| 알고 싶은 것 | 문서 |
|---|---|
| 데이터 구조 (15개 테이블) | [`2026-09-17-erd-review-and-revision.md`](docs/superpowers/specs/2026-09-17-erd-review-and-revision.md) — 2.3 장비/에이전트 분리, 2.4 바이패스 사유 |
| 붙여넣기용 DDL | [`docs/schema/schema.sql`](docs/schema/schema.sql) |
| 배포·인프라 (EC2 / RDS / S3 / Redis) | [`2026-09-12-deployment-architecture-design.md`](docs/superpowers/specs/2026-09-12-deployment-architecture-design.md) |
| 감사 로그 규격 (11 target × 19 action) | [`2026-09-18-audit-log-spec.md`](docs/superpowers/specs/2026-09-18-audit-log-spec.md) |
| 4일 MVP 범위 | [`2026-09-13-mvp-scope.md`](docs/superpowers/specs/2026-09-13-mvp-scope.md) |
| 5주 일정과 기술 선택 | [`2026-09-15-architecture-review-and-5week-plan.md`](docs/superpowers/specs/2026-09-15-architecture-review-and-5week-plan.md) |
| PoC 계획과 검증 절차 | [`2026-09-13-poc-list.md`](docs/superpowers/specs/2026-09-13-poc-list.md), [`2026-09-21-poc-https-and-dashboard.md`](docs/superpowers/specs/2026-09-21-poc-https-and-dashboard.md) |
| 탐지 엔진 브로커 도입 기준 | [`2026-09-12-detection-engine-broker-decision.md`](docs/superpowers/specs/2026-09-12-detection-engine-broker-decision.md) |
| 실제로 돌아가는 코드와 실측 로그 | PoC 저장소의 `README.md`, `addons/dashboard.py` |

---

## 확정된 설계 결정

문서를 읽다 흔들리면 여기로 돌아온다. 되돌리려면 근거가 필요한 항목들이다.

- **검사 서버 장애 시 fail-close 고정** (2026-09-18). fail-open 선택지도 정책 토글도 두지
  않는다. 서버에 닿지 못하면 차단한다
- **로컬 에이전트는 파일 내용을 파싱하지 않는다.** PE 헤더·엔트로피·압축 해제·YARA는 전부 검사
  서버 몫이다. 단말의 공격 표면을 최소로 두기 위한 결정이다
- **에이전트에 영속 저장소를 두지 않는다.** 판정 캐시(SQLite)도 스풀 상태 DB도 없다
- **스풀 파일은 무해해야 한다.** `UUID.tmp`, `0600`, 실행 비트 제거, XOR 인코딩, 인덱싱 제외 —
  어떤 자동 파서도 처리 대상으로 판단하지 않게 만드는 것이 목적이다
- **식별 단위는 장비(에이전트)이며 사용자 신원은 보관하지 않는다.** MAC 주소도 저장하지 않는다
- **비대응 범위**: QUIC(HTTP/3), 인증서 피닝 앱, 시스템 프록시를 안 보는 프로그램, Range 분할
  다운로드, USB·로컬 복사, 공유 PC·VDI, 파일리스·제로데이, 실행 시점 행위 분석(EDR 영역)

## 지금 열려 있는 것

- **스풀 파일 보호 규칙** — `UUID.tmp`, `0600`, XOR 인코딩, 인덱싱 제외가 아직 어느 PoC에도
  없다. 제품 설계 7장이 CVE 세 건을 근거로 세운 원칙인데 코드로 검증된 적이 없다
- **S2 "메모리에 전부 올리지 않음"의 방식** — 헤더를 붙잡은 채 스풀하는 경로가 mitmproxy 훅에 없다.
  버퍼링 + 상한 / HTTP 레이어 확장 / 헤더 선전송 + 연결 끊기 중 결정 필요 (header-timing 4장)
- **압축 인코딩 다운로드** — 에이전트는 압축을 풀지 않으므로 현재 정책 차단. 서버 격리 해제는
  `SubmitFileMetadata.content_encoding` 계약 변경이 필요하다
- `SECURITY_UPDATE` 바이패스의 정확한 호스트 목록 — fail-close가 브라우저 보안 갱신까지 막는
  문제의 대응
- 남은 오탐 3건 — 원인이 각각 달라 단일 수정으로 닫히지 않는다
- 보존·마스킹 주기 재검토, Safari·Firefox 보류 상한

각 문서 맨 아래 `전달 상태` 체크리스트가 그 문서의 미결 항목이다.

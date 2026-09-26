# 에이전트 S1 파이프라인 Chrome 실측

- 날짜: 2026-09-26
- 대상: platform-agent `feat/hold-pipeline` (PR #4, #2·#3 포함) — 판별 → 보류 → `CheckHash`/`SubmitFile` →
  통과/403 → `ReportEvent`
- 목적: Sprint 1 완료 기준("실제 브라우저에서 EICAR는 403, 일반 파일은 저장됨. 서버 불통 시 차단")을 실제
  Chrome으로 확인한다
- 관련 문서: [`2026-09-26-header-timing.md`](2026-09-26-header-timing.md) (버퍼링 보류의 근거),
  [`2026-09-21-poc1-results-and-download-detection.md`](2026-09-21-poc1-results-and-download-detection.md) (판별 규칙)

## 환경

- Chrome 154.0.8037.57, **헤드리스** (Playwright로 구동), 별도 프로필, `--disable-quic`
- 프록시: 호스트 `mitmdump -s src/addon_entry.py`, `BODY_SIZE_LIMIT=8m` (상한 초과 시나리오를 빠르게 보려고)
- HTTPS: mitmproxy CA를 시스템 키체인에 넣지 않고 `--ignore-certificate-errors-spki-list`로 이 프로필에만 신뢰
- 검사 서버: 가짜 VerdictService (`tests/fakes/verdict_server.py`) — EICAR만 차단, 그 외는 업로드 후 ALLOW
- 오리진: 로컬 HTTP 서버(시나리오별 헤더 조합) + HTTPS 실사이트

## 결과

| # | 시나리오 | Chrome | 에이전트 판정 (ReportEvent) |
|---|---|---|---|
| A | 일반 페이지 (HTML·이미지·fetch) | 200 | 비다운로드 — 이벤트 없음 |
| B | 링크 클릭 → 2MiB `application/octet-stream` 첨부 | 저장, sha256 일치 | RELEASED / ENGINE, 업로드 2MiB, 보류 12ms |
| C | 링크 클릭 → EICAR 첨부 | **다운로드 안 생김**, 차단 페이지 | BLOCKED / BLACKLIST, `cache_hit`, 업로드 0 |
| D | `<a download>` → EICAR (CD 없음) | 다운로드 생성 후 **"취소됨"**, 파일 없음 | BLOCKED / BLACKLIST |
| E | gzip 인코딩 첨부 | 차단 페이지 | BLOCKED / POLICY ("encoded download unsupported") |
| F | CD만 있는 `text/plain` 첨부 | 저장 | RELEASED / ENGINE |
| G | 16MiB chunked (상한 8m) | 502 | FAIL_CLOSE / POLICY |
| H | HTTPS 실사이트 `www.7-zip.org/a/7zr.exe` (600KB) | 저장, 직접 받은 파일과 sha256 일치 | RELEASED / ENGINE, 보류 1,748ms |
| I | HTTPS `secure.eicar.org/eicar.com` | **텍스트로 렌더링** (파일 저장 없음) | 비다운로드 — 스트리밍 통과 |
| J | 웹서핑 (Wikipedia·Hacker News·GitHub) | 200, 0.5~1.0s | 이벤트 없음 |
| K | 서버 불통 → B와 같은 첨부 | 차단 페이지 ("fail-close") | 차단 |
| L | 서버 불통 → H와 같은 HTTPS 다운로드 | 차단 페이지 ("fail-close") | 차단 |
| M | 서버 불통 → 웹서핑 | 200 | 영향 없음 |

**Sprint 1 완료 기준은 Chrome에서도 충족한다.** H의 보류 1.7초는 인터넷에서 본문을 받는 시간을 포함한다
(`held_at`이 `responseheaders` 시점).

## 발견

1. **Chrome 네트워크 시간 요청 오탐** — 기동할 때마다 `clients2.google.com/time/1/current`가 인코딩 다운로드로
   정책 차단된다. 브라우저 프로세스의 요청이라 `Sec-Fetch`가 없어 폴백 규칙(CD 신뢰)을 타고, 응답에
   `Content-Disposition: attachment; filename="json.txt"` + gzip이 붙는다. PoC 1 재설계가 "폴백 경로 오탐율은
   측정하지 않았다"고 남긴 구멍이다 → platform-agent #5
2. **서버 불통 시 Chrome 구성요소 업데이트 차단** — `dl.google.com`, `edgedl.me.gvt1.com`의 업데이트가 fail-close로
   막힌다. 서버가 살아 있을 때는 보류 → 업로드(14KB) → 통과. README의 `SECURITY_UPDATE` 바이패스 미결 항목을
   실제로 재현했다
3. **Content-Type 없는 응답은 브라우저가 렌더링하면 비다운로드다** — `secure.eicar.org`는 헤더 없이 68바이트를
   보내고, Chrome은 파일로 저장하지 않고 화면에 보여준다. 에이전트도 비다운로드로 판정해 통과시킨다. 파일은
   생기지 않으므로 설계 범위(다운로드) 밖이지만, **EICAR 바이트가 브라우저와 HTTP 캐시까지는 도달한다**
4. **"차단 시 다운로드 목록에 항목이 안 생긴다"는 링크 탐색에만 성립한다** — C(링크 클릭)는 다운로드 자체가
   없었지만, D(`<a download>`)는 Chrome이 다운로드를 먼저 만들고 403을 받아 "취소됨"으로 끝낸다. 헤드리스라
   `chrome://downloads` 화면은 보지 못했고, D는 실패 항목이 남을 가능성이 높다

## 미측정

- 화면 있는(headful) Chrome, `chrome://downloads` 목록 확인
- 시스템 키체인에 CA를 등록한 실제 설치 조건 (S4 설치 파일)
- Safari·Firefox, Windows (S4)
- 실서버 (가짜 서버 기준)

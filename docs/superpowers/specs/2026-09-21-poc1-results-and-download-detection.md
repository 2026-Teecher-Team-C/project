# PoC 1 결과 반영 및 다운로드 판별 재설계

- 날짜: 2026-09-21
- 목적: PoC 1(응답 보류)의 Part A(HTTPS 인터셉션)·Part B(다운로드 이벤트 대시보드) 실측 결과를
  상위 설계에 반영한다. 두 갈래다 — (1) PoC 1이 무엇을 닫았고 무엇이 열려 있는지 확정 기록,
  (2) **다운로드 판별 규칙 재설계 제안** (MVP 기능 A의 입력)
- 관련 문서:
  [`2026-09-21-poc-https-and-dashboard.md`](2026-09-21-poc-https-and-dashboard.md) (이 실측을 만든 절차서),
  [`2026-09-13-mvp-scope.md`](2026-09-13-mvp-scope.md) (MVP 기능 A = 다운로드 트래픽 감지 정의),
  [`2026-09-17-erd-review-and-revision.md`](2026-09-17-erd-review-and-revision.md) (`download_events` 컬럼 정의, 6장 보존 정책),
  [`프록시-악성코드-탐지-플랫폼.md`](../../../프록시-악성코드-탐지-플랫폼.md) (제품 설계 3장 로컬 에이전트, 6장 시간 예산, 8장 스코프)
- 근거 원문: [`poc1-response-holding` README](https://github.com/2026-Teecher-Team-C/poc1-response-holding/blob/main/README.md)의
  "HTTPS 인터셉션 및 보류 상한 실측 (macOS, 2026-09-21)", "다운로드 이벤트 대시보드 검증 (2026-09-21)" 두 절

## 문서 읽는 법

1~5장은 **실측값**이고, 6~7장은 **제안이며 아직 구현·측정하지 않았다**. 6~7장을 실측 결과로
읽지 말 것 — 근거는 있지만 검증되지 않은 설계안이다.

---

## 1. HTTPS 인터셉션 — 게이트 통과 (실측)

CLAUDE.md가 지정한 이 프로젝트의 최우선 게이트 항목이 닫혔다. `addons/hold_response.py`를
**한 줄도 고치지 않은 채** HTTPS에서 보류·차단이 동작했다. 실제 인터넷 오리진
`python.org` 45,387,635 bytes pkg 기준.

```
기준선(프록시 미경유)  http=200 time=3.899985 size=45387635
통과(BLOCK=False)      http=200 time=7.845719 size=45387635   SHA-256 기준선과 완전 일치
차단(BLOCK=True)       http=403 time=7.229562 size=37
```

Chrome에서도 인증서 경고 없이 통과했고, `BLOCK=True`에서 **`chrome://downloads`에 항목 자체가
생기지 않았다.** 이것이 제품 설계 2장 "받고 나서 지우는 것과 다르다"는 핵심 주장의 실증이다.

## 2. 보류 상한 — 시간 예산 (실측)

```
curl   3 / 10 / 30 / 60 / 120 / 300초 전 구간 통과 (time_total = 300.013559 등 보류값과 일치)
Chrome 300초 보류에도 연결을 끊지 않음. 300초 뒤 응답을 받아 정상 저장, 체크섬 원본과 일치
```

**Chrome 기준 보류 상한은 300초 초과(T > 300s).** 제품 설계 6장 "헤더 보류로 인한 타임아웃과
차단 UX 품질의 트레이드오프"가 문장에서 숫자로 바뀌었다 — 검사 파이프라인의 시간 예산은
적어도 5분까지는 브라우저 제약을 받지 않는다.

**미검증으로 남은 것**: Safari·Firefox의 보류 상한, HTTPS 경로에서의 상한(위 300초 측정은
전부 HTTP 오리진 기준), 300초를 넘는 지점.

## 3. `bypass_domains` — 후보 없음 (실측)

CA 등록 직후 세션에서 Chrome 백그라운드 통신의 TLS 핸드셰이크가 49건 실패해 처음에는 인증서
피닝으로 판단했으나, **이후 세션에서 같은 도메인이 통과하며 재현되지 않았다**
(11:01 49건 → 11:09 1건 → 11:11 0건 → 11:18 0건). `accounts.google.com`은 이후 3회 등장,
실패 0건.

파일 호스팅 도메인을 직접 확인했다:

```
drive.google.com        Chrome에서 인증서 경고 없이 정상 표시
dl.google.com           설치 파일 다운로드 시작됨
storage.googleapis.com  GCS의 MissingSecurityHeader XML을 Chrome이 렌더링
```

셋 다 평문 요청 라인이 찍혔고 핸드셰이크 실패 0건.

**결론: 피닝으로 확인된 도메인이 없다. `bypass_domains` 초기 데이터 후보는 현재 비어 있다.**

**주의사항 (8장 스코프의 "피닝된 앱" 항목에 반영 필요)**: 바이패스 목록을 만들 때
`*.google.com` 같은 와일드카드를 쓰면 `drive.google.com`이 함께 빠져 검사 구멍이 된다.
정확한 호스트명 단위로만 등록해야 한다.

## 4. 다운로드 판별 실측 — 절차서 규칙은 사용 불가 수준 (실측)

`addons/dashboard.py`(절차서 B.4 코드와 byte-identical)로 측정했다. **다운로드를 한 건도 하지
않은 4분간의 일반 웹서핑**에서:

```
총 이벤트           139건
실제 다운로드 MIME    0건
크기                최소 18B / 중앙값 82,980B / 최대 1,628,854B
```

발동 규칙별:

```
80건  규칙 3 — len(body) >= 64KB
59건  규칙 1 — Content-Disposition: attachment
 0건  규칙 2 — DOWNLOAD_MIMES 일치
```

MIME별:

```
46건 text/javascript  40건 application/json  20건 application/javascript
12건 text/css  8건 text/html  8건 image/png  3건 text/plain
 1건 application/x-protobuffer  1건 image/webp
```

**핵심 발견**: 59건은 18~459바이트짜리 JSON API 응답이다. Google이 anti-XSSI 하드닝 목적으로
`Content-Disposition: attachment; filename="f.txt"`를 붙이기 때문이다
(`/async/ddljson`, `/complete/search` 등, 쿼리에 `xssi=t` 동반). 브라우저는 fetch/XHR 응답에서
이 헤더를 무시하므로 서버 쪽에서 안전하게 쓸 수 있는 방어 기법이다.

→ **절차서가 가장 신뢰할 만한 다운로드 신호로 쓴 헤더가 실제로는 다운로드와 무관하다.** 크기
폴백만 조이는 것으로는 해결되지 않는다 (③④의 `mode` 구분이 필요한 이유는 5장).

**규모**: 4분 139건 ≈ 시간당 약 2,000행, 8시간 근무 기준 장비 한 대당 약 16,000행. 각 행에
URL 전문이 들어간다. → ERD 6장이 우려한 "`download_events`가 브라우징 이력 DB가 된다"가
수치로 확인됐다.

**사용성**: 판별 → 3초 보류 → 이벤트 순서이므로 139건이 전부 3초씩 지연됐다. 오탐은 DB 오염
이전에 웹서핑이 느려지는 문제다.

## 5. Sec-Fetch-* 측정 — 판별 규칙 재설계의 근거 (실측)

요청 맥락 헤더로 진짜 다운로드와 오탐을 가를 수 있는지 실측했다.

**전제**: `Sec-Fetch-*`는 potentially trustworthy origin(HTTPS 또는 localhost)에만 전송된다.
평문 HTTP + IP 주소 오리진에서는 Chrome이 헤더를 아예 붙이지 않는다(실측 확인). **curl 등
비브라우저 클라이언트도 전송하지 않는다**(실측: 전 필드 빈 문자열).

다운로드 방식별 실측값:

```
① <a href> 링크 클릭        dest=document  mode=navigate  site=same-origin  user=?1
② <a download> 속성          dest=empty     mode=navigate  site=same-origin  user=-
③ fetch() + Blob 저장        dest=empty     mode=cors      site=same-origin  user=-
④ Content-Disposition만 있는
   text/plain 파일 (링크 클릭) dest=document  mode=navigate  site=same-origin  user=?1

오탐 (Google anti-XSSI)      dest=empty     mode=no-cors   site=none/cross-site  user=-
```

**④와 오탐은 응답 헤더 구성이 동일하다**(`Content-Disposition: attachment` + 비다운로드
MIME). 그런데 요청 맥락은 정반대다. 이것이 6장 규칙 재설계의 근거다.

**`dest`만으로는 부족하다** — ②③과 오탐이 전부 `empty`다. 갈리는 것은 `mode`다.

**측정 환경의 한계**: ①②③④는 전부 같은 테스트 환경(localhost)에서 측정했다. 실제 인터넷
오리진의 다양한 다운로드 방식은 미검증이다. `mode == cors`에서 "다운로드 MIME일 때만 인정"하는
6장의 규칙은 ③ 한 건으로만 검증했다.

---

## 6. 제안 — 다운로드 판별 규칙 재설계 (미구현·부분검증)

> 이 장은 **제안**이다. 아래 규칙을 4장의 오탐 139건 데이터셋에 소급 적용한 결과만 검증됐고,
> 실제 트래픽에 이 규칙 자체를 넣어 재측정하지는 않았다.

```
1) Sec-Fetch 헤더가 있는 경우 (브라우저 + HTTPS/localhost)
   - mode == navigate           → 다운로드 후보. Content-Disposition / MIME / 크기 규칙 전부 적용
   - mode == no-cors            → 서브리소스. Content-Disposition 단독 신호를 신뢰하지 않는다
   - mode == cors                → XHR. 다운로드 MIME일 때만 인정
2) Sec-Fetch 헤더가 없는 경우 (비브라우저 클라이언트, 평문 HTTP 오리진)
   → 기존 규칙(Content-Disposition / MIME / 64KB 크기)으로 폴백
3) 크기 폴백(64KB)은 브라우저가 자체 렌더링/해석하는 MIME에는 적용하지 않는다
   제외 대상: text/html, text/css, text/javascript, application/javascript,
             application/json, text/plain, image/*, video/*, font/*
```

**소급 검증 결과**: 이 규칙을 4장의 오탐 139건 데이터셋에 적용하면 **남는 이벤트 0건**이다.
동시에 5장의 ①②③④ 네 가지 다운로드 방식은 전부 탐지된다.

**남은 한계 (반드시 명시)**:

- 규칙 2(폴백)는 평문 HTTP 오리진과 비브라우저 클라이언트에서 기존 오탐 문제가 그대로
  남는다. 이 경로의 오탐율은 측정하지 않았다
- ①②③④는 전부 같은 테스트 환경(localhost)에서 측정했다. 실제 인터넷 오리진의 다양한
  다운로드 방식은 미검증이다
- `mode == cors`에서 "다운로드 MIME일 때만 인정"하는 규칙은 ③ 한 건으로만 검증했다

## 7. 제안 — `responseheaders` 훅으로 이동 (미구현)

> 이 장도 **제안**이다. 코드로 구현하거나 측정한 적이 없다.

현재 `response` 훅은 **모든 응답 본문을 끝까지 버퍼링한 뒤** 판정한다. 그래서 (a) 4장의 오탐
139건이 전부 3초씩 지연됐고, (b) 1장에서 45MB가 통째로 메모리에 올라갔다 (부수 발견 1번,
기준선 3.899985s vs 프록시 경유 7.845719s — 다운로드 시간 위에 보류가 얹힌다).

mitmproxy의 `responseheaders` 훅은 본문 수신 전에 불리며, 거기서
`flow.response.stream = True`를 지정하면 해당 flow는 버퍼링 없이 통과한다.

```
responseheaders: 요청 맥락 + 응답 헤더로 판정
  다운로드 아님 → stream = True   (버퍼링·보류·이벤트 없음)
  다운로드     → 버퍼 유지, response 훅에서 보류
```

**이 한 가지 변경이 오탐 행·웹서핑 지연·대용량 메모리 버퍼링 세 문제를 동시에 해결한다** (제안일
뿐 미검증).

단, `Content-Length`가 없는 chunked 응답에서는 헤더 시점에 크기를 알 수 없으므로 스트리밍
바이트 카운터가 필요하다 — 이는 제품 설계 8장/ERD `file_type_policies.oversize_action`이
이미 다루려던 문제와 같은 자리다.

---

## 8. ERD·스키마에 반영이 필요한 항목 (수정하지 말고 목록으로만)

`docs/schema/schema.sql`과 `docs/superpowers/specs/2026-09-17-erd-review-and-revision.md`는
이 문서 작성 시점에 이미 미커밋 변경이 있어 건드리지 않았다. 아래는 그 문서들에 반영이
필요한 항목 목록이다.

1. **`download_events.mime_type`이 BLOCKED 건에서 구조적으로 오염된다.** `flow.response`를
   403으로 교체한 뒤 헤더를 읽기 때문에 원본이 아니라 차단 응답의 `text/plain`이 기록된다.
   **차단된 파일이 원래 무엇이었는지가 기록에서 사라진다.** 차단 전 원본 MIME을 별도 컬럼으로
   보존하는 설계가 필요하다
2. **`download_events.file_size`** — erd-review 문서 "논리 오류 6번"과 절차서 B.3/B.7은
   "chunked면 `Content-Length`가 없어 NULL 우려"라고 적었으나, 실제 구현(`addons/dashboard.py`)은
   헤더가 아니라 버퍼 실제 바이트(`len(flow.response.content)`)를 쓰므로 chunked에서도 항상
   채워진다. **문서와 구현의 불일치이며 구현 쪽이 더 견고하다.** erd-review 문서의 해당 서술
   정정 필요 (`file_size BIGINT` NOT NULL 검토 가능)
3. **실제로 NULL이 나오는 유일한 칸은 `mime_type`이다** (`Content-Type` 부재 시 빈 문자열).
   `not null` 제약 검토 시 이 칸이 대상이다. `content_disposition`은 erd-review 논리 오류
   6번의 지적대로 NULL 허용이 맞다 (139건 중 80건이 `content_disposition` 없이도 다운로드
   후보로 잡혔다)
4. **PoC 구현의 `created_at`에 날짜가 없다**(`HH:MM:SS`만, PoC 한정). 실제 ERD의
   `created_at TIMESTAMPTZ`는 이미 날짜를 포함하므로 스키마 자체는 문제 없다 — PoC 코드의
   단순화였을 뿐이라는 점을 기록해 둔다
5. **보존·마스킹 정책이 판별 로직보다 먼저 필요할 수 있다.** erd-review 6장은 이미 90일 후
   `url`→`request_host` 마스킹을 정해뒀지만, 판별이 느슨한 채로 서버에 올리면 그 90일 동안
   시간당 2,000행 × URL 전문이 쌓인다. 6장의 마스킹 주기를 재검토할 필요가 있다

## 9. 대시보드 구조 — PoC 전용, 최종 아키텍처 아님

최종은 `에이전트 → gRPC → API 서버 → SSE → 콘솔`이다 (제품 설계 3장). PoC의 `dashboard.py`는
addon이 로컬 HTTP 서버를 직접 연다. 이 코드를 그대로 에이전트에 남기면 로컬 에이전트가 웹
서버를 품게 되어 "로컬 에이전트는 파일 내용을 파싱하지 않는다 / 공격 표면 최소화" 원칙과
충돌한다.

**상위로 옮길 것**: `_is_download()` 판별 로직(6장 제안으로 대체 예정)과 이벤트 필드 스키마.
**옮기지 않을 것**: `dashboard.py`의 로컬 SSE 서버 코드 자체.

---

## 전달 상태

- [x] Part A·B 실측 결과 이 문서에 반영 (1~5장)
- [x] 다운로드 판별 재설계안 작성 및 오탐 데이터셋으로 소급 검증 (6장)
- [ ] 6장 규칙을 실제 addon 코드로 구현하고 재측정 — 미착수
- [ ] 7장 `responseheaders` 스트리밍 구조 구현 — 미착수
- [ ] 8장 항목을 `docs/schema/schema.sql` / `2026-09-17-erd-review-and-revision.md`에 실제
      반영 — 미착수 (두 파일 다 이 작업 시작 시점에 이미 다른 미커밋 변경이 있어 건드리지
      않음)
- [ ] Safari·Firefox 보류 상한 실측 (2장) — 미착수

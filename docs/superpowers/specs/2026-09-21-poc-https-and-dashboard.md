# PoC 진행 절차서 — HTTPS 인터셉션 + 다운로드 이벤트 대시보드

- 날짜: 2026-09-21
- 목적: PoC 1(응답 보류)에서 **아직 닫히지 않은 칸**을 닫고, 다운로드 이벤트를 실시간 대시보드로
  띄울 수 있는지 검증한다.
- 관련 문서:
  [`프록시-악성코드-탐지-플랫폼.md`](../../../프록시-악성코드-탐지-플랫폼.md) (제품 설계),
  [`2026-09-13-poc-list.md`](2026-09-13-poc-list.md) (PoC 1~3 원본 계획),
  [`2026-09-15-architecture-review-and-5week-plan.md`](2026-09-15-architecture-review-and-5week-plan.md) (1주차 위험 3가지),
  [`2026-09-17-erd-review-and-revision.md`](2026-09-17-erd-review-and-revision.md) (이벤트 필드의 출처)
- 대상 저장소: [`poc1-response-holding`](https://github.com/2026-Teecher-Team-C/poc1-response-holding)

## 0. 현재 상태

PoC 1은 **HTTP 경로에서만** 완료다 (2026-09-14 커밋 기준).

| 항목 | 상태 |
|---|---|
| 포워드 프록시 + 응답 보류 + 403 교체 | ✅ curl·Chrome 실측 |
| 동시 요청 논블로킹 (`asyncio.sleep`) | ✅ |
| **HTTPS 인터셉션** | ❌ **미검증 — 1주차 위험 1번, 게이트 항목** |
| **보류 가능 시간의 상한** | ❌ 3초만 확인 |
| **스트리밍 모드 헤더 타이밍** | ❌ `stream=False`(전체 버퍼링)로만 검증 |

A는 게이트다. 실패하면 Phase 2와 설계 전제가 무너진다. B는 A가 끝난 뒤 같은 환경에서 바로 잇는다.

---

# Part A. HTTPS 인터셉션 검증

## A.1 원칙 — addon은 건드리지 않는다

`hold_response.py`를 **한 줄도 고치지 않은 채** HTTPS에서도 `response` 훅이 불려야 정상이다.
mitmproxy가 TLS를 종료하고 평문 flow를 훅에 넘겨주므로, 코드 수정이 필요하다면 그건 설정 문제다.
검증 중 addon을 고치고 싶어지면 멈추고 A.5 진단표를 먼저 보라.

## A.2 테스트 URL 준비

다음 조건을 **모두** 만족하는 URL 하나를 고른다.

| 조건 | 이유 |
|---|---|
| HTTPS | 검증 대상 |
| QUIC(HTTP/3)을 강제하지 않음 | UDP/443은 OS 프록시를 우회 — 설계상 out of scope |
| HSTS 프리로드 + 인증서 피닝 아님 | 피닝 앱은 설계상 바이패스 대상 |
| 10~50MB 수준의 정상 파일 | 너무 작으면 타이밍이 안 보이고, 랜덤 바이트는 Chrome이 자체 차단 |

권장: 공개 소프트웨어 배포처의 `.zip` / `.dmg` 직링크. 확신이 없으면 로컬에 TLS `http.server`를
띄워 자체 인증서로 먼저 통과시킨 뒤 실제 인터넷 오리진으로 옮긴다 (PoC 1은 아직 LAN `http.server`만
검증했으므로 **실제 인터넷 오리진 검증도 이번에 같이 닫힌다**).

Chrome은 QUIC 격리를 위해 이렇게 띄운다.

```bash
# macOS — QUIC을 끈 별도 프로필로 실행 (기존 프로필에 영향 없음)
open -na "Google Chrome" --args \
  --disable-quic \
  --user-data-dir=/tmp/poc-chrome \
  --proxy-server="http://127.0.0.1:8080"
```

`--proxy-server`를 쓰면 **시스템 프록시를 건드리지 않고** 이 창만 프록시를 타므로, 실패했을 때
원복할 것이 없다. 시스템 프록시 설정(A.4)은 이 방식이 성공한 뒤에 한다.

## A.3 CA 등록

### macOS

```bash
# 1) mitmproxy를 한 번 실행해 CA 생성 (없으면 이 시점에 만들어진다)
ls ~/.mitmproxy/mitmproxy-ca-cert.pem

# 2) 시스템 키체인에 "항상 신뢰"로 등록 (관리자 암호 1회)
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/.mitmproxy/mitmproxy-ca-cert.pem

# 3) 확인 — 결과에 mitmproxy가 보여야 한다
security find-certificate -a -c mitmproxy /Library/Keychains/System.keychain | head
```

> **Docker로 실행 중이라면** 컨테이너 안의 `~/.mitmproxy`가 호스트와 다르다. CA를 볼륨으로 꺼내
> 호스트 키체인에 등록해야 한다. 이번 검증만큼은 `windows/`의 네이티브 실행 경로처럼
> **호스트에서 직접 `mitmdump`를 띄우는 쪽이 변수 하나를 줄인다.**

**로그인 키체인이 아니라 시스템 키체인(`/Library/Keychains/System.keychain`)**이어야 한다.
가장 흔한 실패 원인이다.

### Windows

저장소의 `windows/` PowerShell 스크립트에 CA 설정/원복이 이미 있다. 없다면:

```powershell
certutil -addstore -f "ROOT" "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.cer"
```

## A.4 검증 시나리오

`mitmdump -s addons/hold_response.py -p 8080`으로 띄운 뒤, A.2의 Chrome 창에서 수행한다.

| # | 조건 | 기대 결과 |
|---|---|---|
| 1 | `BLOCK = False`, HTTPS 다운로드 | 3초 지연 후 정상 저장. **SHA-256이 원본과 동일** |
| 2 | `BLOCK = True`, HTTPS 다운로드 | 403. 브라우저 다운로드 목록에 **항목이 생기지 않음** |
| 3 | 1·2를 curl로 반복 | `curl -x http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem -o out.bin -w '%{http_code} %{time_total}\n' <URL>` |

2번의 "다운로드 목록에 항목이 안 생긴다"가 제품 설계 2장의 핵심 주장이다. **스크린샷을 남겨라.**
발표에서 이 장면 하나가 "받고 나서 지우는 것과 뭐가 다른가"에 대한 답이 된다.

## A.5 실패 시 진단표

| 증상 | 원인 | 조치 |
|---|---|---|
| `response` 훅이 아예 안 불림 | 트래픽이 프록시를 안 탐 | mitmproxy 로그에 해당 요청이 보이는지부터 확인. 안 보이면 QUIC 또는 프록시 미적용 |
| 브라우저가 인증서 경고 | CA 미신뢰 / 로그인 키체인에 등록됨 | A.3을 시스템 키체인으로 재수행 후 브라우저 완전 종료·재실행 |
| `ERR_QUIC_PROTOCOL_ERROR` 또는 로그에 요청 없음 | QUIC으로 우회 | `--disable-quic` 확인. 그래도 나면 다른 오리진으로 교체 |
| `CONNECT`만 찍히고 평문 flow 없음 | TLS 종료 실패(피닝·HSTS 프리로드) | 해당 도메인은 바이패스 대상. 다른 URL로 교체 후 `bypass_domains` 후보로 기록 |
| 통과는 되는데 파일 손상 | 응답 교체/인코딩 처리 문제 | 시나리오 1의 SHA-256 비교로 재현. `Content-Encoding` 확인 |

**중요**: 피닝·HSTS로 실패한 도메인은 "버그"가 아니라 **설계상 예정된 비대응 범위**다. 발견하면
고치지 말고 목록에 적어라 — 그게 `bypass_domains` 테이블의 초기 데이터가 된다.

## A.6 보류 상한 실측 (같은 환경에서 바로 이어서)

`asyncio.sleep(3)`의 값만 바꿔가며 **브라우저가 언제 포기하는지**를 잰다.

```
3 → 10 → 30 → 60 → 120 → 300 (초)
```

| 클라이언트 | 끊긴 시각 | 화면에 표시된 오류 |
|---|---|---|
| Chrome | | |
| Safari | | |
| Firefox | | |
| curl | | |

이 표가 제품 설계 6장의 *"헤더 보류로 인한 타임아웃과 차단 UX의 트레이드오프"*를 문장에서
**숫자**로 바꾼다. 여기서 나온 값이 곧 **검사 파이프라인 전체의 시간 예산**이다.

## A.7 원복

```bash
# macOS — CA 신뢰 해제
sudo security delete-certificate -c mitmproxy /Library/Keychains/System.keychain
rm -rf /tmp/poc-chrome
```

시스템 프록시를 건드리지 않았다면 원복할 것은 CA뿐이다.

---

# Part B. 다운로드 이벤트 대시보드 PoC

## B.1 검증 대상

> 에이전트가 가로챈 다운로드의 정보를 **실시간으로 화면에 띄울 수 있는가.**

제품 설계 3장 관리 콘솔의 "실시간 차단 이벤트 스트림(SSE)"을 **가장 작은 형태로** 앞당겨 검증한다.
동시에 MVP 기능 A(다운로드 판별)와 ERD의 `download_events` 필드 설계가 실제로 채워지는지 확인한다.

## B.2 PoC 구조와 최종 구조의 차이 (반드시 인지할 것)

```
[PoC]     mitmproxy addon ──(프로세스 내 큐)──> 로컬 SSE 서버 ──> 브라우저 대시보드
[최종]    에이전트 ──gRPC──> API 서버 ──SSE──> 콘솔(Vercel)
```

PoC에서는 에이전트 안에 대시보드를 함께 띄운다. **이건 최종 아키텍처가 아니다.** 검증하려는 것은
"이벤트를 만들어 흘려보내면 화면이 실시간으로 갱신되는가"이고, 전송 구간이 gRPC인지 프로세스 내
큐인지는 이 검증의 대상이 아니다. 문서에 이 줄을 남기는 이유는, PoC 코드를 그대로 에이전트에
남기면 **로컬 에이전트가 웹 서버를 품는** 구조가 되어 7장의 공격 표면 최소화 원칙과 충돌하기 때문이다.

## B.3 이벤트 필드 — `download_events`의 부분집합으로 맞춘다

임의로 정하지 말고 ERD의 컬럼명을 그대로 쓴다. 나중에 서버로 옮길 때 매핑 비용이 0이 된다.

| 필드 | 출처 | 비고 |
|---|---|---|
| `event_id` | UUID 생성 | |
| `created_at` | 수신 시각 | |
| `request_host` | `flow.request.host` | |
| `url` | `flow.request.pretty_url` | **PoC는 로컬 전용.** 보존 정책은 ERD 6장 참고 |
| `filename` | `Content-Disposition` → 없으면 URL basename | 공격자가 정한 값 — 표시만, 경로로 쓰지 않는다 |
| `mime_type` | `Content-Type` | |
| `file_size` | `Content-Length` 또는 실제 바이트 수 | chunked면 `Content-Length`가 없다 |
| `sha256` | 스트리밍 해시 | PoC 2와 합류하는 지점 |
| `held_ms` | 보류 시작~판정 완료 | A.6의 시간 예산과 대조 |
| `decision` | `RELEASED` / `BLOCKED` | |
| `decision_source` | PoC에선 `POLICY`(토글) | 최종은 `ENGINE`/`BLACKLIST` 등 |

## B.4 구현

의존성은 mitmproxy 하나로 유지한다 (표준 라이브러리 `asyncio`만 추가로 사용).

### `addons/dashboard.py`

```python
"""다운로드 이벤트를 수집해 로컬 SSE로 흘려보내는 PoC용 addon.

주의: 최종 아키텍처에서 이 역할은 API 서버가 맡는다 (B.2 참고).
"""
import asyncio
import hashlib
import json
import time
import uuid
from urllib.parse import unquote, urlparse

from mitmproxy import http

DASHBOARD_PORT = 8765
HOLD_SECONDS = 3
BLOCK = False  # PoC 1과 동일한 데모용 토글

# 다운로드로 볼 MIME (제품 설계 3장 "다운로드 판별")
DOWNLOAD_MIMES = (
    "application/octet-stream", "application/zip", "application/x-msdownload",
    "application/x-apple-diskimage", "application/vnd.microsoft.portable-executable",
)
MIN_DOWNLOAD_BYTES = 64 * 1024


class Dashboard:
    def __init__(self):
        self.events: list[dict] = []
        self.subscribers: set[asyncio.Queue] = set()

    # ── mitmproxy 훅 ──────────────────────────────────────────────
    def running(self):
        asyncio.get_running_loop().create_task(self._serve())

    async def response(self, flow: http.HTTPFlow):
        # 대시보드 자신에 대한 요청은 이벤트로 만들지 않는다 (무한 루프 방지)
        if flow.request.port == DASHBOARD_PORT:
            return
        if not self._is_download(flow):
            return

        started = time.perf_counter()
        body = flow.response.content or b""
        sha256 = hashlib.sha256(body).hexdigest()

        await asyncio.sleep(HOLD_SECONDS)  # 판정 대기 자리 (PoC 3에서 실제 판정으로 교체)

        if BLOCK:
            flow.response = http.Response.make(
                403, b"Blocked by malware detection platform",
                {"Content-Type": "text/plain"},
            )

        self._emit({
            "event_id": str(uuid.uuid4()),
            "created_at": time.strftime("%H:%M:%S"),
            "request_host": flow.request.host,
            "url": flow.request.pretty_url,
            "filename": self._filename(flow),
            "mime_type": flow.response.headers.get("content-type", ""),
            "file_size": len(body),
            "sha256": sha256,
            "held_ms": round((time.perf_counter() - started) * 1000),
            "decision": "BLOCKED" if BLOCK else "RELEASED",
            "decision_source": "POLICY",
        })

    # ── 다운로드 판별 (MVP 기능 A) ────────────────────────────────
    def _is_download(self, flow: http.HTTPFlow) -> bool:
        headers = flow.response.headers
        if "attachment" in headers.get("content-disposition", "").lower():
            return True
        mime = headers.get("content-type", "").split(";")[0].strip().lower()
        if mime in DOWNLOAD_MIMES:
            return True
        return len(flow.response.content or b"") >= MIN_DOWNLOAD_BYTES

    def _filename(self, flow: http.HTTPFlow) -> str:
        cd = flow.response.headers.get("content-disposition", "")
        if "filename=" in cd:
            return unquote(cd.split("filename=")[-1].strip('"; '))
        return urlparse(flow.request.pretty_url).path.rsplit("/", 1)[-1] or "(no name)"

    # ── SSE 서버 ──────────────────────────────────────────────────
    def _emit(self, event: dict):
        self.events.insert(0, event)
        del self.events[200:]
        for q in list(self.subscribers):
            q.put_nowait(event)

    async def _serve(self):
        server = await asyncio.start_server(self._handle, "127.0.0.1", DASHBOARD_PORT)
        print(f"[dashboard] http://127.0.0.1:{DASHBOARD_PORT}")
        async with server:
            await server.serve_forever()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            request_line = await reader.readline()
            path = request_line.decode(errors="replace").split(" ")[1] if b" " in request_line else "/"
            while (await reader.readline()) not in (b"\r\n", b""):
                pass

            if path.startswith("/events"):
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                             b"Cache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n")
                queue: asyncio.Queue = asyncio.Queue()
                self.subscribers.add(queue)
                try:
                    for event in reversed(self.events):   # 접속 시 기존 이벤트부터
                        queue.put_nowait(event)
                    while True:
                        event = await queue.get()
                        writer.write(f"data: {json.dumps(event)}\n\n".encode())
                        await writer.drain()
                finally:
                    self.subscribers.discard(queue)
            else:
                page = PAGE.encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                             + f"Content-Length: {len(page)}\r\n\r\n".encode() + page)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()


PAGE = """<!doctype html><meta charset=utf-8><title>다운로드 이벤트</title>
<style>
 body{font:14px -apple-system,sans-serif;margin:2rem;color:#111}
 table{border-collapse:collapse;width:100%}
 th,td{padding:.5rem .6rem;border-bottom:1px solid #eee;text-align:left;white-space:nowrap}
 th{font-size:12px;color:#888;font-weight:500}
 .BLOCKED{color:#c00;font-weight:600} .RELEASED{color:#090}
 .hash{font-family:ui-monospace,monospace;font-size:12px;color:#888}
</style>
<h2>다운로드 이벤트 <small id=n style="color:#888;font-weight:400">0건</small></h2>
<table><thead><tr>
 <th>시각<th>파일명<th>호스트<th>크기<th>SHA-256<th>보류(ms)<th>판정
</tr></thead><tbody id=t></tbody></table>
<script>
const tbody = document.getElementById('t');
let count = 0;
new EventSource('/events').onmessage = (e) => {
  const d = JSON.parse(e.data);
  const kb = (d.file_size / 1024).toFixed(0).replace(/\\B(?=(\\d{3})+$)/g, ',');
  const row = document.createElement('tr');
  row.innerHTML = `<td>${d.created_at}<td>${d.filename}<td>${d.request_host}`
    + `<td>${kb} KB<td class=hash>${d.sha256.slice(0, 12)}…`
    + `<td>${d.held_ms}<td class=${d.decision}>${d.decision}`;
  tbody.prepend(row);
  document.getElementById('n').textContent = `${++count}건`;
};
</script>"""

addons = [Dashboard()]
```

### 실행

```bash
mitmdump -s addons/dashboard.py -p 8080
# 다른 터미널 또는 브라우저에서
open http://127.0.0.1:8765
```

`hold_response.py`와 **동시에 쓰지 않는다** — 보류가 두 번 걸린다. `dashboard.py`가 PoC 1의
기능을 포함한다.

## B.5 검증 기준

| # | 확인할 것 | 통과 기준 |
|---|---|---|
| 1 | 다운로드 1건 → 대시보드에 행 추가 | 새로고침 없이 자동으로 나타남 |
| 2 | 비다운로드 트래픽(일반 웹서핑) | 행이 **생기지 않음** (ERD 6장 "행을 만들지 않는다") |
| 3 | `BLOCK = True` | 판정 칸이 `BLOCKED`(빨강), 브라우저는 403 |
| 4 | 동시 다운로드 3건 | 3행이 각각 독립적으로 추가, 서로 지연되지 않음 |
| 5 | 대시보드 탭 2개 | 양쪽 모두 실시간 갱신 (SSE 다중 구독) |
| 6 | HTTPS 다운로드 (Part A 완료 후) | HTTP와 동일하게 행 추가 |

2번이 조용한 핵심이다. 여기서 행이 마구 생기면 다운로드 판별 로직이 느슨한 것이고, 그대로 가면
`download_events`가 **브라우징 이력 DB**가 된다 (ERD 6장의 우려가 현실이 되는 지점).

## B.6 개인정보 주의

이 대시보드는 `url` 전체를 화면에 띄운다. **PoC는 로컬 전용이므로 괜찮지만**, 서버로 옮기는 순간
ERD 6장의 보존·마스킹 정책(90일 후 `request_host`만 남김)이 함께 적용되어야 한다. 화면 캡처를
팀 외부(발표 자료 등)로 공유할 때는 개인 URL이 찍히지 않았는지 확인할 것.

## B.7 이 PoC가 앞당겨 증명하는 것

| 최종 기능 | 여기서 검증되는 부분 |
|---|---|
| MVP 기능 A — 다운로드 판별 | `_is_download()` 로직이 실제 트래픽에서 동작하는가 |
| 관리 콘솔 — SSE 이벤트 스트림 | 이벤트 푸시 → 화면 실시간 갱신 |
| `download_events` 스키마 | 필드가 실제로 채워지는가, NULL이 나오는 칸은 어디인가 |
| 성능 지표 (제품 설계 10장) | `held_ms`가 p99 지연 집계의 원형 |

특히 **"NULL이 나오는 칸"을 기록하라.** chunked 응답에서 `Content-Length`가 없는 것처럼, ERD
논리 오류 6번(`not null` 남발)에서 지적된 문제가 실제 데이터로 확인되는 자리다.

---

## 다음 단계

A 완료 → B 완료 → **PoC 2 (스트리밍 해시 + 스풀)**. 지금 `dashboard.py`는 `flow.response.content`로
전체를 메모리에 올린다(`stream=False`). PoC 2에서 스트리밍 모드로 바꾸면 헤더 전송 시점이 달라지고,
그것이 위험 2번과 `file_type_policies.oversize_action` 값 결정의 근거가 된다.

## 전달 상태

- [x] Part A 수행 및 결과 기록 (A.4 시나리오 3건, A.6 타임아웃 표) — curl·Chrome 실측 완료
      (README "HTTPS 인터셉션 및 보류 상한 실측" 절). 단 A.6 타임아웃 표는 Chrome·curl
      두 칸만 채워졌다 — **Safari·Firefox는 미측정** (시간 제약으로 이번 라운드에서
      제외했고, 근거 기록은 남기지 않았다)
- [x] 피닝·HSTS로 실패한 도메인을 `bypass_domains` 초기 데이터 후보로 정리 — 정리 결과
      **후보 없음** (피닝으로 확인된 도메인이 한 건도 없었다). 상세는
      [`2026-09-21-poc1-results-and-download-detection.md`](2026-09-21-poc1-results-and-download-detection.md) 3장
- [x] Part B 수행 및 검증 기준 6건 확인 — 5건 통과, 기준 2("일반 웹서핑에 행이 생기지
      않음")는 실패. 이 실패가 버그가 아니라 다운로드 판별 로직 자체의 한계라는 것이
      이번 라운드의 핵심 측정 결과다. 상세는 위 문서 4~6장
- [ ] A.6 타임아웃 값을 제품 설계 6장에 숫자로 반영 — **미수행.** `프록시-악성코드-탐지-플랫폼.md`가
      이 작업 시작 시점에 이미 이 작업과 무관한 미커밋 변경 상태였으므로, 직접 수정하는
      대신 위 신규 문서 2장에 반영 필요 항목으로만 기록했다. 실제 반영은 그 미커밋
      변경이 정리된 뒤 별도로 수행해야 한다
- [ ] 팀원과 "대시보드는 PoC 전용, 최종 구조 아님"(B.2) 공유 — **미수행.** 문서화(README,
      위 신규 문서 9장)까지는 끝났으나 팀원에게 실제로 전달하는 것은 이 작업의 범위 밖이라
      별도로 진행해야 한다

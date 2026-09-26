# 대용량 다운로드의 헤더 타이밍 실측 (mitmproxy)

- 날짜: 2026-09-26
- 목적: 스프린트 1주차 위험 2번 "대용량 파일에서 헤더가 언제 나가는가"를 닫는다. 결과에 따라
  S2의 "대용량 파일도 메모리에 전부 올리지 않음(스트리밍 스풀)" 방식이 정해진다
- 환경: macOS (arm64), mitmproxy 12.2.3, Python 3.12.14, 평문 HTTP 로컬 오리진(50MB/s 스로틀),
  클라이언트 `curl -x` (`time_starttransfer` = 헤더 도착 시각)
- 관련 문서: [`2026-09-21-poc1-results-and-download-detection.md`](2026-09-21-poc1-results-and-download-detection.md)
  7장 (`responseheaders` 전환 제안), 제품 설계 6장 (헤더 전송 후 차단 불가)

## 결론

1. **버퍼링(`stream=False`)은 헤더를 끝까지 붙잡는다.** 본문 전체 수신 + `response` 훅의 보류가
   끝난 뒤에야 헤더가 나간다. 보류·403 교체 모두 동작. **대가는 메모리 — 본문의 약 2.3배**
2. **`stream`에 콜러블을 걸어 "스풀에 쓰고 아무것도 안 넘기는" 방식은 쓸 수 없다.** `stream`을
   켜는 순간 200 헤더가 즉시 나가므로(5ms) 403을 만들 수 없다. 여기에 chunked 응답이면 빈 청크가
   종료 표시(`0\r\n\r\n`)로 직렬화되어 클라이언트는 **빈 파일을 정상 완료로** 받는다
3. **mitmproxy 공개 훅 안에서는 "헤더를 붙잡은 채 디스크로 스풀"이 불가능하다.** 헤더 전송은
   `stream` 설정과 묶여 있고 분리하는 옵션이 없다
4. **`body_size_limit`은 fail-close와 맞는다.** 초과 시 클라이언트는 깔끔한 502를 받는다
   (Content-Length가 있으면 즉시, chunked면 상한까지 버퍼링한 뒤)

→ **S1은 버퍼링 + `body_size_limit` 상한으로 간다.** S2의 "메모리에 전부 올리지 않음"은 이
구조에서 성립하지 않으므로 팀 결정이 필요하다 (4장).

## 1. 측정값

| 방식 | 인코딩 | 크기 | 클라이언트 응답 | 헤더 도착 | 전체 | 수신 바이트 | 최대 RSS |
|---|---|---|---|---|---|---|---|
| (a) 버퍼링 + 10초 보류 | CL | 300MB | 200 | 15.80s | 15.87s | 300MB | 771MB |
| (a) 버퍼링 + 10초 보류 | chunked | 300MB | 200 | 15.81s | 15.95s | 300MB | 비슷 |
| (a) 버퍼링 + 10초 보류 | CL | 1GB | 200 | 29.34s | 29.55s | 1GB | **2.32GB** |
| (a) 상한 없음 | CL | 2GB | 200 | 39.02s | 39.80s | 2GB | **4.40GB** |
| (a) `body_size_limit=500m` | CL | 700MB | **502** | 0.006s | 0.006s | 175B | ~110MB |
| (a) `body_size_limit=500m` | chunked | 700MB | **502** | 10.01s | 10.01s | 175B | ~726MB |
| (b) 스풀 콜러블 + 403 교체 | CL | 5MB | 200 (행) | 0.005s | 120s 타임아웃 | 0 | 27MB |
| (b) 스풀 콜러블 + 403 교체 | chunked | 5MB | 200 (정상 완료로 인식) | 0.005s | 0.005s | 0 | 27MB |
| (c) `stream=True` | chunked | 50MB | 200 | 0.061s | 1.02s | 50MB | ~111MB |

(a) 1GB 로그: `responseheaders` → 19.3초 뒤 본문 수신 완료, `response` 훅 진입 → 10초 보류 →
헤더 도착 29.34s. **헤더 도착 = 전송 시간 + 보류 시간**이 모든 (a) 실행에서 성립했다.

(b)에서 `response` 훅은 불리고 `flow.response`를 403으로 바꾸는 것도 되지만, 선로에는 아무 영향이
없다 — 이미 200 헤더가 나갔다.

## 2. 근거 (mitmproxy 12.2.3 소스)

- `proxy/layers/http/__init__.py` `start_response_stream()` — `flow.response.stream`이 참이면
  `ResponseHeaders`를 **즉시** 클라이언트로 보낸다. 콜러블의 반환값과 무관하다
- 같은 파일 `send_response()` — `response` 훅 이후 헤더·본문 전송은 `if not already_streamed:`
  안에 있다. 스트리밍한 flow는 훅에서 응답을 바꿔도 다시 보내지 않는다
- `proxy/layers/http/_http1.py` — chunked 응답의 `ResponseData`를 `b"%x\r\n%s\r\n" % (len, data)`로
  직렬화한다. 빈 바이트는 `0\r\n\r\n`, 즉 **본문 종료**가 된다
- 같은 파일 — 프로토콜 오류(`body_size_limit` 초과 포함) 시 헤더가 아직 안 나갔을 때만 오류 응답을
  만든다. 버퍼링 경로에서 502가 깔끔하게 나오는 이유다

## 3. S1 적용

- 다운로드로 판별된 flow는 `stream`을 건드리지 않는다(버퍼링). 비다운로드만 `stream=True`
- `body_size_limit`을 건다. 값은 메모리 2.3배를 감안해 정한다 (예: 500MB → 최대 ~1.2GB)
- 해시는 `response` 훅에서 메모리의 본문으로 계산, `SubmitFile`도 메모리에서 청크로 보낸다
- **주의 — `body_size_limit`은 전역이고, 모든 훅보다 먼저 검사된다** (`proxy/layers/http/__init__.py`
  `check_body_size`가 `HttpRequestHeadersHook`·`HttpResponseHeadersHook` 앞에서 돈다). 결과:
  - 다운로드가 아닌 응답도 상한을 넘으면 502다 (`BODY_SIZE_LIMIT=1k`에서 4KB HTML이 502로 실측).
    500MB 상한이면 Content-Length가 500MB를 넘는 비다운로드(대용량 영상 등)가 깨진다
  - 요청 본문(업로드)도 같은 상한을 받는다 (4KB POST → 413 실측). 에이전트는 요청 본문을 보지 않으므로
    `requestheaders`에서 `flow.request.stream = True`로 흘려보낸다. Content-Length를 선언한 상한 초과
    업로드는 여전히 413이다
  - S3의 "N MB 초과 파일 정책"(`oversize_action = PASS/WARN`)은 이 구조로 표현할 수 없다. Content-Length가
    상한을 넘는 응답은 `responseheaders`가 불리기 전에 502로 끝나므로 에이전트가 PASS를 고를 기회가 없다.
    chunked도 상한에 닿는 순간 502다. **초과 = 차단**이 현재 구조의 유일한 동작이다
- **압축 인코딩(`Content-Encoding`)** — `flow.response.content`는 에이전트 안에서 압축을 푼다. 설계의
  "에이전트는 압축 해제를 하지 않는다"에 어긋나고, `body_size_limit`은 압축된 바이트만 세므로 폭탄에
  무방비다 (1MB gzip → 1GB 해제, RSS 94MB → 2.19GB 실측). S1은 `raw_content`만 쓰고 인코딩된 다운로드는
  정책 차단한다. 서버 격리 환경에서의 해제는 S2 계약 변경(`SubmitFileMetadata.content_encoding`) 안건이다

## 4. 팀 결정이 필요한 것 — S2 "메모리에 전부 올리지 않음"

| 안 | 내용 | 비용 |
|---|---|---|
| **A. 버퍼링 유지 + 상한** | S2 목표를 "상한 내 버퍼링"으로 바꾼다. 스풀은 버퍼를 디스크로 옮기는 용도가 아니라 필요 없어진다 | 메모리 = 본문 × 2.3. 상한 초과 대용량(설치 파일 수 GB)은 차단 |
| B. mitmproxy HTTP 레이어 확장 | 헤더 전송을 미루고 본문을 스풀로 받는 커스텀 레이어 | mitmproxy 내부 API 의존, 버전 고정 필요, 구현·검증 비용 큼 |
| C. 헤더 먼저, 본문 보류, 차단은 연결 끊기 | 200 헤더는 보내고 본문은 판정까지 안 보낸다. 차단 = 연결 리셋 | 설계의 "헤더 전 보류" 원칙과 403 UX를 포기. chunked는 별도 처리 필요. 브라우저별 부분 파일 처리 미검증 |

권장은 **A**다. 5주 안에 B를 안정화하기 어렵고, C는 설계 원칙을 바꾼다. A를 택하면 설계서 3장·7장의
"에이전트 측 스풀링"과 CLAUDE.md의 스풀 규칙 서술을 함께 고쳐야 한다(스풀 보호 규칙 자체는
B/C로 갈 여지를 위해 코드에 남겨둘 수 있다).

## 5. 미측정

- HTTPS 경로 (이번 질문은 HTTP 레이어 동작이라 평문으로 측정했다)
- Chrome 등 실제 브라우저 (curl만)
- `stream_large_bodies` 옵션 조합
- Windows (S4로 연기)

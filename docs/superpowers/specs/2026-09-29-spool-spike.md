# 헤더를 붙잡은 채 디스크로 스풀하기 (B안 스파이크)

- 날짜: 2026-09-29
- 목적: [`2026-09-26-header-timing.md`](2026-09-26-header-timing.md) 4장의 B안("mitmproxy HTTP 레이어 확장")이
  실제로 되는지 판정한다. A안(버퍼링 + 상한)으로는 상한을 넘는 파일을 받을 수 없다
- 환경: macOS 26.6.2 (arm64), RAM 16GB, mitmproxy 12.2.3, Python 3.12.14, 로컬 오리진(스로틀 없음),
  클라이언트 `curl -x`, 2GiB 무작위 파일, `body_size_limit=500m`, 판정 흉내 1초
- 코드: [`../spikes/2026-09-29-spool/`](../spikes/2026-09-29-spool/)

## 결론

1. **된다.** 헤더를 판정까지 붙잡으면서 본문은 디스크 스풀로 받고, 통과 시 스풀에서 내보낼 수 있다.
   2GiB 파일이 500MB 상한 아래에서 통과했고 **최대 RSS는 약 100MB**다(버퍼링은 2GB에 4.40GB)
2. **차단(403)과 헤더 전 보류는 그대로다.** 판정 전에는 헤더가 나가지 않고, 차단 시 403과 함께 스풀이 지워진다
3. **통과 후 방출에 역압이 걸린다.** 20MB/s로 받는 느린 클라이언트에서도 100초 내내 RSS가 56~101MB였다.
   HTTP/1과 HTTP/2 모두 확인했다
4. **대가는 mitmproxy 내부 패치다.** 공개 훅으로는 안 되며, `HttpStream` 메서드 5개와 `ConnectionHandler.wakeup`을
   바꾼다(약 250줄). mitmproxy 버전을 고정해야 한다
5. **스풀 보호 규칙은 다시 필수가 된다.** 스파이크에 UUID.tmp · `0600` · XOR · `.noindex` 디렉터리를 넣었고,
   보류 중 파일 첫 바이트가 원본과 다름(XOR)과 권한 `0o600`을 확인했다

→ S2의 "메모리에 전부 올리지 않음"은 **B안으로 달성 가능하다.** A안이 강제하던 "상한 초과 = 차단"과
"상한 초과 비다운로드도 502"가 함께 풀린다.

**팀 결정 (2026-09-29): S2는 A안(버퍼링 + 500MB 상한)을 유지하고, B안은 고도화 단계에서 도입한다.**
전환할 때 할 일은 3장이다.

## 1. 측정값

| 시나리오 | 프로토콜 | 응답 | 헤더 도착 | 전체 | 수신 | 체크섬 | 최대 RSS |
|---|---|---|---|---|---|---|---|
| 통과, Content-Length | HTTP/1.1 | 200 | 12.15s | 19.89s | 2GiB | 일치 | 84MB |
| 통과, chunked | HTTP/1.1 | 200 | 11.78s | 20.16s | 2GiB | 일치 | 85MB |
| 차단 | HTTP/1.1 | 403 | 11.96s | 11.96s | 17B | — | 50MB |
| 느린 클라이언트 (20MB/s) | HTTP/1.1 | 200 | 12.31s | 102.36s | 2GiB | 일치 | 56MB |
| 방출 중 클라이언트 끊김 | HTTP/1.1 | (중단) | 11.83s | 16.00s | 1.1GB | — | 95MB |
| 보류 중 클라이언트 끊김 | HTTP/1.1 | (중단) | — | 5.00s | 0 | — | 95MB |
| 비다운로드 2GiB (`video/mp4`) | HTTP/1.1 | 200 | 0.003s | 2.78s | 2GiB | 일치 | 58MB |
| 통과 | HTTP/2 (TLS) | 200 | 13.97s | 41.04s | 2GiB | 일치 | 98MB |
| 차단 | HTTP/2 (TLS) | 403 | 13.89s | 13.89s | 17B | — | 98MB |
| 느린 클라이언트 (20MB/s) | HTTP/2 (TLS) | 200 | 13.96s | 102.59s | 2GiB | 일치 | 101MB |
| 방출 중 클라이언트 끊김 | HTTP/2 (TLS) | (중단) | 13.87s | 18.00s | 327MB | — | 102MB |

- 모든 시나리오 뒤 스풀 디렉터리는 비어 있었고, 최종 코드에서 트레이스백은 0건이다
- **헤더 도착 = 수신 + 해시 + XOR + 디스크 쓰기 + 판정(1초)** 이다. XOR를 끄면 같은 통과가 4.81s였다.
  스파이크의 XOR(파이썬 정수 연산)가 수신 경로의 약 60%를 차지한다 — 제품에서는 더 빠른 구현이 필요하다
- 비다운로드 2GiB는 A안 구조에서 `body_size_limit`에 걸려 502였던 경우다. 이번에는 스트리밍으로 그대로 통과했다
- HTTP/2 방출은 약 80MB/s로 HTTP/1(약 280MB/s)보다 느리다. 로컬 측정이라 실제 회선에서는 병목이 아닐 수 있다

## 2. 무엇을 바꿨나 (mitmproxy 12.2.3 내부)

| 대상 | 원래 동작 | 패치 |
|---|---|---|
| `HttpStream.state_consume_response_body` | 청크를 `response_body_buf`(메모리)에 쌓는다 | 스풀 대상이면 청크를 XOR해 스풀 파일에 쓰고 SHA-256을 같이 계산 |
| `HttpStream.check_body_size` | 모든 훅보다 먼저 `body_size_limit`으로 502 | 응답 방향은 건너뜀. 응답 본문은 메모리에 쌓이지 않으므로(다운로드=스풀, 비다운로드=stream) 디스크 상한만 둔다 |
| `HttpStream.send_response` | `response` 훅 뒤 `raw_content`를 한 번에 전송 | 훅(판정) 뒤 통과면 헤더만 보내고 스풀에서 1MiB씩 방출, 차단이면 스풀 삭제 후 403 |
| `HttpStream._handle_event` | `Start`/`HttpEvent`만 받음 | 방출용 `Wakeup` 이벤트를 받아 다음 청크를 보냄. 취소 뒤 늦게 온 것은 버림 |
| `HttpStream.handle_protocol_error` | — | 보류·방출 중 연결이 끊기면 스풀 삭제 |
| `ConnectionHandler.wakeup` | 대기 후 바로 이벤트 전달 | 대기 후 `drain_writers()`로 역압을 건 뒤 이벤트 전달 |

역압이 핵심이다. mitmproxy는 **소켓을 읽는 사이에만** `drain()`한다(`server.py` `drain_writers`). 방출은 읽기 없이
이어지므로, 청크마다 `RequestWakeup(0)`을 내고 `wakeup`에서 `drain()`을 기다린 뒤 다음 청크를 보내게 했다.
이게 없으면 2GiB가 전송 버퍼에 한 번에 쌓인다.

## 3. 제품에 넣기 전에 남은 것

- **mitmproxy 버전 고정** — `platform-agent`의 `pyproject.toml`은 `mitmproxy>=12`다. `==12.2.3`으로 묶고,
  올릴 때마다 이 패치를 재검증한다
- **XOR 성능** — 스파이크 구현은 2GiB에 약 7초를 더한다. 청크 단위 벡터 연산 등으로 줄여야 한다
- **디스크 상한 초과 처리** — 스파이크는 예외만 던진다. 차단 응답(POLICY)으로 끝내는 경로가 필요하다
- **해시·업로드를 스풀에서** — 현재 `_decide`는 메모리 본문으로 해시·`SubmitFile`을 한다. 스풀 경로의 해시를 쓰고
  업로드는 스풀을 복호화하며 청크로 보내게 바꾼다
- **스풀 디렉터리 위치와 정리** — 에이전트 재시작 시 남은 `.tmp` 삭제, OS별 인덱싱 제외(macOS `.noindex`,
  Windows는 S4)
- **HTTP/2 업스트림** — 이번 HTTP/2는 클라이언트 쪽만이다(`connection_strategy=lazy`, 오리진은 HTTP/1).
  오리진도 HTTP/2인 경로는 미측정
- **실제 브라우저** — curl만 측정. Chrome으로 대용량 HTTPS 다운로드 확인 필요

## 4. 미측정

- Chrome 등 실제 브라우저, Windows
- HTTP/2 오리진, HTTP/3(설계상 비대응)
- 여러 대용량 다운로드 동시 진행 시 디스크 I/O와 이벤트 루프 지연
- Spotlight가 `.noindex` 디렉터리를 실제로 건너뛰는지(`mdfind`로 확인 필요)

## 재현

```bash
cd docs/superpowers/spikes/2026-09-29-spool
dd if=/dev/urandom of=big.bin bs=1m count=2048
python3 origin.py 18080 &
mitmdump -p 18081 -s spool_addon.py --set body_size_limit=500m & echo $! > mitm.pid
./run.sh allow-cl 'http://127.0.0.1:18080/dl/big.bin'
./run.sh block-cl 'http://127.0.0.1:18080/dl/big.bin?block=1'
./run.sh slow-20M --limit-rate 20M 'http://127.0.0.1:18080/dl/big.bin'
```

HTTP/2는 `openssl`로 자체 서명 인증서(`cert.pem`, `key.pem`)를 만들고 `python3 origin_tls.py 18443`,
mitmdump에 `--ssl-insecure --set connection_strategy=lazy`, curl에 `--http2 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem`.

# 다운로드 검사 단계별 소요 시간 측정 계획

> 목적: 고도화에 앞서 **어느 단계가 실제로 오래 걸리는지** 숫자로 확인한다. 측정 결과로 다음에 손댈 단계를 정한다.
> 기준 코드: 서버 PR #93 (`feat/checkhash-tlsh-prefilter`), 에이전트 PR #11 (`feat/checkhash-tlsh`)
> 흐름도: https://app.notion.com/p/418222a2bedf80c8a122de75561ca6f2

## 1. 결론 먼저

- 지금은 **단계별 시간을 따로 볼 수 없다.** 남는 숫자는 세 가지뿐이다.
  - `download_events.hold_duration_ms`: 보류 전체 시간. 원본 서버에서 본문을 받는 시간까지 섞여 있다.
  - `analyses.duration_ms`: YARA 매칭 시간만.
  - Prometheus의 JVM·HTTP 기본 지표.
- 그래서 측정 전에 **계측(타이머) 추가 → 벤치마크 환경 → 시나리오 실행 → 집계** 순서가 필요하다.
- 큰 파일과 대량 corpus 조건에서 시간이 클 것으로 예상되는 후보는 다섯 가지다(아래 4절). 측정으로 확인해야 한다.
  - 에이전트 해시 계산
  - 업로드 전송
  - YARA
  - TLSH corpus 선형 비교
  - 차단 시 S3 격리 업로드

## 2. 실제 단계 순서 (측정 대상)

흐름도의 "블룸 → SHA-256 → TLSH → YARA"를 코드 기준으로 펼치면 아래 순서다. SHA-256은 블룸보다 **먼저** 에이전트에서 계산된다.

| # | 위치 | 단계 | 지금 측정되는가 |
|---|---|---|---|
| A0 | 에이전트 | 응답 헤더 수신 → 보류 시작 (`held_at`) | 시작 시각만 |
| A1 | 에이전트 | 원본 서버에서 본문 전체 수신(버퍼링) | ❌ (hold 시간에 섞임) |
| A2 | 에이전트 | SHA-256 + TLSH 계산 (`asyncio.gather`로 동시) | ❌ |
| A3 | 에이전트→서버 | CheckHash RPC 왕복 | ❌ |
| S1 | 서버 CheckHash | event 잠금·근거 행 생성 (`evidence.claim`, tlsh+event_id 있을 때) | ❌ |
| S2 | 서버 CheckHash | corpus try-lock | ❌ |
| S3 | 서버 CheckHash | 블룸 조회 (Redis) | ❌ |
| S4 | 서버 CheckHash | 화이트·블랙리스트·판정 캐시 조회 (Postgres) | ❌ |
| S5 | 서버 CheckHash | TLSH 비교 (`compareClaimed`, corpus 전체 선형 비교) + 근거 저장 | ❌ |
| A4 | 에이전트→서버 | SubmitFile 업로드 (gRPC 스트림, 본문 전체) | `bytes_uploaded`만 |
| S6 | 서버 SubmitFile | 스풀 쓰기 + SHA 재검증 | ❌ |
| S7 | 서버 SubmitFile | 서버 TLSH 계산·저장 (`recordFileFingerprint`) | ❌ |
| S8 | 서버 SubmitFile | 판정 캐시 확인 | ❌ |
| S9 | 서버→엔진 | 엔진 호출 (YARA) | `analyses.duration_ms` = 매칭 시간만 (전송·대기 제외) |
| S10 | 서버 SubmitFile | 결과 저장 + 검증된 TLSH 백스톱 비교 | ❌ |
| S11 | 서버 SubmitFile | **차단일 때 S3 격리 업로드 (응답 전에 동기 실행)** | ❌ |
| A5 | 에이전트 | 403 또는 보류 해제 | 끝 시각만 |
| A6 | 에이전트→서버 | ReportEvent (판정 뒤, 보류 시간 밖) | 해당 없음 |

경로는 네 가지로 나뉜다. 각각 따로 집계해야 한다.

- **P1 CheckHash에서 결정**: 화이트·블랙리스트, 캐시, TLSH 차단
- **P2 업로드 후 통과**: 처음 보는 정상 파일
- **P3 업로드 후 차단**: YARA 또는 백스톱 TLSH. S11 격리 업로드가 포함된다
- **P4 fail-close**: 시간 초과, 오류

## 3. 필요한 세팅

### 3.0 전체 그림: 재고, 모으고, 본다

> 타이머 추가 → 수집 → 보기. 서버는 Prometheus → Grafana로 보고, 에이전트와 엔진은 각자 다른 길로 모은다.

| 어디서 | 무엇으로 재나 | 어떻게 모으나 | 어디서 보나 |
|---|---|---|---|
| 서버 (api-server) | Micrometer 단계별 `Timer` (3.1에서 추가) | Prometheus가 `/actuator/prometheus`를 15초마다 긁는다 (이미 설정됨) | Grafana (Prometheus 데이터소스) |
| 탐지 엔진 | 이미 있는 `duration_ms` (YARA 매칭) | DB `analyses` 테이블에 저장됨 | SQL, 또는 Grafana에 Postgres 데이터소스를 추가 |
| 에이전트 | 단계별 구조화 로그 한 줄 (3.1에서 추가) | **Prometheus로 못 긁는다** (각 PC 프로세스). 벤치 하네스가 로그 파일을 수집한다 | 하네스가 집계한 CSV/표. 나중에 필요하면 `ReportEvent`에 단계 시간 필드를 넣어 서버 DB로 보낸다 |
| 끝에서 끝 | `download_events.hold_duration_ms` | DB | SQL, Grafana Postgres 패널 |

**Grafana는 지금 스택에 없다.** compose에는 Prometheus(9091)만 있다. 벤치 compose override에 다음을 추가한다.
- `grafana/grafana` 컨테이너
- 데이터소스 프로비저닝: Prometheus(`http://prometheus:9090`), Postgres(읽기 전용 계정)
- 대시보드 JSON 하나: 단계별 p50/p95/p99, 경로별 처리량, fail-close 비율, corpus 크기

운영 스택에 Grafana를 둘지는 측정 뒤 따로 정한다. 대시보드 없이도 Prometheus 웹 UI(9091)에서 5절 쿼리를 돌리면 숫자는 볼 수 있다.

### 3.1 계측 추가 (코드 변경, 측정 전용 PR 1개)

**서버 (api-server)**
- Micrometer `Timer`로 단계별 시간을 남긴다. Prometheus 노출은 이미 켜져 있다(`/actuator/prometheus`, compose의 prometheus 9091).
  - `verdict.checkhash.stage{stage=claim|corpus_lock|bloom|lists|cache|tlsh_compare|tlsh_save}`
  - `verdict.submit.stage{stage=receive|spool_verify|fingerprint|cache|engine|persist|similarity|quarantine}`
  - `verdict.checkhash.total{decision,source}`, `verdict.submit.total{decision,source}`
- 퍼센타일 히스토그램을 켠다: `management.metrics.distribution.percentiles-histogram.verdict=true`
- 크기 구간 태그를 붙인다: `size_bucket=lt1m|1-10m|10-100m|gt100m`. 파일 크기를 그대로 태그로 쓰지 않는다(카디널리티 폭발).
- TLSH 비교에는 corpus 크기를 게이지로 남긴다: `verdict.similarity.corpus.size`
- gRPC 서버 기본 지표(`grpc.server.*`)가 이미 나오는지 `/actuator/prometheus`에서 확인한다. 안 나오면 spring-grpc observation 인터셉터를 켠다.
- 로그 MDC에 `event_id`를 넣어 에이전트 로그와 이어 붙일 수 있게 한다.

**탐지 엔진 (detection-engine)**
- 이미 `duration_ms`(YARA 매칭)를 돌려준다. 서버 쪽 S9 타이머(호출 전체)와 빼면 전송·대기 시간이 나온다. 엔진 변경은 필요 없다.

**에이전트**
- Prometheus로 긁어갈 수 없는 PC 프로세스다. 그래서 측정 단계에서는 **구조화 로그 한 줄**로 남긴다.
  - `event_id, size, t_body_received, t_hash_done(sha), t_tlsh_done, t_checkhash_rtt, t_submit_rtt, outcome`
- 벤치마크 하네스가 이 로그를 수집한다.
- 운영에서도 보고 싶어지면 `ReportEventRequest`에 단계 시간 필드를 추가한다. 이건 proto 변경이라 측정 결과를 본 뒤 결정한다.
- `hold_duration_ms`는 원본 다운로드 시간(A1)을 포함한다. 검사 시간만 보려면 **본문 수신 완료 시각**을 따로 남겨야 한다. 이게 가장 중요한 추가 지점이다.

### 3.2 벤치마크 환경

- 개발 스택(`platform`, `platform-agent` compose 프로젝트와 볼륨)을 건드리지 않는다.
  - 별도 프로젝트 이름으로 띄운다: `docker compose -p bench-server ...`, `-p bench-agent ...`
  - 끝나면 그 프로젝트만 `down -v` 한다.
  - Task 7 e2e에서 쓴 방식과 같다.
- 포트 충돌은 scratch override 파일로 푼다. 서버 API 8080과 에이전트 프록시 8080이 겹친다.
- **자원 고정**: 컨테이너에 `cpus`, `mem_limit`를 명시한다(예: api 2 CPU / 2GB, 엔진 2 CPU / 2GB, postgres 1 CPU). 결과 표에 호스트 사양(칩, 코어, 메모리, Docker Desktop 자원)을 함께 적는다.
- **원본 서버**: 로컬 HTTP 서버로 파일을 내려준다(`Content-Disposition: attachment`). 네트워크 변수를 없애기 위해서다. A1은 별도로 잰다.
- 실행마다 같은 조건을 만든다: 블룸 재구축 → 캐시 비우기(cold) 또는 미리 채우기(warm) → 워밍업 20회 → 본 측정.

### 3.3 테스트 데이터

> 빈 DB로 재면 블룸, 목록 조회, TLSH 비교, YARA가 모두 실제보다 빠르게 나온다. **실제 규모의 블랙리스트, TLSH 지문, YARA 룰셋을 DB에 넣고 잰다.** 출처와 넣는 방법은 [실제 데이터 세팅](2026-11-16-realistic-test-data.md)에 정리했다.
> 아래 합성 데이터는 규모를 통제해야 하는 실험(corpus 1k/10k/100k 등)에 쓴다.

- **파일 크기 구간**: 10KB, 1MB, 10MB, 100MB, 500MB (`body_size_limit` 상한)
- **파일 종류**: 무작위 바이트, 텍스트, PE 형태(무해한 빌드 산출물 예: hello.exe), zip. YARA 비용은 내용에 따라 달라진다.
- **corpus 규모**(TLSH 선형 비교 비용 확인용)
  - 악성 지문 1k / 10k / 100k건
  - 무작위 데이터로 만든 지문을 관리자 지문 가져오기 API로 넣는다
  - `ParsedSimilarityCorpus` 캐시 상한 8192를 넘는 구간이 꼭 들어가야 한다
- **YARA 룰셋 규모**: 지금 룰셋, 그리고 룰 수를 10배로 늘린 룰셋
- **변종**: 기준 파일에 공백 64바이트를 붙인 것(거리 약 14~17, 차단), 거리 31~70 변종(경고)

### 3.4 부하 도구

| 목적 | 도구 | 비고 |
|---|---|---|
| 프록시를 거친 끝에서 끝 지연 | `curl -x` 반복 스크립트 또는 k6(HTTP proxy 설정) | A1~A5 전체 |
| 서버만 따로 | `ghz`로 CheckHash/SubmitFile 직접 호출 | 에이전트 변수 제거. 에이전트 토큰 필요 |
| 에이전트 해시만 따로 | pytest 벤치(`HeldBody.sha256()`, `.tlsh()`) | 크기별 A2 |
| 집계 | Prometheus 쿼리 + Postgres SQL | 아래 5절 |

## 4. 시나리오와 보고 싶은 것

| ID | 시나리오 | 동시성 | 보는 단계 | 확인할 질문 |
|---|---|---|---|---|
| M1 | 화이트리스트 해시 (P1) | 1, 8 | A2, A3, S1~S4 | 가장 가벼운 경로의 바닥 지연. 이제 CheckHash마다 DB 쓰기(S1)가 생겼는데 비용이 얼마인가 |
| M2 | 캐시 CLEAN 히트 (P1) | 1, 8 | 위와 같음 | M1과 차이 |
| M3 | TLSH 차단 변종 (P1) | 1, 8 | S5 | corpus 1k/10k/100k에서 선형 비교 시간. 8192 캐시 경계 전후 |
| M4 | 처음 보는 정상 파일 (P2) | 1, 4, 16 | A2, A4, S6~S10 | 크기별로 업로드, 서버 TLSH, YARA 중 어디가 큰가 |
| M5 | YARA 차단 (P3) | 1, 4 | S9, S11 | 동기 S3 격리 업로드가 차단 응답을 얼마나 늦추는가 |
| M6 | 큰 파일 (500MB) | 1, 2 | A1, A2, A4, S7, S9 | 보류 120초 안에 끝나는가. TLSH 4~6초(측정됨)와 SHA-256 비교 |
| M7 | 혼합 부하 (P1 70% / P2 25% / P3 5%) | 16 | 전체 | p95·p99, fail-close 비율, DB 커넥션과 잠금 대기 |
| M8 | Redis 장애 중 | 4 | S3 | 블룸 실패 폴백 경로의 지연 |

**이미 알고 있는 숫자** (8KB 파일, 2026-11-16 e2e, 로컬 맥, 자원 미고정이라 참고용):

| 경로 | 지연 |
|---|---|
| TLSH 차단(P1) 보류 | 첫 요청 72ms, 이후 12~14ms |
| 업로드 후 통과(P2) | 첫 요청 211ms, 이후 35~37ms |
| 백스톱 차단(구버전 에이전트) | 103ms |
| 에이전트 TLSH 계산(500MB) | 4~6초 |

## 5. 집계 방법

**Prometheus** (계측 PR 이후)
```promql
# 단계별 p95 (경로·크기 구간별)
histogram_quantile(0.95, sum by (le, stage, size_bucket) (rate(verdict_submit_stage_seconds_bucket[5m])))
histogram_quantile(0.95, sum by (le, stage) (rate(verdict_checkhash_stage_seconds_bucket[5m])))
```

**Postgres** (지금 바로 가능한 것)
```sql
-- 경로별 보류 시간 (A1 포함이라 상한값으로만 본다)
SELECT decision, decision_source, (bytes_uploaded > 0) AS uploaded,
       percentile_cont(ARRAY[0.5,0.95,0.99]) WITHIN GROUP (ORDER BY hold_duration_ms) AS p50_p95_p99,
       count(*)
FROM download_events WHERE held_at > now() - interval '1 hour'
GROUP BY 1,2,3;

-- YARA 매칭 시간 (크기 구간별)
SELECT width_bucket(fv.file_size, ARRAY[1048576, 10485760, 104857600]) AS size_bucket,
       percentile_cont(ARRAY[0.5,0.95]) WITHIN GROUP (ORDER BY a.duration_ms), count(*)
FROM analyses a JOIN file_verdicts fv USING (sha256)
GROUP BY 1;
```
컬럼 이름은 실행 전에 스키마(V1, V9~V14)와 대조한다.

**결과 표** (시나리오마다 하나씩)

| 시나리오 | 크기 | 동시성 | 전체 p50/p95/p99 | 가장 큰 단계 | 그 단계 비중 | 비고 |
|---|---|---|---|---|---|---|

판단 기준: 전체 p95의 **30% 이상**을 차지하는 단계를 고도화 후보로 올린다. 크기가 커질 때 기울기가 가장 큰 단계도 후보로 올린다.

## 6. 측정 뒤 이어질 수 있는 고도화 (측정 결과로 고른다)

| 단계 | 의심 | 후보 |
|---|---|---|
| S5 TLSH 비교 | corpus에 비례해 선형으로 증가 | 파일 길이 범위로 후보 먼저 거르기, VP-tree 같은 거리 인덱스 (노션 "다음 2주" 항목) |
| A1+A2 | 본문을 다 받은 뒤에야 해시를 시작 | 수신과 동시에 스트리밍으로 SHA-256·TLSH 갱신 |
| S7 | 서버가 TLSH를 다시 계산 | 에이전트 주장 TLSH와 같으면 생략하거나 비동기로 |
| S11 | 차단 응답 전에 S3 업로드를 동기로 실행 | 판정을 먼저 돌려주고 격리는 비동기로 (격리 실패 처리 정책 필요) |
| S1 | 근거 행 생성 때문에 모든 CheckHash가 DB에 씀 | TLSH 비교 대상일 때만 claim |
| S9 | 엔진 직렬 처리, 큰 파일 | 엔진 동시성과 타임아웃 조정, 룰 정리 |

## 7. 할 일 순서

0. [ ] 실제 데이터 세팅 ([실제 데이터 세팅](2026-11-16-realistic-test-data.md)): MalwareBazaar 해시·TLSH, 오픈소스 YARA 룰셋 적재
1. [ ] 계측 PR
   - 서버 Micrometer 단계 타이머, 퍼센타일, 크기 구간 태그, MDC `event_id`
   - 에이전트 단계 로그(본문 수신 완료 시각 포함)
2. [ ] 벤치 스크립트 (`bench/` 또는 scratch)
   - compose override(별도 프로젝트 이름, 자원 고정, 포트, Grafana + 데이터소스·대시보드 프로비저닝)
   - 테스트 파일 생성기, corpus 시드 스크립트
   - 시나리오 실행기, 결과 수집
3. [ ] M1~M8 실행. 시나리오마다 워밍업 후 최소 5회 반복
4. [ ] 결과 표와 판단을 `docs/advancement/`에 `YYYY-MM-DD-pipeline-latency-results.md`로 저장
5. [ ] 후보 단계 1~2개를 골라 고도화 설계로 넘어간다

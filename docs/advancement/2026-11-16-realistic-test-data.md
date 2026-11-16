# 측정용 실제 데이터 세팅

> [측정 계획](2026-11-16-pipeline-latency-measurement.md)의 0단계.
> 지금 DB는 거의 비어 있다. 그래서 블룸, 목록 조회, TLSH 비교, YARA가 모두 실제보다 빠르게 나온다.
> 공개 위협 데이터(MalwareBazaar)와 오픈소스 YARA 룰을 **벤치 DB에 실제 규모로** 넣은 뒤 측정한다.

## 1. 결론 먼저

- **1단계 (지연 측정): 해시·TLSH 메타데이터와 룰만 넣는다.** 악성 바이너리 파일은 받지 않는다.
  - 블랙리스트와 TLSH 지문은 MalwareBazaar의 해시와 TLSH 값으로 채운다.
  - YARA는 YARA Forge 룰셋을 올린다.
  - 업로드·YARA로 흘려보낼 파일은 정상 파일(오픈소스 설치 파일 등)이면 충분하다. YARA 시간은 "룰 수 × 파일 크기"에 좌우되고, 매칭 여부와는 크게 상관없다.
- **2단계 (탐지 품질 측정, 노션 "다음 2주"): 실제 샘플이 필요하다.** 격리 환경 규칙(5절)을 지킬 때만 진행한다.
- **지금 코드에 걸리는 제약이 세 가지 있다.**
  - 룰셋 업로드 **1MB 상한** → platform-server#94에서 32MiB(설정값)로 올림
  - 블룸 `expected-hash-count` 기본값 100,000
  - 대량 적재 경로 없음 (API는 한 건씩)

## 2. 넣을 데이터

| 데이터 | 출처 | 우리 테이블 | 규모 목표 | 비고 |
|---|---|---|---|---|
| 악성 SHA-256 | MalwareBazaar 전체 덤프 또는 최근 CSV ([export](https://bazaar.abuse.ch/export/)) | `hash_blacklist` | 10만 ~ 전체 | 전체 덤프는 1시간마다 갱신되고, CSV 내보내기는 로그인과 Auth-Key가 필요하다 |
| 악성 TLSH | MalwareBazaar 샘플 메타데이터의 `tlsh` ([API](https://bazaar.abuse.ch/api/)) | `file_fingerprints` (가져오기 API) | 블랙리스트 중 TLSH가 있는 것 전부 | CSV에 `tlsh` 열이 있는지는 로그인 후 export 페이지에서 확인해야 한다(아직 확인 못 함). 없으면 API로 샘플별 조회 |
| YARA 룰 | [YARA Forge](https://yarahq.github.io) core(약 5천 개) / extended(약 1.07만) / full(약 1.24만) ([releases](https://github.com/YARAHQ/yara-forge/releases)) | `rulesets`, `yara_rules` | core부터 시작, full까지 | 라이선스는 룰마다 다르다. core 기준 CC BY-SA 4.0(1,621개), DRL 1.1(377개), Volexity, BSD 2-Clause, Apache 2.0이 섞여 있고 나머지는 license 메타데이터가 없다(Elastic 룰은 들어 있지 않음). 내부 측정용은 괜찮지만 제품에 넣어 배포하기 전에는 확인해야 한다 |
| 정상 파일 (업로드·YARA 부하용) | 오픈소스 설치 파일·아카이브 (예: Python, Node.js, 7-Zip, Git 설치 파일, Linux 패키지) | 업로드 대상(파일) | 크기 구간별 5개 이상 | 실제 PE·압축 구조라 YARA 비용이 무작위 바이트와 다르다 |
| 정상 해시 (화이트리스트) | NIST NSRL RDS 일부, 또는 위 정상 파일의 해시 | `hash_whitelist` | 수천 ~ 수만 | 화이트리스트 조회 비용과 블룸 크기를 현실적으로 맞추기 위해 |

**TLSH 비교 대상(corpus) = 활성 블랙리스트 SHA-256 중 TLSH 지문이 있는 것**이다(서버 `CLAUDE.md`). 그래서 블랙리스트와 지문을 **둘 다** 넣어야 한다. 하나만 넣으면 corpus가 비어 TLSH 단계가 공짜로 보인다.

## 3. 지금 코드에서 막히는 곳과 대응

| 제약 | 위치 | 영향 | 대응 |
|---|---|---|---|
| ~~룰셋 업로드 1MB 상한~~ (해결) | 콘솔·nginx·multipart·UseCase·엔진·gRPC·호출 시간 제한 7개 층 | core 7.7MB도 못 올렸다 | platform-server#94: 32MiB 설정값(`ruleset.max-source-bytes`, 엔진 `ENGINE_MAX_RULES_BYTES`), 엔진 호출 시간 제한 60초 |
| 단일 `.yar` 파일만 | 룰셋 업로드 | `include`를 쓰는 룰 저장소는 그대로 못 올린다 | YARA Forge 패키지는 이미 한 파일로 합쳐져 있어 문제없을 것. 다른 저장소는 하나로 합친다 |
| YARA 모듈 지원 | 엔진 `yara-python>=4.5` | 룰이 `pe`, `math`, `hash`, `dotnet`, `magic` 같은 모듈을 쓰면 엔진 빌드에 그 모듈이 있어야 컴파일된다 | 올리기 전에 엔진 컨테이너에서 `yara.compile()`로 컴파일되는지 먼저 확인한다. 실패한 룰 목록과 컴파일 시간도 기록한다 |
| 블룸 크기 | `lookup.bloom-filter.expected-hash-count` (기본 100,000) | 해시를 그 이상 넣으면 오탐률이 설정값보다 올라간다. 오탐은 안전한 쪽이지만 DB 조회가 늘어 측정값이 왜곡된다 | 벤치 설정에서 실제 적재 수에 맞춘다. 운영값도 이 결과를 보고 정한다 |
| 한 건씩 넣는 API | `POST /api/admin/blacklist`, `/api/admin/file-fingerprints/import` | 10만 건이면 감사 로그 10만 행, 시간도 오래 걸린다 | 아래 4절 |
| 지문 가져오기 형식 | `FingerprintImportController` (`(T1)?[0-9A-F]{70}`) | MalwareBazaar TLSH는 `T1` 접두가 있는 대문자 70자리라 그대로 맞을 것 | 적재 스크립트에서 형식을 검증하고 맞지 않는 줄은 건너뛰며 개수를 센다 |

## 4. 넣는 방법

로컬에서는 벤치 전용 compose 프로젝트(`-p bench-server`)의 DB에만 넣는다. 개발 DB(`platform`)에는 넣지 않는다. 운영 EC2에서 잴 때는 4.1절을 따른다.

1. **소량(1만 건 이하): 관리 API로 넣는다.** 운영과 같은 경로라 블룸 즉시 반영, 감사 로그, 잠금이 모두 실제처럼 동작한다.
2. **대량(10만 건 이상): 벤치 DB에 SQL `COPY`로 넣고 블룸을 재구축한다.**
   - 빠르지만 감사 로그, 블룸 즉시 반영, corpus 토큰 갱신 같은 앱 쪽 불변식을 건너뛴다.
   - 그래서 넣은 뒤 반드시 블룸 재구축(서버 재시작이나 재구축 스케줄 대기)과 corpus 캐시 무효화를 확인한다.
   - **벤치 DB에서만** 쓴다.
   - 나중에 운영에서도 대량 가져오기가 필요하면 그때 정식 배치 API를 만든다. 예전 `feat/blacklist-import-script` 브랜치가 있었으니 먼저 확인한다.
3. **YARA 룰셋**: 관리 API(`POST /api/admin/rulesets` → `/activate`)로 올린다. 올린 뒤 엔진 로그에서 컴파일 시간과 실패 룰을 확인한다.
4. **적재 기록**을 남긴다. 측정 결과 문서 머리에 그대로 붙인다.
   - 덤프 날짜
   - 블랙리스트 수, TLSH 지문 수, corpus 수
   - 룰셋 이름·버전·룰 수·파일 크기
   - 화이트리스트 수

적재 스크립트는 `bench/seed/`에 둔다. Auth-Key는 환경변수로만 받고 레포에 넣지 않는다. 내려받은 덤프와 룰 파일도 레포에 커밋하지 않는다. 라이선스와 용량 때문이다.

## 4.1 운영 EC2에서 측정할 때

운영도 EC2 한 대에서 `docker compose`로 돈다. 배포 설정은 `deploy.yml`이고, `compose.yml` + `compose.temp-db.yml` + `compose.prod.yml`을 쓴다. **Postgres도 같은 EC2 안의 컨테이너다**(RDS 아님).

로컬 벤치와 구성이 같고 하드웨어만 다르다. 그래서 아직 운영 중이 아닌 지금은 **운영 EC2에서 재는 숫자가 실제 서비스 성능에 가장 가깝다.** 다만 공유 서버라 아래 조건을 지킨다.

**데이터 구분**

| 데이터 | 처리 |
|---|---|
| 블랙리스트 해시, TLSH 지문, YARA 룰, 화이트리스트 | 관리 API(대량이면 정식 배치 가져오기)로 넣고 **측정 뒤에도 남긴다.** 운영에 있어야 할 데이터다 |
| 부하 테스트로 생기는 데이터: `download_events`, `analyses`, `similarity_assessments`, `event_decision_evidence`, 감사 로그, 격리 S3 객체 | 측정 뒤 **정리 스크립트로 지운다** |

**측정 전**

1. **팀에 공유한다.** 측정 시간대를 알리고, 그동안 데모·개발 사용을 피한다.
2. **PR #93(서버)과 #11(에이전트)이 머지·배포된 상태인지 확인한다.** 새 흐름이 배포돼 있어야 의미가 있다.
3. **되돌릴 지점을 만든다.** 둘 중 하나를 쓴다.
   - `docker compose ... exec postgres pg_dump -Fc` 로 DB를 덤프해 EC2 밖에 보관한다.
   - EC2 EBS 볼륨 스냅샷을 찍는다.
4. **디스크 여유 공간을 확인한다**(`df -h`, `docker system df`).
   - 해시 적재, 업로드 스풀(`engine-spool`), 격리 파일, Prometheus 데이터가 모두 같은 디스크에 쌓인다.
   - 측정 중 디스크가 차면 운영 DB까지 멈춘다. 측정 데이터 예상량의 2배 이상 여유가 있을 때만 진행한다.
5. **Slack 알림을 끈다.** 차단 시나리오가 수천 번 돌면 팀 채널에 그만큼 알림이 간다. 설정값으로 끌 수 없으면 측정 동안 웹훅 URL을 비운다.
6. **테스트 전용 에이전트를 등록한다.** 등록 토큰을 따로 발급한다. 이 `agent_id`가 정리 스크립트의 기준이다.
7. **블룸 기대 개수를 실제 적재 수에 맞춘다**(`lookup.bloom-filter.expected-hash-count`).
8. **EC2 정보를 기록한다.** 인스턴스 타입, vCPU, 메모리, 디스크 종류를 결과 문서에 남긴다.

**측정 중**

- **부하 도구(k6, ghz, 테스트 에이전트)는 EC2 밖에서 돌린다.**
  - 같은 EC2에서 돌리면 서버와 CPU를 나눠 써서 숫자가 틀어진다.
  - 밖에서 보내면 네트워크 왕복이 섞이지만, 서버 단계별 타이머로 분리된다.
  - 가능하면 같은 리전의 별도 EC2에서, 아니면 로컬 맥에서 돌리고 RTT를 따로 기록한다.
- **자원 경쟁도 측정 대상이다.** api, 엔진, Postgres, Redis가 한 EC2의 CPU·메모리를 나눠 쓴다.
  - YARA가 CPU를 잡는 동안 CheckHash(Postgres·Redis)가 느려지는지 M7 혼합 부하에서 본다.
  - `docker stats`를 같은 시간대로 기록한다.
- **엔진 자원 제한을 확인한다.** 운영 compose에는 `mem_limit: 1g`, `cpus: 1.0`이 걸려 있다. 측정 결과는 이 제한 아래의 숫자다.

**측정 뒤**

1. **정리 스크립트를 돌린다.** 테스트 `agent_id` 기준으로 지운다.
   - 이벤트, 근거, 분석, 평가 행
   - 격리 S3 객체와 `quarantine_files` 행
   - 측정 기간의 감사 로그
   - 외래 키 순서를 지켜 한 트랜잭션에서 지운다. 지우기 전에 지울 건수를 먼저 출력해서 확인한다.
2. **Slack 알림을 되돌린다.**
3. **결과를 확인한다.** 대시보드 숫자가 측정 전 수준으로 돌아왔는지 본다.
4. **덤프·스냅샷은 결과 확인이 끝날 때까지 보관한다.** 그 뒤에 지운다.

## 5. 실제 샘플을 쓸 때 (2단계, 탐지 품질 측정)

지연 측정에는 필요 없다. 탐지율을 재려면 실제 샘플이 있어야 한다. 그때는 아래를 지킨다.

- **격리된 환경에서만 다룬다.**
  - 리눅스 VM이나 전용 컨테이너를 쓴다. 맥 호스트의 작업 폴더에서 풀지 않는다.
  - 받은 파일은 MalwareBazaar 기본 형식(암호 zip)대로 보관하고, 검사 직전에 격리 환경 안에서만 푼다.
- **실행하지 않는다.** 우리 파이프라인은 바이트를 해시하고 YARA로 읽기만 한다. 엔진은 이미 내부 네트워크(`engine-net`)에만 붙어 있다.
- **호스트 백신이 격리하거나 지울 수 있다.** 그건 정상 동작이니 백신을 끄지 말고, 격리 환경 안에서 작업한다.
- **다 쓰면 지운다.** 벤치 볼륨을 `down -v`로 지운다. 격리 S3(localstack)에 올라간 사본도 함께 지운다.
- **샘플 수와 종류를 기록한다.** 패밀리, 파일 형식, 수집 날짜를 남겨 탐지율을 해석할 수 있게 한다.
- **변종 탐지율**은 노션 계획대로 직접 만든 변종(공백 붙이기, 일부 바이트 수정)으로 잰다. 원본 샘플을 다시 패킹하는 작업은 하지 않는다.

## 5.1 YARA Forge 확인 결과 (2026-11-16, 릴리스 `20261115`)

엔진과 같은 조건(yara-python 4.5.4, 메모리 1GiB / CPU 1개)에서 잰 값이다.

| 패키지 | 파일 크기 | 룰 수 | 필요한 모듈 | 컴파일 | 최대 메모리 | 27MB PE 매칭 | 6.6MB ELF 매칭 |
|---|---|---|---|---|---|---|---|
| core | 7.7MB | 5,089 | `pe`, `dotnet`, `hash` | 1.2초 | 92MB | 0.43초 | 0.08초 |
| extended | 17.5MB | 10,849 | + `math`, `string` | 2.7초 | 214MB | - | - |
| full | 19.4MB | 11,852 | + `elf`, `console` | 3.9초 | 276MB | 0.66초 | 0.17초 |

- 정상 파일(Python 3.12.8 Windows 설치 파일, `libpython3.12.so`)에서는 어느 패키지도 오탐을 내지 않았다.
- 실제 스택에서 nginx를 거쳐 올린 결과 (platform-server#94 확인)

| 패키지 | 업로드 | 활성화 | 엔진 메모리 |
|---|---|---|---|
| core | 201, 3.5초 | 200, 1.8초 | 최대 224MiB |
| full | 201, 7.7초 | 200, 5.3초 | 최대 392MiB, 평상시 303MiB (제한 1GiB) |

## 6. 할 일

1. [ ] abuse.ch Auth-Key 발급 (팀 계정 또는 개인). export 페이지에서 CSV 열 구성(`tlsh` 포함 여부)을 확인한다
2. [x] YARA Forge core·extended·full을 내려받아 파일 크기, 룰 수, 필요한 모듈을 확인한다. 엔진 컨테이너에서 컴파일을 시험한다 (5.1절)
3. [x] 업로드 상한: platform-server#94로 32MiB. 블룸 기대 개수는 이미 설정값이라 적재 수를 본 뒤 환경변수로 맞춘다
4. [ ] `bench/seed/` 적재 스크립트 작성: API 경로(소량)와 COPY 경로(대량). 2026-10-27에 만든 MalwareBazaar 해시 적재 스크립트(`import_malwarebazaar.py`, 커밋 안 됨, 로컬 백업)를 출발점으로 TLSH 지문 적재를 더한다
5. [ ] 정상 파일 세트 준비: 크기 구간별 오픈소스 설치 파일, 그리고 해시 목록
6. [ ] 운영 EC2에서 잴지 정한다(팀 합의). 잰다면 4.1절의 측정 전 체크리스트, 정리 스크립트를 준비한다
7. [ ] 적재 → 블룸 재구축 → 적재 기록 작성 → [측정 계획](2026-11-16-pipeline-latency-measurement.md) 1단계(계측)로 넘어간다

## 출처

- MalwareBazaar export: https://bazaar.abuse.ch/export/
- MalwareBazaar API: https://bazaar.abuse.ch/api/
- MalwareBazaar FAQ: https://bazaar.abuse.ch/faq/
- YARA Forge: https://yarahq.github.io , https://github.com/YARAHQ/yara-forge/releases
- YARA Forge 소개 (패키지 구성): https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab
- Nextron (Elastic 룰 라이선스 관련): https://www.nextron-systems.com/2025/04/30/yara-forge-rule-sets-now-available-in-thor-cloud-and-thor-cloud-lite/

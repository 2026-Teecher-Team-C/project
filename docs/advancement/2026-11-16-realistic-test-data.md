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
  - 룰셋 업로드 **1MB 상한**
  - 블룸 `expected-hash-count` 기본값 100,000
  - 대량 적재 경로 없음 (API는 한 건씩)

## 2. 넣을 데이터

| 데이터 | 출처 | 우리 테이블 | 규모 목표 | 비고 |
|---|---|---|---|---|
| 악성 SHA-256 | MalwareBazaar 전체 덤프 또는 최근 CSV ([export](https://bazaar.abuse.ch/export/)) | `hash_blacklist` | 10만 ~ 전체 | 전체 덤프는 1시간마다 갱신되고, CSV 내보내기는 로그인과 Auth-Key가 필요하다 |
| 악성 TLSH | MalwareBazaar 샘플 메타데이터의 `tlsh` ([API](https://bazaar.abuse.ch/api/)) | `file_fingerprints` (가져오기 API) | 블랙리스트 중 TLSH가 있는 것 전부 | CSV에 `tlsh` 열이 있는지는 로그인 후 export 페이지에서 확인해야 한다(아직 확인 못 함). 없으면 API로 샘플별 조회 |
| YARA 룰 | [YARA Forge](https://yarahq.github.io) core(약 5천 개) / extended(약 1.07만) / full(약 1.24만) ([releases](https://github.com/YARAHQ/yara-forge/releases)) | `rulesets`, `yara_rules` | core부터 시작, full까지 | 라이선스는 룰 출처마다 다르다. core 헤더는 Elastic License 2.0. 내부 측정용은 괜찮지만 제품에 넣어 배포하기 전에는 확인해야 한다 |
| 정상 파일 (업로드·YARA 부하용) | 오픈소스 설치 파일·아카이브 (예: Python, Node.js, 7-Zip, Git 설치 파일, Linux 패키지) | 업로드 대상(파일) | 크기 구간별 5개 이상 | 실제 PE·압축 구조라 YARA 비용이 무작위 바이트와 다르다 |
| 정상 해시 (화이트리스트) | NIST NSRL RDS 일부, 또는 위 정상 파일의 해시 | `hash_whitelist` | 수천 ~ 수만 | 화이트리스트 조회 비용과 블룸 크기를 현실적으로 맞추기 위해 |

**TLSH 비교 대상(corpus) = 활성 블랙리스트 SHA-256 중 TLSH 지문이 있는 것**이다(서버 `CLAUDE.md`). 그래서 블랙리스트와 지문을 **둘 다** 넣어야 한다. 하나만 넣으면 corpus가 비어 TLSH 단계가 공짜로 보인다.

## 3. 지금 코드에서 막히는 곳과 대응

| 제약 | 위치 | 영향 | 대응 |
|---|---|---|---|
| 룰셋 업로드 1MB 상한 | `UploadRulesetUseCase.MAX_BYTES` | YARA Forge core 파일이 1MB를 넘으면 올릴 수 없다 (실제 크기는 받아서 확인) | 상한을 설정값으로 빼서 벤치에서만 올리거나, 룰셋을 나눠 올린다. 상한을 바꾸는 건 별도 PR |
| 단일 `.yar` 파일만 | 룰셋 업로드 | `include`를 쓰는 룰 저장소는 그대로 못 올린다 | YARA Forge 패키지는 이미 한 파일로 합쳐져 있어 문제없을 것. 다른 저장소는 하나로 합친다 |
| YARA 모듈 지원 | 엔진 `yara-python>=4.5` | 룰이 `pe`, `math`, `hash`, `dotnet`, `magic` 같은 모듈을 쓰면 엔진 빌드에 그 모듈이 있어야 컴파일된다 | 올리기 전에 엔진 컨테이너에서 `yara.compile()`로 컴파일되는지 먼저 확인한다. 실패한 룰 목록과 컴파일 시간도 기록한다 |
| 블룸 크기 | `lookup.bloom-filter.expected-hash-count` (기본 100,000) | 해시를 그 이상 넣으면 오탐률이 설정값보다 올라간다. 오탐은 안전한 쪽이지만 DB 조회가 늘어 측정값이 왜곡된다 | 벤치 설정에서 실제 적재 수에 맞춘다. 운영값도 이 결과를 보고 정한다 |
| 한 건씩 넣는 API | `POST /api/admin/blacklist`, `/api/admin/file-fingerprints/import` | 10만 건이면 감사 로그 10만 행, 시간도 오래 걸린다 | 아래 4절 |
| 지문 가져오기 형식 | `FingerprintImportController` (`(T1)?[0-9A-F]{70}`) | MalwareBazaar TLSH는 `T1` 접두가 있는 대문자 70자리라 그대로 맞을 것 | 적재 스크립트에서 형식을 검증하고 맞지 않는 줄은 건너뛰며 개수를 센다 |

## 4. 넣는 방법

벤치 전용 compose 프로젝트(`-p bench-server`)의 DB에만 넣는다. 개발 DB(`platform`)에는 넣지 않는다.

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

## 6. 할 일

1. [ ] abuse.ch Auth-Key 발급 (팀 계정 또는 개인). export 페이지에서 CSV 열 구성(`tlsh` 포함 여부)을 확인한다
2. [ ] YARA Forge core·extended·full을 내려받아 파일 크기, 룰 수, 필요한 모듈을 확인한다. 엔진 컨테이너에서 컴파일을 시험한다
3. [ ] 1MB 업로드 상한과 블룸 기대 개수를 벤치에서 바꿀 방법을 정한다(설정값으로 빼는 PR이 필요한지)
4. [ ] `bench/seed/` 적재 스크립트 작성: API 경로(소량)와 COPY 경로(대량)
5. [ ] 정상 파일 세트 준비: 크기 구간별 오픈소스 설치 파일, 그리고 해시 목록
6. [ ] 적재 → 블룸 재구축 → 적재 기록 작성 → [측정 계획](2026-11-16-pipeline-latency-measurement.md) 1단계(계측)로 넘어간다

## 출처

- MalwareBazaar export: https://bazaar.abuse.ch/export/
- MalwareBazaar API: https://bazaar.abuse.ch/api/
- MalwareBazaar FAQ: https://bazaar.abuse.ch/faq/
- YARA Forge: https://yarahq.github.io , https://github.com/YARAHQ/yara-forge/releases
- YARA Forge 소개 (패키지 구성): https://cyb3rops.medium.com/introducing-yara-forge-a77cbb77dcab
- Nextron (Elastic 룰 라이선스 관련): https://www.nextron-systems.com/2025/04/30/yara-forge-rule-sets-now-available-in-thor-cloud-and-thor-cloud-lite/

# 에이전트 생명주기 · 정책 적용 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 로컬 에이전트가 스스로 등록·하트비트·토큰 갱신·정책 수신을 하고, 받은 바이패스 정책(PINNED, SECURITY_UPDATE)을 트래픽에 적용한다.

**Architecture:** `AgentService` gRPC 클라이언트(`AgentClient`)와 그것을 주기적으로 돌리는 `AgentLifecycle`을 새로 만들고, `HoldPipeline`이 기동 시 둘을 띄운다. 자격 증명은 OS 키체인(`keyring`)에, 정책은 메모리에만 둔다. `VerdictClient`는 고정 토큰 대신 `AgentLifecycle.token`을 매 호출마다 읽는다. 바이패스는 두 곳에서 적용한다: PINNED는 `tls_clienthello`에서 TLS를 풀지 않고, 모든 바이패스 호스트는 `responseheaders`에서 보류 없이 흘려보내며 다운로드면 BYPASSED 이벤트를 보고한다.

**Tech Stack:** Python 3.12, mitmproxy 12, grpcio (aio), protobuf, keyring, pytest + pytest-asyncio, ruff

**Spec:** 별도 스펙 문서 없음. 근거는 아래 셋과 2026-09-29 결정(Global Constraints에 옮겨 적음)이다.
- `platform-agent/proto/proto/teecher/agent/v1/agent.proto` — `AgentService` 계약
- `project/docs/superpowers/specs/2026-09-18-system-flow.md` — `decision` 값(BYPASSED), PC 현황 3분 기준, `request_host` 위조 경고(156행)
- `project/docs/schema/schema.sql` — `bypass_domains`(와일드카드 금지), `file_type_policies`

**시작 조건:** platform-agent PR #7(`refactor/held-body`)이 `develop`에 머지된 뒤 `develop`에서 브랜치를 딴다. 이 계획의 `addon.py`·`verdict_client.py` 코드는 #7 이후 상태 기준이다.

## Global Constraints

- 토큰 저장: `agent_token`은 OS 키체인(`keyring`, 서비스 `teecher-agent`, 사용자 `credentials`)에만 둔다. 평문 파일 금지. "에이전트에 영속 저장소를 두지 않는다" 원칙의 유일한 예외다 (2026-09-29 결정)
- `file_type_policies`는 받아 `Policy`에 보관만 하고 동작에 쓰지 않는다 (2026-09-29 결정)
- 정책은 기동 시 1회 + `POLICY_REFRESH_SECONDS`(기본 300)마다 다시 받는다. 실패하면 마지막으로 받은 정책을 유지한다 (2026-09-29 결정)
- 정책을 한 번도 못 받았으면 `EMPTY_POLICY` — 아무것도 바이패스하지 않는다(전부 검사)
- 바이패스 호스트는 정확한 호스트만 인정한다. 와일드카드(`*`)가 들어간 항목, 빈 호스트, 알 수 없는 분류는 버린다. 하위 도메인은 바이패스하지 않는다
- 바이패스 판단의 호스트는 실제로 연결하는 대상(서버 연결 주소)이다. Host 헤더·SNI만으로 바이패스하지 않는다
- 검사 서버 장애 시 fail-close 고정. 이 계획의 어떤 실패도 다운로드를 통과시키는 쪽으로 가면 안 된다
- 하트비트 기본 60초(`HEARTBEAT_INTERVAL_SECONDS`). 콘솔 PC 현황은 `last_heartbeat_at > now() - 3분`
- 토큰 갱신 시점: 받은 시각부터 만료까지의 절반이 지나면. 서버는 발급 시각을 주지 않으므로 받은 시각을 에이전트가 기록한다
- `AGENT_TOKEN` 환경변수가 있으면 개발용 수동 주입 — 등록·갱신을 건너뛰고 그 값을 쓴다(하트비트·정책은 그대로)
- 로그·예외 메시지에 토큰·등록 토큰 값을 넣지 않는다
- 줄 길이 120, ruff `E,F,I,B,UP`, 테스트 이름은 한국어 서술형(기존 관례)

## Review Focus

1. **Host 헤더/SNI 위조로 바이패스를 얻는 경우** — CONNECT 대상은 `evil.com`인데 Host 헤더나 SNI가 바이패스 호스트면 바이패스하지 않아야 한다 → Task 8 테스트 `test_Host_헤더와_연결_대상이_다르면_바이패스하지_않는다`, `test_SNI만_PINNED_호스트면_가로챈다`
2. **키체인을 쓸 수 없는 환경**(잠김, Linux 백엔드 없음, 깨진 항목) — 에이전트는 죽지 않고 시작하며 다운로드는 fail-close로 막힌다 → Task 2 `test_KeyringStore_키체인_오류는_로드에서_None`, Task 6 `test_키체인_저장이_실패해도_메모리의_토큰으로_동작한다`
3. **서버가 쓸 수 없는 자격 증명을 돌려주는 경우**(빈 토큰, 이미 지난 만료 시각) — 저장하지 않는다 → Task 4 `test_쓸_수_없는_자격_증명은_거부한다`
4. **토큰 갱신·정책 수신 실패, 폐기된 토큰(UNAUTHENTICATED)** — 주기 작업이 죽지 않고 기존 토큰·정책을 유지한다 → Task 6 `test_토큰_갱신_실패는_기존_토큰을_유지한다`, `test_정책_수신_실패는_마지막_정책을_유지한다`, `test_주기_작업은_예외에도_계속_돈다`
5. **기동 직후 정책을 받기 전의 트래픽** — 바이패스 없이 전부 보류·검사된다 → Task 8 `test_정책을_받기_전에는_바이패스하지_않는다`

알려진 한계(테스트하지 않음, PR 본문에 적는다): 토큰 갱신 순간 이전 토큰으로 진행 중이던 판정 RPC는 UNAUTHENTICATED → fail-close로 그 다운로드 1건이 막힐 수 있다.

## File Structure

| 파일 | 책임 |
|---|---|
| `src/agent/policy.py` (신규) | `Policy` 값 객체 — GetPolicy 응답 정규화, 호스트 → 바이패스 분류 조회 |
| `src/agent/credentials.py` (신규) | `Credentials` 값 객체, `CredentialStore`(키체인·메모리) |
| `src/agent/identity.py` (신규) | 등록에 보낼 호스트 정보 `AgentIdentity` |
| `src/agent/platform/{macos,windows,linux}.py`, `__init__.py` | OS별 `hardware_uuid()` 추가 |
| `src/agent/__init__.py` | `__version__` |
| `src/agent/agent_client.py` (신규) | `AgentService` gRPC 호출, 오류를 `AgentServiceError`로 모음 |
| `src/agent/lifecycle.py` (신규) | 자격 증명 확보·하트비트·토큰 갱신·정책 갱신 오케스트레이션 |
| `src/agent/config.py` | 새 환경변수 4개 |
| `src/agent/verdict_client.py` | 채널 공유, 토큰을 콜러블로 받기 |
| `src/agent/addon.py` | 생명주기 기동·정리, 바이패스 적용 |
| `tests/fakes/agent_server.py` (신규) | 가짜 `AgentService` |
| `tests/fakes/verdict_server.py` | `create_server`가 가짜 AgentService도 함께 띄움 |
| `compose.dev.yml`, `README.md`, `CLAUDE.md` | 새 환경변수, 저장 원칙 예외 |

---

### Task 1: 정책 값 객체

**Files:**
- Create: `src/agent/policy.py`
- Test: `tests/test_policy.py`

**Interfaces:**
- Consumes: `teecher.agent.v1.agent_pb2` (생성 코드, 이미 있음)
- Produces:
  - `normalize_host(host: str) -> str`
  - `Policy(bypass_hosts: Mapping[str, int], file_type_policies: tuple = ())` — frozen dataclass
  - `Policy.from_proto(response: agent_pb2.GetPolicyResponse) -> Policy`
  - `Policy.bypass_category(host: str) -> int | None` — `agent_pb2.BYPASS_CATEGORY_*` 값 또는 None
  - `EMPTY_POLICY: Policy`

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_policy.py`:

```python
import pytest

from agent.policy import EMPTY_POLICY, Policy
from teecher.agent.v1 import agent_pb2

PINNED = agent_pb2.BYPASS_CATEGORY_PINNED
SECURITY_UPDATE = agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


def response(*entries: tuple[str, int]) -> agent_pb2.GetPolicyResponse:
    return agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host=host, category=category) for host, category in entries]
    )


def test_정확한_호스트만_바이패스한다():
    policy = Policy.from_proto(response(("dl.google.com", SECURITY_UPDATE)))

    assert policy.bypass_category("dl.google.com") == SECURITY_UPDATE
    assert policy.bypass_category("x.dl.google.com") is None
    assert policy.bypass_category("google.com") is None
    assert policy.bypass_category("dl.google.com.evil.com") is None


def test_대소문자와_끝의_점은_같은_호스트로_본다():
    policy = Policy.from_proto(response(("DL.Google.com.", SECURITY_UPDATE)))

    assert policy.bypass_category("dl.google.com") == SECURITY_UPDATE
    assert policy.bypass_category("DL.GOOGLE.COM.") == SECURITY_UPDATE


@pytest.mark.parametrize(
    ("host", "category"),
    [
        ("*.google.com", SECURITY_UPDATE),
        ("", PINNED),
        ("a.example", agent_pb2.BYPASS_CATEGORY_UNSPECIFIED),
        ("b.example", 7),
    ],
)
def test_와일드카드_빈_호스트_알_수_없는_분류는_버린다(host, category):
    entry = agent_pb2.BypassHost(host=host)
    entry.category = category  # proto3 enum은 열려 있어 7도 들어간다

    policy = Policy.from_proto(agent_pb2.GetPolicyResponse(bypass_hosts=[entry]))

    assert dict(policy.bypass_hosts) == {}


def test_파일_유형_정책은_보관만_한다():
    ftp = agent_pb2.FileTypePolicy(file_type="exe", inspection_level=agent_pb2.INSPECTION_LEVEL_NONE)

    policy = Policy.from_proto(agent_pb2.GetPolicyResponse(file_type_policies=[ftp]))

    assert policy.file_type_policies == (ftp,)


def test_빈_정책은_아무것도_바이패스하지_않는다():
    assert EMPTY_POLICY.bypass_category("dl.google.com") is None
```

- [ ] **Step 2: 실패 확인**

Run: `uv run --group dev pytest tests/test_policy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.policy'`

- [ ] **Step 3: 구현**

`src/agent/policy.py`:

```python
"""GetPolicy로 받은 정책. 메모리에만 둔다(에이전트는 정책을 저장하지 않는다).

- 바이패스 호스트는 와일드카드 없는 정확한 호스트만 인정한다(ERD ck_bypass_domains_exact_host).
  `*.google.com`은 drive.google.com까지 면제해 검사 구멍을 만든다.
- file_type_policies는 받아 보관만 한다(2026-09-29 결정). 에이전트가 유형을 판단할 근거는 공격자가 정한
  MIME·확장자뿐이라, 검사를 줄이는 값(NONE·HASH_ONLY)을 따르면 우회 경로가 된다.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from teecher.agent.v1 import agent_pb2

_KNOWN_CATEGORIES = frozenset({agent_pb2.BYPASS_CATEGORY_PINNED, agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE})


def normalize_host(host: str) -> str:
    return host.strip().rstrip(".").lower()


@dataclass(frozen=True)
class Policy:
    bypass_hosts: Mapping[str, int]
    file_type_policies: tuple[agent_pb2.FileTypePolicy, ...] = ()

    @staticmethod
    def from_proto(response: agent_pb2.GetPolicyResponse) -> "Policy":
        hosts: dict[str, int] = {}
        for entry in response.bypass_hosts:
            host = normalize_host(entry.host)
            if not host or "*" in host or entry.category not in _KNOWN_CATEGORIES:
                continue
            hosts[host] = entry.category
        return Policy(MappingProxyType(hosts), tuple(response.file_type_policies))

    def bypass_category(self, host: str) -> int | None:
        return self.bypass_hosts.get(normalize_host(host))


EMPTY_POLICY = Policy(MappingProxyType({}))
```

- [ ] **Step 4: 통과 확인**

Run: `uv run --group dev pytest tests/test_policy.py -q`
Expected: PASS (8 passed)

- [ ] **Step 5: 커밋**

```bash
git add src/agent/policy.py tests/test_policy.py
git commit -m "feat: GetPolicy 응답을 정규화하는 Policy 값 객체"
```

---

### Task 2: 자격 증명과 키체인 저장소

**Files:**
- Create: `src/agent/credentials.py`
- Modify: `pyproject.toml`, `uv.lock` (`keyring` 의존성)
- Test: `tests/test_credentials.py`

**Interfaces:**
- Produces:
  - `Credentials(agent_id: str, agent_token: str, issued_at: datetime, expires_at: datetime)` — frozen dataclass, UTC aware datetime
  - `Credentials.refresh_due(now: datetime) -> bool`
  - `Credentials.to_json() -> str`, `Credentials.from_json(raw: str) -> Credentials`
  - `CredentialStore` Protocol: `load() -> Credentials | None`, `save(creds: Credentials) -> None`
  - `MemoryStore`, `KeyringStore`, `CredentialStoreError(Exception)`
  - `make_store(kind: str) -> CredentialStore` — `"memory"` 또는 `"keyring"`
  - 모듈 상수 `SERVICE = "teecher-agent"`, `USERNAME = "credentials"`

- [ ] **Step 1: 의존성 추가**

Run: `uv add "keyring>=25"`
Expected: `pyproject.toml`의 `dependencies`에 `"keyring>=25"`가 들어가고 `uv.lock`이 갱신된다

- [ ] **Step 2: 실패하는 테스트 작성**

`tests/test_credentials.py`:

```python
from datetime import UTC, datetime, timedelta

import pytest

from agent import credentials
from agent.credentials import CredentialStoreError, Credentials, KeyringStore, MemoryStore, make_store

T0 = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


def creds(lifetime: timedelta = timedelta(hours=24)) -> Credentials:
    return Credentials("agent-1", "tok-1", issued_at=T0, expires_at=T0 + lifetime)


def test_수명의_절반이_지나면_갱신_대상이다():
    c = creds()

    assert not c.refresh_due(T0 + timedelta(hours=11, minutes=59))
    assert c.refresh_due(T0 + timedelta(hours=12))


def test_JSON으로_왕복한다():
    c = creds()

    assert Credentials.from_json(c.to_json()) == c


def test_MemoryStore는_저장한_것을_돌려준다():
    store = MemoryStore()
    assert store.load() is None

    store.save(creds())

    assert store.load() == creds()


class FakeKeyring:
    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}
        self.fail = False

    def get_password(self, service: str, username: str) -> str | None:
        if self.fail:
            raise RuntimeError("keychain locked")
        return self.data.get((service, username))

    def set_password(self, service: str, username: str, value: str) -> None:
        if self.fail:
            raise RuntimeError("keychain locked")
        self.data[(service, username)] = value


@pytest.fixture
def fake_keyring(monkeypatch):
    fake = FakeKeyring()
    monkeypatch.setattr(credentials, "keyring", fake)
    return fake


def test_KeyringStore는_teecher_agent_항목에_저장한다(fake_keyring):
    KeyringStore().save(creds())

    assert KeyringStore().load() == creds()
    assert ("teecher-agent", "credentials") in fake_keyring.data


def test_KeyringStore_깨진_항목은_없는_것으로_본다(fake_keyring):
    fake_keyring.data[("teecher-agent", "credentials")] = "{not json"

    assert KeyringStore().load() is None


def test_KeyringStore_키체인_오류는_로드에서_None(fake_keyring):
    fake_keyring.fail = True

    assert KeyringStore().load() is None


def test_KeyringStore_저장_실패는_CredentialStoreError(fake_keyring):
    fake_keyring.fail = True

    with pytest.raises(CredentialStoreError):
        KeyringStore().save(creds())


def test_make_store():
    assert isinstance(make_store("memory"), MemoryStore)
    assert isinstance(make_store("keyring"), KeyringStore)
```

- [ ] **Step 3: 실패 확인**

Run: `uv run --group dev pytest tests/test_credentials.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.credentials'`

- [ ] **Step 4: 구현**

`src/agent/credentials.py`:

```python
"""에이전트 자격 증명(agent_id, agent_token)과 그 보관소.

설계 원칙 "에이전트에 영속 저장소를 두지 않는다"의 유일한 예외다(2026-09-29 결정). 1회용 등록 토큰으로
받은 agent_token은 재시작 뒤에도 남아야 하므로 OS 키체인(macOS Keychain, Windows 자격 증명 관리자)에
둔다. 평문 파일로는 쓰지 않는다. 로그에 토큰 값을 남기지 않는다.
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import keyring

logger = logging.getLogger(__name__)

SERVICE = "teecher-agent"
USERNAME = "credentials"


class CredentialStoreError(Exception):
    """자격 증명을 저장하지 못했다. 호출자는 이번 실행 동안 메모리의 값을 쓴다."""


@dataclass(frozen=True)
class Credentials:
    agent_id: str
    agent_token: str
    issued_at: datetime  # 에이전트가 토큰을 받은 시각(UTC). 서버는 발급 시각을 주지 않는다
    expires_at: datetime

    def refresh_due(self, now: datetime) -> bool:
        return now >= self.issued_at + (self.expires_at - self.issued_at) / 2

    def to_json(self) -> str:
        return json.dumps(
            {
                "agent_id": self.agent_id,
                "agent_token": self.agent_token,
                "issued_at": self.issued_at.isoformat(),
                "expires_at": self.expires_at.isoformat(),
            }
        )

    @staticmethod
    def from_json(raw: str) -> "Credentials":
        data = json.loads(raw)
        return Credentials(
            agent_id=data["agent_id"],
            agent_token=data["agent_token"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )


class CredentialStore(Protocol):
    def load(self) -> Credentials | None: ...

    def save(self, creds: Credentials) -> None: ...


class MemoryStore:
    """테스트·개발(Docker처럼 키체인이 없는 환경)용. 재시작하면 사라진다."""

    def __init__(self) -> None:
        self._creds: Credentials | None = None

    def load(self) -> Credentials | None:
        return self._creds

    def save(self, creds: Credentials) -> None:
        self._creds = creds


class KeyringStore:
    def load(self) -> Credentials | None:
        try:
            raw = keyring.get_password(SERVICE, USERNAME)
        except Exception:
            logger.exception("키체인에서 자격 증명을 읽지 못했다 — 없는 것으로 본다")
            return None
        if raw is None:
            return None
        try:
            return Credentials.from_json(raw)
        except Exception:
            logger.error("키체인의 자격 증명 항목이 깨졌다 — 없는 것으로 본다")
            return None

    def save(self, creds: Credentials) -> None:
        try:
            keyring.set_password(SERVICE, USERNAME, creds.to_json())
        except Exception as exc:
            raise CredentialStoreError(f"키체인 저장 실패: {type(exc).__name__}") from exc


def make_store(kind: str) -> CredentialStore:
    return MemoryStore() if kind == "memory" else KeyringStore()
```

- [ ] **Step 5: 통과 확인**

Run: `uv run --group dev pytest tests/test_credentials.py -q`
Expected: PASS (8 passed)

- [ ] **Step 6: 커밋**

```bash
git add pyproject.toml uv.lock src/agent/credentials.py tests/test_credentials.py
git commit -m "feat: 에이전트 자격 증명을 OS 키체인에 보관"
```

---

### Task 3: 등록에 보낼 호스트 정보

**Files:**
- Create: `src/agent/identity.py`
- Modify: `src/agent/__init__.py`, `src/agent/platform/__init__.py`, `src/agent/platform/macos.py`, `src/agent/platform/windows.py`, `src/agent/platform/linux.py`
- Test: `tests/test_identity.py`

**Interfaces:**
- Produces:
  - `agent.__version__: str` — `pyproject.toml`의 `version`과 같아야 한다
  - `AgentIdentity(hostname: str, os_platform: int, agent_version: str, hardware_uuid: str)` — frozen dataclass
  - `current_identity() -> AgentIdentity` — 절대 예외를 던지지 않는다
  - `os_platform_of(platform: str) -> int` — `agent_pb2.OS_PLATFORM_*`
  - `agent.platform.hardware_uuid() -> str` — 실패하면 `""`
  - `agent.platform.macos.parse_ioreg(output: str) -> str`

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_identity.py`:

```python
import tomllib
from pathlib import Path

import agent
from agent.identity import current_identity, os_platform_of
from agent.platform.macos import parse_ioreg
from teecher.agent.v1 import agent_pb2

IOREG_SAMPLE = """
+-o J314sAP  <class IOPlatformExpertDevice, id 0x100000240, registered, matched, active, busy 0 (0 ms), retain 34>
    {
      "IOPlatformSerialNumber" = "ABCDEF123"
      "IOPlatformUUID" = "0A1B2C3D-1111-2222-3333-444455556666"
    }
"""


def test_ioreg_출력에서_IOPlatformUUID를_꺼낸다():
    assert parse_ioreg(IOREG_SAMPLE) == "0A1B2C3D-1111-2222-3333-444455556666"
    assert parse_ioreg("no uuid here") == ""


def test_OS_이름을_proto_값으로_바꾼다():
    assert os_platform_of("darwin") == agent_pb2.OS_PLATFORM_MACOS
    assert os_platform_of("win32") == agent_pb2.OS_PLATFORM_WINDOWS
    assert os_platform_of("linux") == agent_pb2.OS_PLATFORM_LINUX
    assert os_platform_of("freebsd14") == agent_pb2.OS_PLATFORM_UNSPECIFIED


def test_버전은_pyproject와_같다():
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())

    assert agent.__version__ == pyproject["project"]["version"]


def test_현재_호스트_정보는_예외_없이_채워진다():
    identity = current_identity()

    assert identity.hostname
    assert identity.agent_version == agent.__version__
    assert isinstance(identity.hardware_uuid, str)  # 얻지 못하면 "" — 서버는 재설치 매칭 후보로만 쓴다
```

- [ ] **Step 2: 실패 확인**

Run: `uv run --group dev pytest tests/test_identity.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.identity'`

- [ ] **Step 3: 구현**

`src/agent/__init__.py` (지금 비어 있다):

```python
__version__ = "0.1.0"  # pyproject.toml의 version과 맞춘다 (tests/test_identity.py가 확인)
```

`src/agent/platform/macos.py` — import 아래에 추가하고 `__all__`에 `"hardware_uuid"`를 넣는다:

```python
import re
import subprocess

_IOREG_UUID = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')


def parse_ioreg(output: str) -> str:
    match = _IOREG_UUID.search(output)
    return match.group(1) if match else ""


def hardware_uuid() -> str:
    # 위조 가능한 값이라 서버는 식별 근거가 아닌 재설치 매칭 후보로만 쓴다. 못 얻으면 빈 문자열.
    try:
        result = subprocess.run(
            ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except Exception:
        return ""
    return parse_ioreg(result.stdout)
```

`src/agent/platform/windows.py` — 추가하고 `__all__`에 `"hardware_uuid"`:

```python
import subprocess


def hardware_uuid() -> str:
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except Exception:
        return ""
    return result.stdout.strip()
```

`src/agent/platform/linux.py` — 추가하고 `__all__`에 `"hardware_uuid"`:

```python
def hardware_uuid() -> str:
    # 보통 root만 읽을 수 있다. 못 읽으면 빈 문자열.
    try:
        return Path("/sys/class/dmi/id/product_uuid").read_text().strip()
    except OSError:
        return ""
```

`src/agent/platform/__init__.py` — 세 분기의 import에 `hardware_uuid`를 더하고 `__all__`에 추가:

```python
if sys.platform == "darwin":
    from agent.platform.macos import create_spool_file, hardware_uuid, prepare_spool_dir
elif sys.platform == "win32":
    from agent.platform.windows import create_spool_file, hardware_uuid, prepare_spool_dir
else:
    from agent.platform.linux import create_spool_file, hardware_uuid, prepare_spool_dir

__all__ = ["SpoolFile", "create_spool_file", "hardware_uuid", "prepare_spool_dir"]
```

`src/agent/identity.py`:

```python
"""RegisterAgent에 보내는 호스트 정보. 사용자 신원은 담지 않는다(식별 단위는 장비)."""

import socket
import sys
from dataclasses import dataclass

from agent import __version__
from agent.platform import hardware_uuid
from teecher.agent.v1 import agent_pb2


@dataclass(frozen=True)
class AgentIdentity:
    hostname: str
    os_platform: int  # agent_pb2.OS_PLATFORM_*
    agent_version: str
    hardware_uuid: str


def os_platform_of(platform: str) -> int:
    if platform == "darwin":
        return agent_pb2.OS_PLATFORM_MACOS
    if platform == "win32":
        return agent_pb2.OS_PLATFORM_WINDOWS
    if platform.startswith("linux"):
        return agent_pb2.OS_PLATFORM_LINUX
    return agent_pb2.OS_PLATFORM_UNSPECIFIED


def current_identity() -> AgentIdentity:
    try:
        hostname = socket.gethostname()
    except OSError:
        hostname = ""
    return AgentIdentity(hostname, os_platform_of(sys.platform), __version__, hardware_uuid())
```

- [ ] **Step 4: 통과 확인**

Run: `uv run --group dev pytest tests/test_identity.py tests/test_platform.py -q`
Expected: PASS (기존 platform 테스트 포함, Windows 전용 1개 skip)

- [ ] **Step 5: 커밋**

```bash
git add src/agent/__init__.py src/agent/identity.py src/agent/platform tests/test_identity.py
git commit -m "feat: 등록에 보낼 호스트 정보와 OS별 hardware UUID"
```

---

### Task 4: 가짜 AgentService와 AgentClient

**Files:**
- Create: `tests/fakes/agent_server.py`, `src/agent/agent_client.py`
- Modify: `tests/fakes/verdict_server.py:105-112` (`create_server`)
- Test: `tests/test_agent_client.py`

**Interfaces:**
- Consumes: `Credentials`(Task 2), `Policy`(Task 1), `AgentIdentity`(Task 3)
- Produces:
  - `AgentServiceError(Exception)`, `AgentUnauthenticated(AgentServiceError)`
  - `AgentClient(channel: grpc_aio.Channel, rpc_timeout_seconds: float)`
  - `async register(*, enrollment_token: str, identity: AgentIdentity) -> Credentials`
  - `async heartbeat(token: str, agent_version: str) -> None`
  - `async refresh_token(current: Credentials) -> Credentials` — `agent_id`는 이어받는다
  - `async get_policy(token: str) -> Policy`
  - 테스트용: `FakeAgentServicer` — 속성 `enrollment_tokens: set[str]`(기본 `{"enroll-ok"}`), `valid_tokens: set[str]`, `token_lifetime: timedelta`, `registrations: list`, `heartbeats: list[tuple[str, str]]`, `policy: GetPolicyResponse`, `policy_calls: int`, `fail_code: grpc.StatusCode | None`
  - `create_server()`의 세 번째 반환값(`FakeVerdictServicer`)에 `.agent: FakeAgentServicer`가 붙는다. 같은 포트에서 두 서비스를 모두 받는다

- [ ] **Step 1: 가짜 서버 작성**

`tests/fakes/agent_server.py`:

```python
"""테스트용 가짜 AgentService. 등록 토큰은 1회용, 토큰 갱신 시 이전 토큰은 즉시 무효 — 실서버 계약과 같다."""

from datetime import UTC, datetime, timedelta

import grpc
from google.protobuf.timestamp_pb2 import Timestamp

from teecher.agent.v1 import agent_pb2, agent_pb2_grpc


def _timestamp(value: datetime) -> Timestamp:
    ts = Timestamp()
    ts.FromDatetime(value)
    return ts


class FakeAgentServicer(agent_pb2_grpc.AgentServiceServicer):
    def __init__(self) -> None:
        self.enrollment_tokens: set[str] = {"enroll-ok"}
        self.valid_tokens: set[str] = set()
        self.token_lifetime = timedelta(hours=24)
        self.registrations: list[agent_pb2.RegisterAgentRequest] = []
        self.heartbeats: list[tuple[str, str]] = []
        self.policy = agent_pb2.GetPolicyResponse()
        self.policy_calls = 0
        # 설정하면 모든 RPC가 이 코드로 실패한다
        self.fail_code: grpc.StatusCode | None = None
        self._seq = 0

    def _issue(self) -> tuple[str, Timestamp]:
        self._seq += 1
        token = f"tok-{self._seq}"
        self.valid_tokens.add(token)
        return token, _timestamp(datetime.now(UTC) + self.token_lifetime)

    async def _fail_if_forced(self, context) -> None:
        if self.fail_code is not None:
            await context.abort(self.fail_code, "forced failure")

    async def _authorized(self, context) -> str:
        await self._fail_if_forced(context)
        auth = dict(context.invocation_metadata() or ()).get("authorization", "")
        token = auth.removeprefix("Bearer ")
        if not auth.startswith("Bearer ") or token not in self.valid_tokens:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid agent token")
        return token

    async def RegisterAgent(self, request, context):
        await self._fail_if_forced(context)
        self.registrations.append(request)
        if request.enrollment_token not in self.enrollment_tokens:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "invalid enrollment token")
        self.enrollment_tokens.discard(request.enrollment_token)
        token, expires = self._issue()
        return agent_pb2.RegisterAgentResponse(agent_id=f"agent-{self._seq}", agent_token=token, token_expires_at=expires)

    async def Heartbeat(self, request, context):
        token = await self._authorized(context)
        self.heartbeats.append((token, request.agent_version))
        return agent_pb2.HeartbeatResponse(server_time=_timestamp(datetime.now(UTC)))

    async def RefreshAgentToken(self, request, context):
        old = await self._authorized(context)
        self.valid_tokens.discard(old)
        token, expires = self._issue()
        return agent_pb2.RefreshAgentTokenResponse(agent_token=token, token_expires_at=expires)

    async def GetPolicy(self, request, context):
        await self._authorized(context)
        self.policy_calls += 1
        return self.policy
```

`tests/fakes/verdict_server.py` — import에 `from .agent_server import FakeAgentServicer`(상대 import: pytest의 `fakes.verdict_server`와 단독 실행의 `tests.fakes.verdict_server` 둘 다에서 동작한다)와 `from teecher.agent.v1 import agent_pb2_grpc`를 더하고 `create_server`를 바꾼다:

```python
async def create_server(host: str = "127.0.0.1", port: int = 0) -> tuple[grpc_aio.Server, int, FakeVerdictServicer]:
    """port=0이면 빈 포트를 골라 바인딩한다. (server, bound_port, servicer)를 돌려준다.

    가짜 AgentService도 같은 서버에 붙는다 — servicer.agent로 접근한다.
    """
    servicer = FakeVerdictServicer()
    servicer.agent = FakeAgentServicer()
    server = grpc_aio.server()
    verdict_pb2_grpc.add_VerdictServiceServicer_to_server(servicer, server)
    agent_pb2_grpc.add_AgentServiceServicer_to_server(servicer.agent, server)
    bound_port = server.add_insecure_port(f"{host}:{port}")
    await server.start()
    return server, bound_port, servicer
```

단독 실행 경로의 import가 깨지지 않았는지 확인한다(저장소 루트에서): `PYTHONPATH=src uv run python -c "import tests.fakes.verdict_server"` → 오류 없이 끝난다.

- [ ] **Step 2: 실패하는 테스트 작성**

`tests/test_agent_client.py`:

```python
import socket
from datetime import timedelta

import grpc
import pytest
from fakes.verdict_server import create_server
from grpc import aio as grpc_aio

from agent.agent_client import AgentClient, AgentServiceError, AgentUnauthenticated
from agent.identity import AgentIdentity
from teecher.agent.v1 import agent_pb2

IDENTITY = AgentIdentity("pc-1", agent_pb2.OS_PLATFORM_MACOS, "0.1.0", "HW-1")


def unused_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def env():
    server, port, verdict = await create_server()
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{port}")
    yield AgentClient(channel, rpc_timeout_seconds=5), verdict.agent
    await channel.close()
    await server.stop(None)


async def test_등록하면_자격_증명을_받고_등록_토큰은_1회용이다(env):
    client, fake = env

    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)

    assert creds.agent_id
    assert creds.agent_token in fake.valid_tokens
    assert creds.expires_at > creds.issued_at
    [request] = fake.registrations
    assert (request.hostname, request.os_platform, request.agent_version, request.hardware_uuid) == (
        "pc-1",
        agent_pb2.OS_PLATFORM_MACOS,
        "0.1.0",
        "HW-1",
    )
    with pytest.raises(AgentUnauthenticated):
        await client.register(enrollment_token="enroll-ok", identity=IDENTITY)


async def test_하트비트는_토큰과_버전을_보낸다(env):
    client, fake = env
    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)

    await client.heartbeat(creds.agent_token, "0.1.0")

    assert fake.heartbeats == [(creds.agent_token, "0.1.0")]


async def test_토큰_갱신은_새_토큰을_주고_이전_토큰은_무효가_된다(env):
    client, _ = env
    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)

    renewed = await client.refresh_token(creds)

    assert renewed.agent_id == creds.agent_id
    assert renewed.agent_token != creds.agent_token
    with pytest.raises(AgentUnauthenticated):
        await client.heartbeat(creds.agent_token, "0.1.0")


async def test_정책을_받는다(env):
    client, fake = env
    creds = await client.register(enrollment_token="enroll-ok", identity=IDENTITY)
    fake.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE)]
    )

    policy = await client.get_policy(creds.agent_token)

    assert policy.bypass_category("dl.google.com") == agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


async def test_서버_오류는_AgentServiceError이고_인증_실패와_구분된다(env):
    client, fake = env
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    with pytest.raises(AgentServiceError) as exc_info:
        await client.get_policy("anything")

    assert not isinstance(exc_info.value, AgentUnauthenticated)


async def test_쓸_수_없는_자격_증명은_거부한다(env):
    client, fake = env
    fake.token_lifetime = timedelta(seconds=-1)  # 이미 지난 만료 시각

    with pytest.raises(AgentServiceError):
        await client.register(enrollment_token="enroll-ok", identity=IDENTITY)


async def test_오류_메시지에_토큰이_없다(env):
    client, _ = env

    with pytest.raises(AgentUnauthenticated) as exc_info:
        await client.heartbeat("secret-token-value", "0.1.0")

    assert "secret-token-value" not in str(exc_info.value)


async def test_서버가_없으면_AgentServiceError():
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{unused_port()}")
    client = AgentClient(channel, rpc_timeout_seconds=1)

    with pytest.raises(AgentServiceError):
        await client.heartbeat("t", "0.1.0")
    await channel.close()
```

- [ ] **Step 3: 실패 확인**

Run: `uv run --group dev pytest tests/test_agent_client.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.agent_client'`

- [ ] **Step 4: 구현**

`src/agent/agent_client.py`:

```python
"""AgentService(등록·하트비트·토큰 갱신·정책) gRPC 클라이언트.

판정 경로가 아니므로 fail-close 경계(VerdictUnavailable)와 무관하다. 모든 실패는 AgentServiceError로 모으고,
호출자(AgentLifecycle)가 로그를 남긴 뒤 다음 주기에 다시 시도한다. 메시지에 토큰 값을 넣지 않는다.
"""

from datetime import UTC, datetime

import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from grpc import aio as grpc_aio

from agent.credentials import Credentials
from agent.identity import AgentIdentity
from agent.policy import Policy
from teecher.agent.v1 import agent_pb2, agent_pb2_grpc


class AgentServiceError(Exception):
    pass


class AgentUnauthenticated(AgentServiceError):
    """토큰(또는 등록 토큰)이 무효·만료·폐기됐다."""


def _credentials(agent_id: str, token: str, expires_at: Timestamp) -> Credentials:
    issued_at = datetime.now(UTC)
    expires = expires_at.ToDatetime(tzinfo=UTC)
    if not agent_id or not token or expires <= issued_at:
        raise AgentServiceError("서버가 쓸 수 없는 자격 증명을 돌려줬다")
    return Credentials(agent_id, token, issued_at, expires)


class AgentClient:
    def __init__(self, channel: grpc_aio.Channel, rpc_timeout_seconds: float) -> None:
        self._stub = agent_pb2_grpc.AgentServiceStub(channel)
        self._timeout = rpc_timeout_seconds

    async def _call(self, name: str, method, request, token: str | None):
        metadata = [("authorization", f"Bearer {token}")] if token else None
        try:
            return await method(request, timeout=self._timeout, metadata=metadata)
        except grpc.RpcError as exc:
            code = exc.code() if hasattr(exc, "code") else None
            if code == grpc.StatusCode.UNAUTHENTICATED:
                raise AgentUnauthenticated(f"{name}: 인증 실패") from exc
            raise AgentServiceError(f"{name} 실패: {code}") from exc
        except Exception as exc:
            raise AgentServiceError(f"{name} 실패: {type(exc).__name__}") from exc

    async def register(self, *, enrollment_token: str, identity: AgentIdentity) -> Credentials:
        request = agent_pb2.RegisterAgentRequest(
            enrollment_token=enrollment_token,
            hostname=identity.hostname,
            os_platform=identity.os_platform,
            agent_version=identity.agent_version,
            hardware_uuid=identity.hardware_uuid,
        )
        response = await self._call("RegisterAgent", self._stub.RegisterAgent, request, None)
        return _credentials(response.agent_id, response.agent_token, response.token_expires_at)

    async def heartbeat(self, token: str, agent_version: str) -> None:
        request = agent_pb2.HeartbeatRequest(agent_version=agent_version)
        await self._call("Heartbeat", self._stub.Heartbeat, request, token)

    async def refresh_token(self, current: Credentials) -> Credentials:
        request = agent_pb2.RefreshAgentTokenRequest()
        response = await self._call("RefreshAgentToken", self._stub.RefreshAgentToken, request, current.agent_token)
        return _credentials(current.agent_id, response.agent_token, response.token_expires_at)

    async def get_policy(self, token: str) -> Policy:
        response = await self._call("GetPolicy", self._stub.GetPolicy, agent_pb2.GetPolicyRequest(), token)
        return Policy.from_proto(response)
```

- [ ] **Step 5: 통과 확인**

Run: `uv run --group dev pytest tests/test_agent_client.py tests/test_verdict_client.py tests/test_addon.py -q`
Expected: PASS — 새 테스트 8개 + 기존 테스트(가짜 서버 변경으로 깨지지 않음)

- [ ] **Step 6: 커밋**

```bash
git add tests/fakes/agent_server.py tests/fakes/verdict_server.py src/agent/agent_client.py tests/test_agent_client.py
git commit -m "feat: AgentService gRPC 클라이언트와 가짜 AgentService"
```

---

### Task 5: 새 설정값

**Files:**
- Modify: `src/agent/config.py`
- Test: `tests/test_config.py` (신규)

**Interfaces:**
- Produces: `Config`에 필드 추가 — `enrollment_token: str = ""`, `heartbeat_interval_seconds: float = 60`, `policy_refresh_seconds: float = 300`, `credential_store: str = "keyring"`. 환경변수 `ENROLLMENT_TOKEN`, `HEARTBEAT_INTERVAL_SECONDS`, `POLICY_REFRESH_SECONDS`, `CREDENTIAL_STORE`(`keyring`|`memory`)

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_config.py`:

```python
import pytest

from agent.config import Config


def test_새_설정의_기본값(monkeypatch):
    for name in ("ENROLLMENT_TOKEN", "HEARTBEAT_INTERVAL_SECONDS", "POLICY_REFRESH_SECONDS", "CREDENTIAL_STORE"):
        monkeypatch.delenv(name, raising=False)

    config = Config.from_env()

    assert config.enrollment_token == ""
    assert config.heartbeat_interval_seconds == 60
    assert config.policy_refresh_seconds == 300
    assert config.credential_store == "keyring"


def test_새_설정을_환경변수에서_읽는다(monkeypatch):
    monkeypatch.setenv("ENROLLMENT_TOKEN", "enroll-ok")
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SECONDS", "30")
    monkeypatch.setenv("POLICY_REFRESH_SECONDS", "120")
    monkeypatch.setenv("CREDENTIAL_STORE", "Memory")

    config = Config.from_env()

    assert (config.enrollment_token, config.heartbeat_interval_seconds, config.policy_refresh_seconds) == (
        "enroll-ok",
        30,
        120,
    )
    assert config.credential_store == "memory"


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CREDENTIAL_STORE", "file"),
        ("HEARTBEAT_INTERVAL_SECONDS", "0"),
        ("POLICY_REFRESH_SECONDS", "nan"),
    ],
)
def test_잘못된_값은_시작_시_거부한다(monkeypatch, name, value):
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        Config.from_env()
```

- [ ] **Step 2: 실패 확인**

Run: `uv run --group dev pytest tests/test_config.py -q`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'enrollment_token'`

- [ ] **Step 3: 구현**

`src/agent/config.py` — `_validate_body_size_limit` 아래에 추가:

```python
_CREDENTIAL_STORES = {"keyring", "memory"}


def _parse_credential_store(raw: str, var_name: str) -> str:
    value = raw.strip().lower()
    if value not in _CREDENTIAL_STORES:
        raise ValueError(f"{var_name}는 keyring 또는 memory여야 한다: {raw!r}")
    return value
```

`Config` 필드 — `agent_token`의 주석을 바꾸고 새 필드를 끝에 더한다:

```python
    # 개발용 수동 주입. 비어 있지 않으면 등록·토큰 갱신을 건너뛰고 이 값을 쓴다.
    agent_token: str = ""
    ...
    body_size_limit: str = "500m"
    # 1회용 등록 토큰. 키체인에 자격 증명이 없을 때만 쓴다.
    enrollment_token: str = ""
    # 콘솔 PC 현황은 3분 안의 하트비트로 판단한다.
    heartbeat_interval_seconds: float = 60
    policy_refresh_seconds: float = 300
    # keyring(운영) 또는 memory(테스트·키체인 없는 개발 환경)
    credential_store: str = "keyring"
```

`from_env()`의 `Config(...)` 인자 끝에 더한다:

```python
            enrollment_token=os.environ.get("ENROLLMENT_TOKEN", ""),
            heartbeat_interval_seconds=_parse_positive_seconds(
                os.environ.get("HEARTBEAT_INTERVAL_SECONDS", "60"), "HEARTBEAT_INTERVAL_SECONDS"
            ),
            policy_refresh_seconds=_parse_positive_seconds(
                os.environ.get("POLICY_REFRESH_SECONDS", "300"), "POLICY_REFRESH_SECONDS"
            ),
            credential_store=_parse_credential_store(
                os.environ.get("CREDENTIAL_STORE", "keyring"), "CREDENTIAL_STORE"
            ),
```

- [ ] **Step 4: 통과 확인**

Run: `uv run --group dev pytest tests/test_config.py tests/test_verdict_client.py -q`
Expected: PASS

- [ ] **Step 5: 커밋**

```bash
git add src/agent/config.py tests/test_config.py
git commit -m "feat: 등록 토큰·하트비트·정책 갱신·자격 증명 저장소 설정"
```

---

### Task 6: AgentLifecycle

**Files:**
- Create: `src/agent/lifecycle.py`
- Test: `tests/test_lifecycle.py`

**Interfaces:**
- Consumes: `Config`(Task 5), `AgentClient`·`AgentServiceError`(Task 4), `CredentialStore`·`CredentialStoreError`·`Credentials`(Task 2), `AgentIdentity`(Task 3), `Policy`·`EMPTY_POLICY`(Task 1)
- Produces:
  - `AgentLifecycle(config: Config, client: AgentClient, store: CredentialStore, identity: AgentIdentity, *, clock: Callable[[], datetime] | None = None)`
  - `token() -> str` — 지금 쓸 토큰, 없으면 `""`. `VerdictClient`에 콜러블로 넘긴다
  - `policy: Policy` (property) — 기본 `EMPTY_POLICY`
  - `async start() -> None` — 절대 예외를 던지지 않는다. 자격 증명 확보 → 정책 1회 → 하트비트 1회 → 주기 작업 시작
  - `async stop() -> None` — 주기 작업 취소
  - `async heartbeat_once()`, `async refresh_token_if_due()`, `async refresh_policy_once()`, `async tick()` — 테스트에서 직접 부른다

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_lifecycle.py`:

```python
import asyncio
from datetime import UTC, datetime, timedelta

import grpc
import pytest
from fakes.verdict_server import create_server
from grpc import aio as grpc_aio

from agent.agent_client import AgentClient
from agent.config import Config
from agent.credentials import CredentialStoreError, MemoryStore
from agent.identity import AgentIdentity
from agent.lifecycle import AgentLifecycle
from agent.policy import EMPTY_POLICY
from teecher.agent.v1 import agent_pb2

IDENTITY = AgentIdentity("pc-1", agent_pb2.OS_PLATFORM_MACOS, "0.1.0", "HW-1")
SECURITY_UPDATE = agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


@pytest.fixture
async def env():
    server, port, verdict = await create_server()
    channel = grpc_aio.insecure_channel(f"127.0.0.1:{port}")
    lifecycles: list[AgentLifecycle] = []

    def make(store=None, clock=None, **config_kwargs) -> AgentLifecycle:
        config = Config(verdict_server_address=f"127.0.0.1:{port}", **config_kwargs)
        lifecycle = AgentLifecycle(config, AgentClient(channel, 5), store or MemoryStore(), IDENTITY, clock=clock)
        lifecycles.append(lifecycle)
        return lifecycle

    yield make, verdict.agent

    for lifecycle in lifecycles:
        await lifecycle.stop()
    await channel.close()
    await server.stop(None)


class FailingSaveStore(MemoryStore):
    def save(self, creds):
        raise CredentialStoreError("keychain locked")


async def test_자격_증명이_없으면_등록하고_저장한다(env):
    make, fake = env
    store = MemoryStore()
    lifecycle = make(store=store, enrollment_token="enroll-ok")

    await lifecycle.start()

    assert lifecycle.token() in fake.valid_tokens
    assert store.load() is not None and store.load().agent_token == lifecycle.token()
    assert len(fake.heartbeats) == 1
    assert fake.policy_calls == 1


async def test_저장된_자격_증명이_있으면_등록하지_않는다(env):
    make, fake = env
    first = make(enrollment_token="enroll-ok")
    await first.start()
    store = MemoryStore()
    store.save(first._creds)
    fake.enrollment_tokens.add("enroll-2")

    second = make(store=store, enrollment_token="enroll-2")
    await second.start()

    assert len(fake.registrations) == 1
    assert second.token() == first.token()


async def test_자격_증명도_등록_토큰도_없으면_빈_토큰으로_시작한다(env):
    make, fake = env
    lifecycle = make()

    await lifecycle.start()

    assert lifecycle.token() == ""
    assert lifecycle.policy is EMPTY_POLICY
    assert fake.heartbeats == []


async def test_등록에_실패하면_다음_주기에_다시_시도한다(env):
    make, fake = env
    lifecycle = make(enrollment_token="enroll-late")

    await lifecycle.start()
    assert lifecycle.token() == ""

    fake.enrollment_tokens.add("enroll-late")
    await lifecycle.tick()

    assert lifecycle.token() in fake.valid_tokens
    assert fake.policy_calls == 1  # 등록 직후 정책도 받는다


async def test_수명의_절반이_지나면_토큰을_갱신하고_저장한다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    store = MemoryStore()
    lifecycle = make(store=store, clock=lambda: now[0], enrollment_token="enroll-ok")
    await lifecycle.start()
    old = lifecycle.token()

    await lifecycle.refresh_token_if_due()
    assert lifecycle.token() == old  # 아직 절반 전

    now[0] += timedelta(hours=13)
    await lifecycle.refresh_token_if_due()

    assert lifecycle.token() != old
    assert old not in fake.valid_tokens
    assert store.load().agent_token == lifecycle.token()


async def test_토큰_갱신_실패는_기존_토큰을_유지한다(env):
    make, fake = env
    now = [datetime.now(UTC)]
    lifecycle = make(clock=lambda: now[0], enrollment_token="enroll-ok")
    await lifecycle.start()
    old = lifecycle.token()
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    now[0] += timedelta(hours=13)
    await lifecycle.refresh_token_if_due()

    assert lifecycle.token() == old


async def test_정책_수신_실패는_마지막_정책을_유지한다(env):
    make, fake = env
    fake.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE)]
    )
    lifecycle = make(enrollment_token="enroll-ok")
    await lifecycle.start()
    fake.fail_code = grpc.StatusCode.UNAVAILABLE

    await lifecycle.refresh_policy_once()

    assert lifecycle.policy.bypass_category("dl.google.com") == SECURITY_UPDATE


async def test_키체인_저장이_실패해도_메모리의_토큰으로_동작한다(env):
    make, fake = env
    lifecycle = make(store=FailingSaveStore(), enrollment_token="enroll-ok")

    await lifecycle.start()

    assert lifecycle.token() in fake.valid_tokens


async def test_AGENT_TOKEN을_주면_등록하지_않고_그_토큰을_쓴다(env):
    make, fake = env
    fake.valid_tokens.add("manual")
    lifecycle = make(agent_token="manual", enrollment_token="enroll-ok")

    await lifecycle.start()

    assert fake.registrations == []
    assert lifecycle.token() == "manual"
    assert fake.heartbeats == [("manual", "0.1.0")]


async def test_주기_작업은_예외에도_계속_돈다(env):
    make, fake = env
    lifecycle = make(enrollment_token="enroll-ok", heartbeat_interval_seconds=0.05, policy_refresh_seconds=0.05)
    await lifecycle.start()

    fake.fail_code = grpc.StatusCode.UNAVAILABLE
    await asyncio.sleep(0.2)
    fake.fail_code = None
    before = len(fake.heartbeats)
    await asyncio.sleep(0.2)

    assert len(fake.heartbeats) > before


async def test_stop하면_주기_작업이_멈춘다(env):
    make, fake = env
    lifecycle = make(enrollment_token="enroll-ok", heartbeat_interval_seconds=0.05)
    await lifecycle.start()
    await asyncio.sleep(0.15)

    await lifecycle.stop()
    count = len(fake.heartbeats)
    await asyncio.sleep(0.15)

    assert len(fake.heartbeats) == count
```

- [ ] **Step 2: 실패 확인**

Run: `uv run --group dev pytest tests/test_lifecycle.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.lifecycle'`

- [ ] **Step 3: 구현**

`src/agent/lifecycle.py`:

```python
"""에이전트 생명주기 — 자격 증명 확보(키체인 로드 또는 등록), 하트비트, 토큰 갱신, 정책 갱신.

판정 경로와 분리돼 있고, 여기서 무엇이 실패해도 다운로드는 막히는 쪽으로만 간다:
- 토큰이 없으면 VerdictService가 UNAUTHENTICATED를 돌려주고 VerdictClient가 fail-close로 차단한다
- 정책을 한 번도 못 받았으면 EMPTY_POLICY(바이패스 없음) — 모든 다운로드를 검사한다
어떤 메서드도 예외를 밖으로 던지지 않는다. 실패는 로그로 남기고 다음 주기에 다시 시도한다.
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from agent.agent_client import AgentClient, AgentServiceError
from agent.config import Config
from agent.credentials import Credentials, CredentialStore, CredentialStoreError
from agent.identity import AgentIdentity
from agent.policy import EMPTY_POLICY, Policy

logger = logging.getLogger(__name__)


class AgentLifecycle:
    def __init__(
        self,
        config: Config,
        client: AgentClient,
        store: CredentialStore,
        identity: AgentIdentity,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._config = config
        self._client = client
        self._store = store
        self._identity = identity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._creds: Credentials | None = None
        self._policy: Policy = EMPTY_POLICY
        self._tasks: list[asyncio.Task] = []

    def token(self) -> str:
        if self._config.agent_token:
            return self._config.agent_token
        return self._creds.agent_token if self._creds else ""

    @property
    def policy(self) -> Policy:
        return self._policy

    async def start(self) -> None:
        await self._ensure_credentials()
        await self.refresh_policy_once()
        await self.heartbeat_once()
        self._tasks = [
            asyncio.create_task(self._every(self._config.heartbeat_interval_seconds, self.tick)),
            asyncio.create_task(self._every(self._config.policy_refresh_seconds, self.refresh_policy_once)),
        ]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []

    async def tick(self) -> None:
        """하트비트 주기마다: 자격 증명이 없으면 다시 확보, 갱신 시점이면 갱신, 그리고 하트비트."""
        if not self.token():
            await self._ensure_credentials()
            if self.token():
                await self.refresh_policy_once()
        await self.refresh_token_if_due()
        await self.heartbeat_once()

    async def _every(self, interval: float, fn: Callable[[], Awaitable[None]]) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await fn()
            except Exception:
                logger.exception("주기 작업 실패 — 다음 주기에 다시 시도한다")

    async def _ensure_credentials(self) -> None:
        if self._config.agent_token:
            return
        try:
            self._creds = await asyncio.to_thread(self._store.load)
        except Exception:
            logger.exception("자격 증명 로드 실패")
            self._creds = None
        if self._creds is not None:
            return
        if not self._config.enrollment_token:
            logger.error("자격 증명이 없고 ENROLLMENT_TOKEN도 없다 — 모든 다운로드가 fail-close로 차단된다")
            return
        try:
            creds = await self._client.register(
                enrollment_token=self._config.enrollment_token, identity=self._identity
            )
        except AgentServiceError as exc:
            logger.error("에이전트 등록 실패: %s", exc)
            return
        self._creds = creds
        logger.info("에이전트 등록 완료: agent_id=%s", creds.agent_id)
        await self._save(creds)

    async def _save(self, creds: Credentials) -> None:
        try:
            await asyncio.to_thread(self._store.save, creds)
        except CredentialStoreError as exc:
            logger.error("자격 증명 저장 실패 — 이번 실행 동안은 메모리의 토큰을 쓴다: %s", exc)

    async def heartbeat_once(self) -> None:
        token = self.token()
        if not token:
            return
        try:
            await self._client.heartbeat(token, self._identity.agent_version)
        except AgentServiceError as exc:
            logger.warning("하트비트 실패: %s", exc)

    async def refresh_token_if_due(self) -> None:
        if self._config.agent_token or self._creds is None:
            return
        if not self._creds.refresh_due(self._clock()):
            return
        try:
            creds = await self._client.refresh_token(self._creds)
        except AgentServiceError as exc:
            logger.warning("토큰 갱신 실패 — 기존 토큰을 만료까지 쓴다: %s", exc)
            return
        self._creds = creds
        await self._save(creds)

    async def refresh_policy_once(self) -> None:
        token = self.token()
        if not token:
            return
        try:
            self._policy = await self._client.get_policy(token)
        except AgentServiceError as exc:
            logger.warning("정책 수신 실패 — 마지막으로 받은 정책을 유지한다: %s", exc)
```

- [ ] **Step 4: 통과 확인**

Run: `uv run --group dev pytest tests/test_lifecycle.py -q`
Expected: PASS (11 passed)

- [ ] **Step 5: 커밋**

```bash
git add src/agent/lifecycle.py tests/test_lifecycle.py
git commit -m "feat: 등록·하트비트·토큰 갱신·정책 갱신을 도는 AgentLifecycle"
```

---

### Task 7: HoldPipeline에 생명주기 연결

**Files:**
- Modify: `src/agent/verdict_client.py:38-52,129-130` (생성자, `_metadata`, `close`)
- Modify: `src/agent/addon.py` (`__init__`, `running`, `done`, `wait_started` 추가)
- Modify: `tests/test_addon.py` (`pipeline_factory`), `tests/test_addon_e2e.py` (`proxy` fixture), `tests/test_verdict_client.py`
- Modify: `compose.dev.yml`

**Interfaces:**
- Consumes: `AgentLifecycle`(Task 6), `AgentClient`(Task 4), `make_store`(Task 2), `current_identity`(Task 3)
- Produces:
  - `open_channel(config: Config) -> grpc_aio.Channel` (in `verdict_client.py`)
  - `VerdictClient(config, channel=None, token: Callable[[], str] | None = None)` — 주입된 채널은 `close()`가 닫지 않는다
  - `HoldPipeline.lifecycle: AgentLifecycle | None`, `async HoldPipeline.wait_started() -> None`

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_verdict_client.py` 끝에 추가:

```python
async def test_토큰_콜러블은_호출할_때마다_다시_읽는다(fake_server):
    port, servicer = fake_server
    current = ["tok-a"]
    client = VerdictClient(Config(verdict_server_address=f"127.0.0.1:{port}"), token=lambda: current[0])

    await client.check_hash("0" * 64, 10)
    assert servicer.last_metadata.get("authorization") == "Bearer tok-a"
    current[0] = "tok-b"
    await client.check_hash("0" * 64, 10)

    assert servicer.last_metadata.get("authorization") == "Bearer tok-b"
    await client.close()


async def test_주입된_채널은_close가_닫지_않는다(fake_server):
    port, _ = fake_server
    config = Config(verdict_server_address=f"127.0.0.1:{port}")
    channel = open_channel(config)
    client = VerdictClient(config, channel)

    await client.close()
    await VerdictClient(config, channel).check_hash("0" * 64, 10)  # 아직 쓸 수 있다

    await channel.close()
```

import 줄을 `from agent.verdict_client import CHUNK_SIZE, ReportFailed, VerdictClient, VerdictUnavailable, open_channel`로 바꾼다.

`tests/test_addon.py` — `pipeline_factory`의 `_make` 안, `setenv` 두 줄 아래에 추가:

```python
        monkeypatch.setenv("CREDENTIAL_STORE", "memory")
```

그리고 파일 끝에 추가:

```python
async def test_등록한_토큰으로_판정_RPC를_호출하고_하트비트를_보낸다(fake_server, pipeline_factory, monkeypatch):
    port, servicer = fake_server
    monkeypatch.setenv("ENROLLMENT_TOKEN", "enroll-ok")
    pipeline = pipeline_factory(port)
    await pipeline.wait_started()
    [token] = servicer.agent.valid_tokens

    await run_flow(pipeline, make_flow(CLEAN_BODY))

    assert servicer.last_metadata.get("authorization") == f"Bearer {token}"
    assert servicer.agent.heartbeats == [(token, "0.1.0")]
    assert servicer.agent.policy_calls == 1


async def test_자격_증명이_없으면_다운로드는_fail_close로_막힌다(fake_server, pipeline_factory, monkeypatch):
    # 가짜 VerdictService는 토큰을 검사하지 않으므로, 실서버의 UNAUTHENTICATED를 흉내 낸다
    port, servicer = fake_server
    monkeypatch.delenv("ENROLLMENT_TOKEN", raising=False)
    pipeline = pipeline_factory(port)
    await pipeline.wait_started()

    async def unauthenticated(*args, **kwargs):
        raise VerdictUnavailable("UNAUTHENTICATED")

    monkeypatch.setattr(pipeline.client, "check_hash", unauthenticated)
    flow = make_flow(CLEAN_BODY)

    await run_flow(pipeline, flow)

    assert pipeline.lifecycle.token() == ""
    assert flow.response.status_code == 403
```

`tests/test_addon.py` 상단의 `from agent.verdict_client import ReportFailed`를 `from agent.verdict_client import ReportFailed, VerdictUnavailable`로 바꾼다.

`tests/test_addon_e2e.py` — `proxy` fixture의 `setenv("BODY_SIZE_LIMIT", "64k")` 아래에 추가:

```python
    monkeypatch.setenv("CREDENTIAL_STORE", "memory")
```

- [ ] **Step 2: 실패 확인**

Run: `uv run --group dev pytest tests/test_verdict_client.py tests/test_addon.py -q`
Expected: FAIL — `ImportError: cannot import name 'open_channel'`, `AttributeError: 'HoldPipeline' object has no attribute 'wait_started'`

- [ ] **Step 3: 구현 — VerdictClient**

`src/agent/verdict_client.py` — import에 `from collections.abc import Callable` 추가. 생성자·`_metadata`·`close`를 바꾸고 `open_channel`을 더한다:

```python
def open_channel(config: Config) -> grpc_aio.Channel:
    """VerdictService와 AgentService가 같은 주소를 쓴다 — 채널 하나를 공유한다."""
    if config.verdict_server_tls:
        return grpc_aio.secure_channel(config.verdict_server_address, grpc.ssl_channel_credentials())
    return grpc_aio.insecure_channel(config.verdict_server_address)


class VerdictClient:
    def __init__(
        self,
        config: Config,
        channel: grpc_aio.Channel | None = None,
        token: Callable[[], str] | None = None,
    ) -> None:
        self._config = config
        # 주입된 채널은 주인(HoldPipeline)이 닫는다.
        self._owns_channel = channel is None
        self._channel = channel if channel is not None else open_channel(config)
        self._stub = verdict_pb2_grpc.VerdictServiceStub(self._channel)
        # 토큰은 AgentLifecycle이 갱신하므로 호출할 때마다 다시 읽는다.
        self._token = token or (lambda: config.agent_token)

    def _metadata(self) -> list[tuple[str, str]] | None:
        token = self._token()
        if not token:
            return None
        return [("authorization", f"Bearer {token}")]
```

```python
    async def close(self) -> None:
        if self._owns_channel:
            await self._channel.close()
```

- [ ] **Step 4: 구현 — HoldPipeline**

`src/agent/addon.py` — import 추가:

```python
from grpc import aio as grpc_aio

from agent.agent_client import AgentClient
from agent.credentials import make_store
from agent.identity import current_identity
from agent.lifecycle import AgentLifecycle
from agent.verdict_client import VerdictClient, open_channel
```

`__init__`에 필드 추가:

```python
        self.lifecycle: AgentLifecycle | None = None
        self._channel: grpc_aio.Channel | None = None
        self._lifecycle_task: asyncio.Task | None = None
```

`running()`의 `self.client = VerdictClient(self.config)` 한 줄을 다음으로 바꾼다:

```python
        # grpc.aio 채널은 실행 중인 루프에 묶인다 — running() 안에서 만든다.
        self._channel = open_channel(self.config)
        self.lifecycle = AgentLifecycle(
            self.config,
            AgentClient(self._channel, self.config.rpc_timeout_seconds),
            make_store(self.config.credential_store),
            current_identity(),
        )
        self.client = VerdictClient(self.config, self._channel, token=self.lifecycle.token)
        # 등록·정책 수신은 기동을 막지 않는다. 끝나기 전의 다운로드는 토큰 없음(fail-close)·바이패스 없음이다.
        self._lifecycle_task = asyncio.create_task(self.lifecycle.start())
```

(기존의 `# grpc.aio 채널은 ...` 주석 줄은 위로 옮겼으니 지운다.)

`done()`을 바꾼다:

```python
    async def done(self) -> None:
        if self._lifecycle_task is not None:
            self._lifecycle_task.cancel()
            await asyncio.gather(self._lifecycle_task, return_exceptions=True)
        if self.lifecycle is not None:
            await self.lifecycle.stop()
        await self.drain_reports()
        if self.client is not None:
            await self.client.close()
        if self._channel is not None:
            await self._channel.close()

    async def wait_started(self) -> None:
        """AgentLifecycle.start()가 끝날 때까지 기다린다. 테스트에서 쓴다."""
        if self._lifecycle_task is not None:
            await self._lifecycle_task
```

- [ ] **Step 5: 개발 환경 설정**

`compose.dev.yml` — `environment:`의 `VERDICT_SERVER_ADDRESS` 아래에 추가:

```yaml
      # 컨테이너에는 OS 키체인이 없다 — 자격 증명은 메모리에만 (재시작하면 다시 등록)
      CREDENTIAL_STORE: memory
      ENROLLMENT_TOKEN: ${ENROLLMENT_TOKEN:-}
      AGENT_TOKEN: ${AGENT_TOKEN:-}
```

- [ ] **Step 6: 통과 확인**

Run: `uv run --group dev pytest -q`
Expected: PASS — 전체(기존 + Task 1~7), Windows 전용 1개 skip

- [ ] **Step 7: 커밋**

```bash
git add src/agent/verdict_client.py src/agent/addon.py tests/test_verdict_client.py tests/test_addon.py tests/test_addon_e2e.py compose.dev.yml
git commit -m "feat: 보류 파이프라인이 기동 시 에이전트 생명주기를 띄우고 그 토큰으로 판정을 요청"
```

---

### Task 8: 바이패스 정책 적용

**Files:**
- Modify: `src/agent/addon.py` (`responseheaders`, `tls_clienthello` 추가, `_bypass` 추가)
- Test: `tests/test_bypass.py` (신규)

**Interfaces:**
- Consumes: `HoldPipeline.lifecycle.policy`(Task 7), `Policy.bypass_category`(Task 1)
- Produces:
  - `HoldPipeline.tls_clienthello(data: tls.ClientHelloData) -> None` — PINNED면 `data.ignore_connection = True`
  - 바이패스된 다운로드의 ReportEvent: `decision=FINAL_DECISION_BYPASSED`, `decision_source=DECISION_SOURCE_POLICY`, `sha256=""`, `file_size`=Content-Length(없거나 잘못되면 0)
  - 상수 `BYPASS_REASONS: dict[int, str]`

- [ ] **Step 1: 실패하는 테스트 작성**

`tests/test_bypass.py`:

```python
from types import SimpleNamespace

import pytest
from fakes.verdict_server import create_server
from mitmproxy.addons.proxyserver import Proxyserver
from mitmproxy.test import taddons
from test_addon import CLEAN_BODY, make_flow

from agent.addon import HOLD_KEY, HoldPipeline
from teecher.agent.v1 import agent_pb2
from teecher.verdict.v1 import verdict_pb2

PINNED = agent_pb2.BYPASS_CATEGORY_PINNED
SECURITY_UPDATE = agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE


@pytest.fixture
async def pipeline(monkeypatch):
    """dl.google.com=SECURITY_UPDATE, pinned.example=PINNED 정책을 받은 파이프라인."""
    server, port, servicer = await create_server()
    servicer.agent.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[
            agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE),
            agent_pb2.BypassHost(host="pinned.example", category=PINNED),
        ]
    )
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
    monkeypatch.setenv("CREDENTIAL_STORE", "memory")
    monkeypatch.setenv("ENROLLMENT_TOKEN", "enroll-ok")
    p = HoldPipeline()
    taddons.context(Proxyserver(), p)
    p.running()
    await p.wait_started()

    async def no_rpc(*args, **kwargs):
        raise AssertionError("바이패스된 flow가 판정 RPC를 호출했다")

    monkeypatch.setattr(p.client, "check_hash", no_rpc)
    monkeypatch.setattr(p.client, "submit_file", no_rpc)
    yield p, servicer
    await p.done()
    await server.stop(None)


def at_host(flow, host: str, connect_host: str | None = None):
    flow.request.host = host
    flow.server_conn.address = (connect_host or host, 443)
    return flow


async def test_SECURITY_UPDATE_호스트의_다운로드는_보류_없이_흘려보내고_BYPASSED로_보고한다(pipeline):
    p, servicer = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com")

    p.responseheaders(flow)
    await p.response(flow)
    await p.drain_reports()

    assert flow.response.stream is True
    assert HOLD_KEY not in flow.metadata
    [event] = servicer.report_events
    assert event.decision == verdict_pb2.FINAL_DECISION_BYPASSED
    assert event.decision_source == verdict_pb2.DECISION_SOURCE_POLICY
    assert event.sha256 == ""
    assert event.file_size == len(CLEAN_BODY)
    assert event.request_host == "dl.google.com"


async def test_바이패스_호스트의_비다운로드는_보고하지_않는다(pipeline):
    p, servicer = pipeline
    flow = at_host(make_flow(b"{}", content_type="application/json", attachment=False), "dl.google.com")

    p.responseheaders(flow)
    await p.drain_reports()

    assert flow.response.stream is True
    assert servicer.report_events == []


async def test_하위_도메인은_바이패스하지_않는다(pipeline):
    p, _ = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "x.dl.google.com")

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata


async def test_Host_헤더와_연결_대상이_다르면_바이패스하지_않는다(pipeline):
    p, _ = pipeline
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com", connect_host="evil.example")

    p.responseheaders(flow)

    assert flow.response.stream is False
    assert HOLD_KEY in flow.metadata


async def test_정책을_받기_전에는_바이패스하지_않는다(monkeypatch):
    server, port, servicer = await create_server()
    servicer.agent.policy = agent_pb2.GetPolicyResponse(
        bypass_hosts=[agent_pb2.BypassHost(host="dl.google.com", category=SECURITY_UPDATE)]
    )
    monkeypatch.setenv("VERDICT_SERVER_ADDRESS", f"127.0.0.1:{port}")
    monkeypatch.setenv("CREDENTIAL_STORE", "memory")
    monkeypatch.delenv("ENROLLMENT_TOKEN", raising=False)  # 등록 못 함 → 정책 못 받음
    p = HoldPipeline()
    taddons.context(Proxyserver(), p)
    p.running()
    await p.wait_started()
    flow = at_host(make_flow(CLEAN_BODY), "dl.google.com")

    p.responseheaders(flow)

    assert flow.response.stream is False
    await p.done()
    await server.stop(None)


def clienthello(connect_host: str | None, sni: str | None):
    return SimpleNamespace(
        context=SimpleNamespace(server=SimpleNamespace(address=(connect_host, 443) if connect_host else None)),
        client_hello=SimpleNamespace(sni=sni),
        ignore_connection=False,
    )


async def test_PINNED_호스트는_TLS를_풀지_않는다(pipeline):
    p, _ = pipeline
    data = clienthello("pinned.example", "pinned.example")

    p.tls_clienthello(data)

    assert data.ignore_connection is True


@pytest.mark.parametrize(
    ("connect_host", "sni"),
    [("dl.google.com", "dl.google.com"), ("other.example", "other.example"), ("x.pinned.example", "x.pinned.example")],
)
async def test_PINNED가_아니면_가로챈다(pipeline, connect_host, sni):
    p, _ = pipeline
    data = clienthello(connect_host, sni)

    p.tls_clienthello(data)

    assert data.ignore_connection is False


async def test_SNI만_PINNED_호스트면_가로챈다(pipeline):
    p, _ = pipeline
    data = clienthello("evil.example", "pinned.example")

    p.tls_clienthello(data)

    assert data.ignore_connection is False
```

`from test_addon import ...`는 `from fakes...`와 같은 이유로 된다 — `tests/`에 `__init__.py`가 없어 pytest(기본 prepend import 모드)가 `tests/`를 sys.path에 넣는다. 모듈을 import해도 그 파일의 테스트가 다시 수집되지는 않는다.

- [ ] **Step 2: 실패 확인**

Run: `uv run --group dev pytest tests/test_bypass.py -q`
Expected: FAIL — `AttributeError: 'HoldPipeline' object has no attribute 'tls_clienthello'`, SECURITY_UPDATE 테스트는 `stream is False`로 실패

- [ ] **Step 3: 구현**

`src/agent/addon.py` — import에 `from mitmproxy import ctx, exceptions, http, tls`(tls 추가), `from agent.policy import EMPTY_POLICY, Policy`, `from teecher.agent.v1 import agent_pb2` 추가. 상수 추가:

```python
BYPASS_REASONS = {
    agent_pb2.BYPASS_CATEGORY_PINNED: "pinned host bypass",
    agent_pb2.BYPASS_CATEGORY_SECURITY_UPDATE: "security update bypass",
}


def _content_length(headers) -> int:
    try:
        return max(int(headers.get("content-length", "0")), 0)
    except ValueError:
        return 0


def _connect_host(flow: http.HTTPFlow) -> str:
    # 실제로 연결한 대상. Host 헤더는 클라이언트가 임의로 적을 수 있다(설계 system-flow 156행).
    address = flow.server_conn.address if flow.server_conn else None
    return address[0] if address else ""
```

`HoldPipeline`에 메서드 추가:

```python
    def _policy(self) -> Policy:
        return self.lifecycle.policy if self.lifecycle is not None else EMPTY_POLICY

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        # 인증서를 고정한 앱은 가로채면 연결이 깨진다 — TLS를 풀지 않고 그대로 흘려보낸다.
        # 호스트는 CONNECT 대상(실제 연결할 곳)만 본다. SNI는 클라이언트가 임의로 적을 수 있다.
        try:
            address = data.context.server.address
            host = address[0] if address else ""
            if host and self._policy().bypass_category(host) == agent_pb2.BYPASS_CATEGORY_PINNED:
                data.ignore_connection = True
                logger.info("PINNED 바이패스: %s", host)
        except Exception:
            # 판단에 실패하면 가로챈다(검사하는 쪽).
            logger.exception("PINNED 바이패스 판단 실패")

    def _bypass_category(self, flow: http.HTTPFlow) -> int | None:
        policy = self._policy()
        category = policy.bypass_category(_connect_host(flow))
        # 연결 대상과 요청 호스트가 둘 다 같은 바이패스 호스트일 때만 인정한다.
        if category is None or policy.bypass_category(flow.request.host) != category:
            return None
        return category

    def _bypass(self, flow: http.HTTPFlow, category: int) -> None:
        flow.metadata[PASSTHROUGH_KEY] = True
        flow.response.stream = True
        try:
            if not is_download(flow.request.headers, flow.response.headers).is_download:
                return
            hold = _snapshot(flow)
            hold.file_size = _content_length(flow.response.headers)
            self._schedule_report(
                hold,
                Outcome(verdict_pb2.FINAL_DECISION_BYPASSED, verdict_pb2.DECISION_SOURCE_POLICY, BYPASS_REASONS[category]),
            )
        except Exception:
            logger.exception("바이패스 이벤트 보고 준비 실패: %s", flow.request.pretty_url)
```

`responseheaders()` 맨 앞(기존 주석 위)에 추가:

```python
        try:
            category = self._bypass_category(flow)
        except Exception:
            logger.exception("바이패스 판단 실패 — 바이패스하지 않는다: %s", flow.request.pretty_url)
            category = None
        if category is not None:
            self._bypass(flow, category)
            return
```

- [ ] **Step 4: 통과 확인**

Run: `uv run --group dev pytest -q && uv run --group dev ruff check . && uv run --group dev ruff format --check .`
Expected: 전체 PASS, ruff 통과

- [ ] **Step 5: 커밋**

```bash
git add src/agent/addon.py tests/test_bypass.py
git commit -m "feat: PINNED는 TLS를 풀지 않고 바이패스 호스트는 보류 없이 흘려보냄"
```

---

### Task 9: 문서

**Files:**
- Modify: `platform-agent/README.md`, `platform-agent/CLAUDE.md:22`
- Modify: `project/README.md:76` (설계 레포)

- [ ] **Step 1: platform-agent README에 환경변수 추가**

README에 환경변수 표가 없으면 "실행" 절 아래에 다음 표를 새로 넣는다(있으면 행만 추가):

```markdown
| 환경변수 | 기본값 | 설명 |
|---|---|---|
| `VERDICT_SERVER_ADDRESS` | `localhost:9090` | 검사 서버 gRPC 주소 (VerdictService·AgentService 공용) |
| `VERDICT_SERVER_TLS` | `false` | gRPC TLS |
| `ENROLLMENT_TOKEN` | (없음) | 1회용 등록 토큰. 키체인에 자격 증명이 없을 때만 쓴다 |
| `AGENT_TOKEN` | (없음) | 개발용 수동 주입. 있으면 등록·토큰 갱신을 건너뛴다 |
| `CREDENTIAL_STORE` | `keyring` | `keyring`(OS 키체인) 또는 `memory`(키체인 없는 개발 환경) |
| `HEARTBEAT_INTERVAL_SECONDS` | `60` | 하트비트·토큰 갱신 확인 주기 |
| `POLICY_REFRESH_SECONDS` | `300` | 정책 재수신 주기 |
| `HOLD_TIMEOUT_SECONDS` | `120` | 보류 최대 시간 |
| `RPC_TIMEOUT_SECONDS` | `10` | 단건 RPC 타임아웃 |
| `BODY_SIZE_LIMIT` | `500m` | 검사 대상 본문 상한 (초과는 차단) |
```

- [ ] **Step 2: 저장 원칙의 예외를 두 곳에 적는다**

`platform-agent/CLAUDE.md` 22행의 "영속 저장소를 두지 않는다" 항목 끝에 한 줄 추가:

```markdown
  예외는 하나 — `agent_token`(자격 증명)은 OS 키체인에 둔다(`src/agent/credentials.py`, 2026-09-29 결정). 평문 파일 금지.
```

`project/README.md` 76행을 다음으로 바꾼다:

```markdown
- **에이전트에 영속 저장소를 두지 않는다.** 판정 캐시(SQLite)도 스풀 상태 DB도 없다. 예외는 `agent_token`
  하나로, OS 키체인에 둔다(2026-09-29). 정책은 메모리에만 두고 기동 시·5분마다 다시 받는다
```

같은 파일 "지금 열려 있는 것"에 한 줄 추가:

```markdown
- **`file_type_policies` 적용 위치** — 에이전트는 받아 보관만 한다(2026-09-29). 유형 판단 근거가 공격자가 정한
  MIME·확장자뿐이라 검사를 줄이는 값을 따르면 우회 경로가 된다. `file_type` 값 정의와 서버 측 적용 방안이 필요하다
```

- [ ] **Step 3: 커밋**

```bash
# platform-agent
git add README.md CLAUDE.md
git commit -m "docs: 생명주기 환경변수와 자격 증명 저장 예외"
# project (설계 레포)
git add README.md
git commit -m "Record the keychain exception and the file type policy deferral"
```

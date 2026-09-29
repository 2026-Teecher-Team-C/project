"""B안 스파이크 — 헤더를 붙잡은 채 본문을 디스크로 스풀하고, 판정 후 스풀에서 역압을 지키며 내보낸다.

mitmproxy 12.2.3 내부(HttpStream, ConnectionHandler)를 패치한다. 공개 API가 아니다.

  mitmdump -s spool_addon.py --set body_size_limit=500m

URL에 `block`이 있으면 차단(403), 아니면 통과. 판정은 HOLD_SECONDS 동안 기다리는 흉내다.
"""

import asyncio
import hashlib
import logging
import os
import stat
import time
import uuid

from mitmproxy import http
from mitmproxy.proxy import commands, events, server
from mitmproxy.proxy.layers import http as httplayer
from mitmproxy.proxy.layers.http import (
    HttpResponseHook,
    ResponseData,
    ResponseHeaders,
    ResponseTrailers,
    SendHttp,
)
from mitmproxy.proxy.layers.http._events import ResponseEndOfMessage

logger = logging.getLogger("spike")

SPOOL_DIR = os.path.join(os.path.dirname(__file__), "spool.noindex")  # .noindex: Spotlight 제외
DISK_LIMIT = 8 * 1024**3
RELEASE_CHUNK = 1024 * 1024
HOLD_SECONDS = 1.0
KEY_LEN = 32
NOXOR = bool(os.environ.get("SPIKE_NOXOR"))


class Spool:
    """UUID.tmp, 0600, 실행 비트 없음, XOR 인코딩. 쓰면서 SHA-256을 같이 계산한다(원본 바이트 기준)."""

    def __init__(self):
        os.makedirs(SPOOL_DIR, mode=0o700, exist_ok=True)
        self.path = os.path.join(SPOOL_DIR, f"{uuid.uuid4().hex}.tmp")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self.f = os.fdopen(fd, "wb", buffering=0)
        self.key = os.urandom(KEY_LEN)
        self.sha = hashlib.sha256()
        self.size = 0
        self.rf = None
        self.roff = 0

    def _xor(self, data: bytes, off: int) -> bytes:
        if NOXOR:
            return data
        k = off % KEY_LEN
        reps = (len(data) + k) // KEY_LEN + 1
        ks = (self.key * reps)[k : k + len(data)]
        n = len(data)
        return (int.from_bytes(data, "little") ^ int.from_bytes(ks, "little")).to_bytes(n, "little")

    def write(self, data: bytes) -> None:
        self.sha.update(data)
        self.f.write(self._xor(data, self.size))
        self.size += len(data)

    def finish(self) -> None:
        self.f.close()

    def read(self, n: int) -> bytes:
        if self.rf is None:
            self.rf = open(self.path, "rb", buffering=0)
        enc = self.rf.read(n)
        out = self._xor(enc, self.roff)
        self.roff += len(enc)
        return out

    def discard(self) -> None:
        for fh in (self.f, self.rf):
            if fh is not None and not fh.closed:
                fh.close()
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass


HS = httplayer.HttpStream
_orig_handle_event = HS._handle_event
_orig_consume = HS.state_consume_response_body
_orig_send_response = HS.send_response
_orig_check_body_size = HS.check_body_size


def _handle_event(self, event):
    # Wakeup은 HttpEvent가 아니라 원래 _handle_event의 @expect가 거부한다. 방출 중일 때만 가로챈다.
    # HttpStream에 오는 Wakeup은 전부 방출이 요청한 것이다. 방출이 끊김으로 취소된 뒤 늦게 온 것은 버린다.
    if isinstance(event, events.Wakeup):
        if getattr(self, "_spool_releasing", False):
            yield from self._spool_release_step()
        return
    yield from _orig_handle_event(self, event)


def check_body_size(self, request):
    # 응답 본문은 메모리에 쌓지 않으므로(다운로드=스풀, 비다운로드=stream) 메모리 상한 검사를 건너뛴다.
    if not request:
        return False
    return (yield from _orig_check_body_size(self, request))


def state_consume_response_body(self, event):
    if not self.flow.metadata.get("spool"):
        return (yield from _orig_consume(self, event))
    sp = getattr(self, "_spool", None)
    if sp is None:
        sp = self._spool = Spool()
        self.flow.metadata["spool_path"] = sp.path
    if isinstance(event, ResponseData):
        sp.write(event.data)
        if sp.size > DISK_LIMIT:
            sp.discard()
            raise RuntimeError("disk limit")  # 스파이크: 다루지 않음
    elif isinstance(event, ResponseTrailers):
        self.flow.response.trailers = event.trailers
    elif isinstance(event, ResponseEndOfMessage):
        sp.finish()
        self.flow.metadata["spool_sha256"] = sp.sha.hexdigest()
        self.flow.metadata["spool_size"] = sp.size
        self.flow.response.data.content = b""
        yield from self.send_response()


def send_response(self, already_streamed=False):
    sp = getattr(self, "_spool", None)
    if sp is None or already_streamed:
        return (yield from _orig_send_response(self, already_streamed))

    self.flow.response.timestamp_end = time.time()
    yield HttpResponseHook(self.flow)  # 애드온이 판정을 기다리는 동안 헤더는 나가지 않는다
    self.server_state = self.state_done
    if (yield from self.check_killed(False)):
        sp.discard()
        return

    if not self.flow.metadata.get("spool_release"):
        # 차단: 애드온이 응답을 403으로 바꿨다. 원래 send_response의 비스트리밍 경로와 같다.
        sp.discard()
        self._spool = None
        content = self.flow.response.raw_content
        yield SendHttp(ResponseHeaders(self.stream_id, self.flow.response, not content), self.context.client)
        if content:
            yield SendHttp(ResponseData(self.stream_id, content), self.context.client)
        if self.client_state == self.state_done:
            yield from self.flow_done()
        return

    yield SendHttp(ResponseHeaders(self.stream_id, self.flow.response, False), self.context.client)
    self._spool_releasing = True
    self.server_state = _releasing_state
    yield from self._spool_release_step()


def _releasing_state(event):
    # 방출 중 도착한 서버 쪽 이벤트는 없다(본문은 다 받았다). 자리표시자.
    return
    yield


def _spool_release_step(self):
    sp = self._spool
    data = sp.read(RELEASE_CHUNK)
    if data:
        yield SendHttp(ResponseData(self.stream_id, data), self.context.client)
        yield commands.RequestWakeup(0)  # 다음 청크는 drain 이후 — ConnectionHandler.wakeup 패치 참고
        return
    self._spool_releasing = False
    sp.discard()
    self._spool = None
    self.server_state = self.state_done
    if self.flow.response.trailers:
        yield SendHttp(ResponseTrailers(self.stream_id, self.flow.response.trailers), self.context.client)
    if self.client_state == self.state_done:
        yield from self.flow_done()


_orig_protocol_error = HS.handle_protocol_error


def handle_protocol_error(self, event):
    # 클라이언트가 방출 중(또는 보류 중)에 끊으면 스풀을 지운다.
    sp = getattr(self, "_spool", None)
    if sp is not None:
        self._spool_releasing = False
        sp.discard()
        self._spool = None
    yield from _orig_protocol_error(self, event)


HS.handle_protocol_error = handle_protocol_error
HS._handle_event = _handle_event
HS.check_body_size = check_body_size
HS.state_consume_response_body = state_consume_response_body
HS.send_response = send_response
HS._spool_release_step = _spool_release_step

_orig_wakeup = server.ConnectionHandler.wakeup


async def wakeup(self, request):
    # 원래는 소켓 읽기 사이에만 drain한다. 방출은 읽기 없이 이어지므로 여기서 역압을 건다.
    await asyncio.sleep(request.delay)
    await self.drain_writers()
    task = asyncio.current_task()
    self.wakeup_timer.discard(task)
    await self.server_event(events.Wakeup(request))


server.ConnectionHandler.wakeup = wakeup


class SpoolHold:
    def requestheaders(self, flow: http.HTTPFlow):
        flow.request.stream = True

    def responseheaders(self, flow: http.HTTPFlow):
        if "/dl" in flow.request.path:
            flow.metadata["spool"] = True
        else:
            flow.response.stream = True

    async def response(self, flow: http.HTTPFlow):
        if not flow.metadata.get("spool"):
            return
        path = flow.metadata.get("spool_path")
        st = os.stat(path)
        with open(path, "rb") as f:
            head = f.read(16)
        logger.warning(
            "보류 중 스풀: %s mode=%s size=%d head=%s sha256=%s",
            os.path.basename(path),
            oct(stat.S_IMODE(st.st_mode)),
            st.st_size,
            head.hex(),
            flow.metadata["spool_sha256"],
        )
        await asyncio.sleep(HOLD_SECONDS)
        if "block" in flow.request.path:
            flow.response = http.Response.make(403, b"blocked by spike\n", {"Content-Type": "text/plain"})
        else:
            flow.metadata["spool_release"] = True


addons = [SpoolHold()]

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

No source code exists yet. The repository currently contains only the design document
`프록시-악성코드-탐지-플랫폼.md` (Korean) describing the system to be built. There is no build
tooling, package manifest, or test suite to run — check back in this file once implementation
starts and update the commands/architecture sections accordingly.

## What this project is

A proxy-based malware download detection platform: it intercepts file downloads at the OS proxy
layer *before bytes reach the browser/disk*, holds the HTTP response, verifies the file is safe,
and only then releases the response so the browser can save it. Because it sits at the OS proxy
layer rather than as a browser extension, it covers all traffic through that layer (`curl`,
`wget`, game launchers, updaters), not just browser downloads.

Core insight driving the design: a browser writes bytes to disk as they arrive, so inspection
must happen before the response is forwarded — a proxy that withholds the response until a
verdict is reached is the only place this check can happen without browser or kernel changes.

## Planned system components

- **로컬 에이전트 (local agent / proxy)** — intercepts download traffic, distinguishes downloads
  from other traffic (`Content-Disposition`, MIME, size) to pass non-downloads through
  immediately, spools the file to a temp location while streaming a SHA-256 hash in a single
  pass, and keeps a local SQLite verdict cache as a fallback when the inspection server is down.
- **검사 서버 (inspection server, Spring Boot)** — hash lookup API backed by a Redis bloom filter
  for fast pre-filtering, receives full file uploads only on cache miss (WebFlux streaming), then
  runs magic-byte type detection → PE header parsing → section entropy → YARA rule matching, and
  caches/records verdicts.
- **관리 콘솔 (admin console, React)** — live blocked-event stream (SSE), policy editing (per-type
  inspection level, bypass domains), quarantine management / false-positive restoration, and a
  threat/performance dashboard (overhead, p99 latency, cache hit rate).

## Data flow

Origin server → proxy intercepts (response withheld from browser) → spool to disk + streaming
SHA-256 → hash lookup (bloom filter → exact lookup) → on cache miss, upload to inspection server →
PE analysis + YARA matching → malicious: quarantine + 403 to browser; safe: release the held
response so the browser resumes and saves the file itself. The file is written to disk twice: once
into the proxy spool, once into the browser's own temp/download path — the proxy never controls
final file placement.

## Key design constraints (read before touching related code)

- **Full binary payloads are never parsed by the local agent.** Any parsing of untrusted file
  content (PE headers, entropy, decompression, YARA) belongs in the inspection server, ideally in
  an isolated process with memory/CPU/time limits, to keep the local agent's attack surface
  minimal. Do not add file-format parsing to the proxy/agent side.
- **Spooled files must stay inert.** Naming (`UUID.tmp`), permissions (`0600`, no exec bit), XOR
  encoding of spooled bytes, and exclusion from OS indexing are all deliberate — the goal is that
  no automatic parser (indexer, thumbnailer, AV) ever treats a pending file as something to
  process (see CVE-2010-2568, CVE-2017-11421, CVE-2017-0290 in the design doc for the threat this
  addresses). Preserve these properties in any spool-handling code.
- **Header/response-holding timing is a hard constraint.** Once HTTP response headers are sent to
  the browser, a blocking response can no longer be constructed — the hold must happen before
  headers go out, trading off against timeout/UX behavior.
- **Local vs. server boundary is a 3-stage pipeline** (local filter → hash lookup → conditional
  upload) specifically to avoid doubling bandwidth by uploading every file in full.
- **Failure policy for the inspection server is fixed fail-close** (2026-09-18 decision). When the
  inspection server is unreachable, downloads are blocked — there is no fail-open option, no policy
  toggle, and no circuit-breaker/local-cache mitigation. Do not reintroduce a configurable failure
  mode. The accepted cost is that an inspection-server outage stops downloads entirely.
- **Bloom filters can't delete entries**, so false-positive restoration/whitelisting must be a
  separate layer from the bloom filter, not a mutation of it.
- Out of scope by design (do not attempt to "fix"): QUIC/HTTP3 traffic, pinned apps, programs that
  bypass the OS proxy setting, Range-split downloads (hash can't be computed from partial
  connections), non-network file introduction (USB, local copy), fileless attacks/zero-days,
  second-stage dropper payloads, and runtime behavioral analysis (that's EDR's job).

## Reference systems mentioned in the design

mitmproxy (TLS interception structure), Squid + ICAP (forward proxy + external inspection
pattern), Zscaler/Netskope (commercial SWG this reimagines for a single endpoint). Note this
system is a *forward* proxy that withholds and fully buffers response bodies until cleared —
the opposite goal of a reverse proxy like nginx, which optimizes for passing bytes through fast.

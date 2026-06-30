# Emulation Watchpoints, Auto-Stack, and PEB/TEB Scaffold Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the P2 ergonomics gaps an external RE session hit while trying to unpack a
packed Windows x64 binary with GhydraMCP's dynamic-analysis tools: `emulation_reset` silently
leaves RSP at 0 even though the server already supports auto-stack, neither emulation engine can
stop early when a specific buffer gets written (forcing slow full-instruction tracing to find
"who wrote 0x223018"), and Unicorn faults immediately on any PEB-walk import resolver because
GS-relative memory is unmapped.

**Architecture:** Four independent, additive features layered onto the existing two engines
(`EmulationService.java` for PCode emulation, `ghydra/dynamic/unicorn_engine.py` for Unicorn).
Each is a pure extension — no existing endpoint's default behavior changes except auto-stack
(opt-out, not opt-in, see Task 1). `format_dynamic_state` (added in the `v3.4.1` formatter fix)
already renders arbitrary nested dict/list fields, so new response fields (`watchHit`,
`watch_hit`) need no further bridge-formatter work — only new tool parameters and request-body
wiring.

**Tech Stack:** Java 21 / Ghidra `EmulatorHelper` (PCode) for Tasks 1–2; Python 3.11 / Unicorn
Engine 2.x for Tasks 3–4; pytest for Python, JUnit 4 for Java; existing root-level
`test_emulation.py` integration tier (live Ghidra, auto-skip) for Task 2's live-loop behavior.

## Global Constraints

- Bridge-only changes bump `BRIDGE_VERSION` in `bridge_mcp_hydra.py`; any change touching
  `src/main/java/` also bumps `PLUGIN_VERSION` in `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`
  (currently `v3.3.0`). `API_VERSION` stays unchanged — every change here is additive
  (new optional request fields, new response fields, new tools).
- TDD per `superpowers:test-driven-development`: write the test, watch it fail for the right
  reason, then implement.
- Pure-logic Java goes through JUnit (`src/test/java`, runs via `mvn test`, no live Ghidra). Any
  logic that needs a live `Program`/`EmulatorHelper` (the `run()` loop itself) is **not**
  JUnit-testable in this codebase's existing pattern (see `EmulationServiceTest.java`: it only
  covers static helpers) — verify that logic through the existing root-level
  `test_emulation.py` integration tier instead, which auto-skips when Ghidra isn't reachable.
- Unicorn-engine logic is fully unit-testable offline (`tests/test_unicorn_engine.py`,
  `pytest.importorskip("unicorn")`, no Ghidra needed) — prefer this tier for Tasks 3–4.
- Bridge wiring (new tool parameters, request-body construction) is unit-testable offline via
  `monkeypatch.setattr(b, "safe_post", ...)` capturing the request body, following
  `tests/test_bridge_batch.py`'s `test_functions_rename_batch_builds_patch_requests` pattern.
- Conventional-commit messages; update `CHANGELOG.md` under a new version section per the
  existing `## [x.y.z] - YYYY-MM-DD` format.
- Update `GHIDRA_HTTP_API.md`/`GHYDRA_CLI.md` for any new REST field or MCP tool parameter, per
  repo convention (reference docs listed in `CLAUDE.md`).

---

## File Structure

| File | Responsibility |
|---|---|
| `bridge_mcp_hydra.py` | MCP tool surface: `emulation_reset`/`emulation_run` get new params; new `unicorn_run` watch params; new `unicorn_setup_peb` tool; `_unicorn_run_result` learns `WATCHPOINT`. |
| `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java` | New `StopReason.WATCHPOINT`, new nested `WatchHit` record, new field + factory overload on the DTO. |
| `src/main/java/eu/starsong/ghidra/service/EmulationService.java` | `run()` grows optional watch-address/length params; compare-before/after memory snapshot detects the write; `Session` carries the pending `WatchHit`. |
| `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java` | `RunRequest` DTO grows `watch_address`/`watch_length` fields, threaded into `service.run(...)`. |
| `ghydra/dynamic/unicorn_engine.py` | New `StopReason.WATCHPOINT`; `run()` grows `watch_start`/`watch_length`, reuses the existing `UC_HOOK_MEM_WRITE` hook to stop early; new `setup_peb()` method builds a minimal TEB/PEB/PEB_LDR_DATA and sets `GS_BASE`. |
| `ghydra/dynamic/registers.py` | Add `GS_BASE`/`FS_BASE` to the resolvable register map (needed by `setup_peb()` and by callers who want to read/write GS base directly). |
| `tests/test_bridge_dynamic_formatters.py` / new `tests/test_bridge_emulation_watch.py` | Offline bridge wiring tests (request-body construction, no live Ghidra). |
| `tests/test_unicorn_engine.py` | Offline engine tests for watchpoint stop and PEB scaffold (no live Ghidra). |
| `tests/test_dynamic_registers.py` | Cover the new `GS_BASE`/`FS_BASE` entries. |
| `src/test/java/eu/starsong/ghidra/dto/EmulationStateDtoTest.java` | Cover the new 8-arg `of(...)` factory and `WatchHit`. |
| `test_emulation.py` | New live-Ghidra integration test for the PCode watchpoint loop (auto-skips without Ghidra). |
| `CHANGELOG.md`, `GHIDRA_HTTP_API.md`, `GHYDRA_CLI.md` (if it documents emulation tools) | Docs for the new fields/tool. |

---

### Task 1: Wire `auto_stack` through `emulation_reset`

The Java side already fully implements auto-stack (`EmulationService.reset(..., boolean autoStack)`
at `src/main/java/eu/starsong/ghidra/service/EmulationService.java:165-214`, and
`EmulationResource.ResetRequest.auto_stack` at
`src/main/java/eu/starsong/ghidra/resource/EmulationResource.java:192-197`). The bridge's
`emulation_reset` tool just never sends it, so it's always `false` and `RSP` stays `0` — exactly
the bug the external review hit (`emulation_call` even throws `"Stack pointer is not set. Use
auto_stack during reset."` when this happens, at `EmulationService.java:273`, but nothing tells
the *caller* to set it because the bridge never exposes the flag). **No Java changes needed.**

**Files:**
- Modify: `bridge_mcp_hydra.py:3260-3281` (the `emulation_reset` tool)
- Test: `tests/test_bridge_emulation_watch.py` (new file, also used by Task 2)

**Interfaces:**
- Produces: `emulation_reset(start, registers=None, memory=None, auto_stack=True, port=None)` —
  POST body gains `"auto_stack": <bool>`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bridge_emulation_watch.py
"""Offline tests for emulation_reset/emulation_run wiring (auto_stack, watchpoints)."""

import bridge_mcp_hydra as b


def test_emulation_reset_sends_auto_stack_by_default(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "READY", "steps": 0,
                                     "registers": {}}, "timestamp": 1})

    b.emulation_reset("0x1000")

    assert captured["auto_stack"] is True


def test_emulation_reset_auto_stack_can_be_disabled(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "READY", "steps": 0,
                                     "registers": {}}, "timestamp": 1})

    b.emulation_reset("0x1000", auto_stack=False)

    assert captured["auto_stack"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bridge_emulation_watch.py -v`
Expected: `FAIL` — `KeyError: 'auto_stack'` (the current body dict never sets that key).

- [ ] **Step 3: Write minimal implementation**

Replace the `emulation_reset` tool body in `bridge_mcp_hydra.py`:

```python
@mcp.tool()
@text_output
def emulation_reset(start: str, registers: dict | None = None,
                    memory: list | None = None, auto_stack: bool = True,
                    port: int | None = None) -> dict:
    """Start a fresh PCode emulation session at an address.

    Args:
        start: Start address in hex (PC is set here)
        registers: Optional {register_name: hex_value} initial register writes
        memory: Optional [{"address": hex, "hex": "ca fe"}] initial memory writes
        auto_stack: Auto-map a 1 MiB scratch stack and point RSP/RBP at its midpoint
            (default True; pass False to manage the stack yourself, e.g. to emulate
            from a state where the real stack pointer is already known)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: initial emulation state (pc, registers, steps, stopReason)
    """
    port = _get_instance_port(port)
    body: dict = {"start": start, "auto_stack": auto_stack}
    if registers:
        body["registers"] = registers
    if memory:
        body["memory"] = memory
    return simplify_response(safe_post(port, "emulation/reset", body))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_bridge_emulation_watch.py -v`
Expected: both tests `PASS`.

- [ ] **Step 5: Run the full offline suite to check for regressions**

Run: `python -m pytest`
Expected: all tests pass (216+ — the two new ones plus the existing 215).

- [ ] **Step 6: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_emulation_watch.py
git commit -m "fix: emulation_reset now defaults to auto_stack=True

The Java service already implemented auto-stack (EmulationService.reset's
autoStack param); the bridge tool never sent it, so RSP silently stayed 0
and emulation_call failed with 'Stack pointer is not set'."
```

---

### Task 2: PCode emulation watchpoint (`emulation_run` stop-on-write)

`EmulatorHelper` has no built-in "stop on write to address X" primitive (confirmed via
`javap -p -classpath lib/Emulation.jar ghidra.app.emulator.EmulatorHelper`: the closest is
`enableMemoryWriteTracking(boolean)` + `getTrackedMemoryWriteSet()`, which accumulate a *set* of
written addresses with no per-write value/PC and undocumented reset semantics across repeated
`run()` calls). Instead, snapshot the watch region's bytes before each step and compare after —
the same technique the loop already uses for `until`-address checking. This needs no exotic
Ghidra API, only `EmulatorHelper.readMemory`, which the service already calls elsewhere.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java`
- Modify: `src/main/java/eu/starsong/ghidra/service/EmulationService.java`
- Modify: `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java`
- Modify: `bridge_mcp_hydra.py` (`emulation_run` tool)
- Test: `src/test/java/eu/starsong/ghidra/dto/EmulationStateDtoTest.java`
- Test: `tests/test_bridge_emulation_watch.py` (request-body wiring)
- Test: `test_emulation.py` (live-Ghidra watchpoint-hit behavior)

**Interfaces:**
- Consumes: nothing new from Task 1.
- Produces: `EmulationStateDto.WatchHit(String address, int length, String before, String after,
  String writePc)`; `EmulationStateDto.StopReason.WATCHPOINT`;
  `EmulationService.run(Program, String until, long maxSteps, boolean trace, String
  watchAddress, int watchLength)` (4-arg `run(...)` overload kept, delegates with
  `watchAddress=null, watchLength=0`); bridge tool
  `emulation_run(until=None, max_steps=100000, trace=False, watch_address=None,
  watch_length=0, port=None)`.

- [ ] **Step 1: Write the failing JUnit test for the DTO**

Append to `src/test/java/eu/starsong/ghidra/dto/EmulationStateDtoTest.java`:

```java
    @Test
    public void ofWithWatchHitPopulatesAllFields() {
        EmulationStateDto.WatchHit hit = new EmulationStateDto.WatchHit(
            "0x223018", 4, "00000000", "deadbeef", "0x140001010");
        EmulationStateDto dto = EmulationStateDto.of(
            "0x140001012", StopReason.WATCHPOINT, 7L,
            Map.of("RIP", "0x140001012"), List.of(), null, null, hit);
        assertEquals(StopReason.WATCHPOINT, dto.stopReason());
        assertEquals("0x223018", dto.watchHit().address());
        assertEquals("deadbeef", dto.watchHit().after());
        assertEquals("0x140001010", dto.watchHit().writePc());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn test -Dtest=EmulationStateDtoTest`
Expected: `FAIL` — compile error (`StopReason.WATCHPOINT`, `EmulationStateDto.WatchHit`, and the
8-arg `of(...)` don't exist yet).

- [ ] **Step 3: Implement the DTO changes**

Replace `src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java` in full:

```java
package eu.starsong.ghidra.dto;

import java.util.List;
import java.util.Map;

/** Wire representation of a PCode emulation session's state. */
public record EmulationStateDto(
        String pc,
        StopReason stopReason,
        long steps,
        Map<String, String> registers,
        List<String> trace,
        String lastError,
        String detail,
        WatchHit watchHit) {

    /**
     * Why an emulation session is in its current state. Serializes to its enum name
     * (e.g. {@code "BREAKPOINT"}), so the JSON wire shape is unchanged from a plain string.
     */
    public enum StopReason {
        /** Fresh session, set by {@code reset} before any execution. */
        READY,
        /** {@code step} completed (possibly fewer than requested if it stopped early). */
        STEPPED,
        /** {@code run} reached its {@code until} target address. */
        TARGET_REACHED,
        /** Execution halted at a breakpoint that was set on the session. */
        BREAKPOINT,
        /** The emulator faulted (unmapped read, unimplemented instruction, etc.); see {@code lastError}. */
        ERROR,
        /** {@code run} hit its step cap without otherwise stopping. */
        MAX_STEPS,
        /** Execution stopped due to a hook trap */
        HOOK_TRAP,
        /** Unmapped memory access */
        UNMAPPED,
        /** {@code run} stopped because the watched memory region changed; see {@code watchHit}. */
        WATCHPOINT
    }

    /** A memory write detected by an active {@code run} watchpoint. */
    public record WatchHit(String address, int length, String before, String after, String writePc) {}

    public static EmulationStateDto of(String pc, StopReason stopReason, long steps,
            Map<String, String> registers, List<String> trace, String lastError) {
        return new EmulationStateDto(pc, stopReason, steps, registers, trace, lastError, null, null);
    }

    public static EmulationStateDto of(String pc, StopReason stopReason, long steps,
            Map<String, String> registers, List<String> trace, String lastError, String detail) {
        return new EmulationStateDto(pc, stopReason, steps, registers, trace, lastError, detail, null);
    }

    public static EmulationStateDto of(String pc, StopReason stopReason, long steps,
            Map<String, String> registers, List<String> trace, String lastError, String detail,
            WatchHit watchHit) {
        return new EmulationStateDto(pc, stopReason, steps, registers, trace, lastError, detail, watchHit);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn test -Dtest=EmulationStateDtoTest`
Expected: `PASS` (3 tests: the existing `ofPopulatesAllFields` plus the new one).

- [ ] **Step 5: Implement the `run()` watchpoint loop**

In `src/main/java/eu/starsong/ghidra/service/EmulationService.java`:

Add the import (with the other `java.util.*` imports near the top):

```java
import java.util.Arrays;
```

Add a `watchHit` field to `Session` (next to `lastError`):

```java
        StopReason stopReason = StopReason.READY;
        String lastError = null;
        EmulationStateDto.WatchHit watchHit = null;
```

Replace the `run(Program, String, long, boolean)` method with a 4-arg convenience overload plus
the new 6-arg implementation:

```java
    public EmulationStateDto run(Program program, String untilStr, long maxSteps, boolean trace) {
        return run(program, untilStr, maxSteps, trace, null, 0);
    }

    /**
     * Run the session until {@code untilStr}, a breakpoint, an error, {@code maxSteps}, or
     * (when {@code watchAddressStr} is given) until the bytes at that address change. The
     * watch is a before/after snapshot compared after every step -- {@link EmulatorHelper}
     * has no native memory-write breakpoint, only a write-tracking *set*
     * ({@code enableMemoryWriteTracking}) with no per-write value or triggering PC, which
     * this needs.
     */
    public EmulationStateDto run(Program program, String untilStr, long maxSteps, boolean trace,
            String watchAddressStr, int watchLength) {
        Session s = require(program);
        long cap = Math.min(maxSteps <= 0 ? MAX_STEPS_CAP : maxSteps, MAX_STEPS_CAP);
        Address until = untilStr == null || untilStr.isEmpty()
            ? null : GhidraUtil.resolveAddress(program, untilStr);
        Address watchAddr = watchAddressStr == null || watchAddressStr.isEmpty()
            ? null : GhidraUtil.resolveAddress(program, watchAddressStr);
        if (watchAddressStr != null && !watchAddressStr.isEmpty() && watchAddr == null) {
            throw new IllegalArgumentException("Invalid watch address: " + watchAddressStr);
        }
        int watchLen = Math.min(Math.max(watchLength, 1), 4096);
        s.watchHit = null;
        return GhidraSwing.runRead(() -> {
            byte[] before = watchAddr != null ? s.emu.readMemory(watchAddr, watchLen) : null;
            for (long i = 0; i < cap; i++) {
                Address pc = s.emu.getExecutionAddress();
                if (until != null && pc != null && pc.equals(until)) { s.stopReason = StopReason.TARGET_REACHED; break; }
                if (trace && s.trace.size() < MAX_TRACE && pc != null) s.trace.add(pc.toString());
                if (!stepOnce(s)) break;
                if (watchAddr != null) {
                    byte[] after = s.emu.readMemory(watchAddr, watchLen);
                    if (!Arrays.equals(before, after)) {
                        s.stopReason = StopReason.WATCHPOINT;
                        s.watchHit = new EmulationStateDto.WatchHit(
                            watchAddr.toString(), watchLen, toHexString(before), toHexString(after),
                            pc != null ? pc.toString() : null);
                        break;
                    }
                    before = after;
                }
                if (i == cap - 1) s.stopReason = StopReason.MAX_STEPS;
            }
            return snapshot(program, s, trace);
        });
    }

    private static String toHexString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
```

Update `snapshot()` to surface `watchHit` only while in that state (mirrors the existing
`lastError`-only-when-`ERROR` guard immediately above it):

```java
    private EmulationStateDto snapshot(Program program, Session s, boolean includeTrace) {
        Address pc = s.emu.getExecutionAddress();
        Map<String, String> regs = new LinkedHashMap<>();
        for (Register r : program.getLanguage().getRegisters()) {
            if (r.isBaseRegister() && !r.isProcessorContext()) {
                try { regs.put(r.getName(), toHex(s.emu.readRegister(r))); }
                catch (RuntimeException ignore) { /* register unreadable in this state; omit */ }
            }
        }
        String err = s.stopReason == StopReason.ERROR ? s.lastError : null;
        EmulationStateDto.WatchHit wh = s.stopReason == StopReason.WATCHPOINT ? s.watchHit : null;
        return EmulationStateDto.of(
            pc != null ? pc.toString() : null,
            s.stopReason, s.steps, regs,
            includeTrace ? new ArrayList<>(s.trace) : List.of(),
            err, null, wh);
    }
```

- [ ] **Step 6: Wire the REST request**

In `src/main/java/eu/starsong/ghidra/resource/EmulationResource.java`, update `RunRequest` and
the `run()` handler:

```java
    private void run(GhidraContext ctx) {
        var program = ctx.requireProgram();
        RunRequest req = ctx.bodyAsClass(RunRequest.class);
        if (req == null) req = new RunRequest();
        respond(ctx, service.run(program, req.until, req.max_steps, req.trace,
                                 req.watch_address, req.watch_length));
    }
```

```java
    private static class RunRequest {
        public String until; public long max_steps; public boolean trace;
        public String watch_address; public int watch_length;
    }
```

- [ ] **Step 7: Run the Java unit suite**

Run: `mvn test`
Expected: all tests `PASS` (the build needs `GHIDRA_HOME` set, e.g.
`GHIDRA_HOME=C:\Users\proma\Documents\ghidra_12.1.2_PUBLIC`).

- [ ] **Step 8: Wire the bridge tool**

In `bridge_mcp_hydra.py`, replace `emulation_run`:

```python
@mcp.tool()
@text_output
def emulation_run(until: str | None = None, max_steps: int = 100000,
                  trace: bool = False, watch_address: str | None = None,
                  watch_length: int = 0, port: int | None = None) -> dict:
    """Run the emulation session until an address, a breakpoint, an error, max_steps,
    or (with watch_address) until that memory region's bytes change.

    A watchpoint is the fast way to find "who writes buffer X": skip
    instruction-level trace=True tracing of a whole unpacking stub and just
    run straight to the write. On a watchpoint hit, result.watchHit carries
    {address, length, before, after, writePc} -- writePc is the instruction
    that performed the write.

    Args:
        until: Optional stop address in hex
        max_steps: Hard step cap (default 100000, server caps at 5000000)
        trace: When true, returns the list of executed instruction addresses
        watch_address: Optional hex address; run stops as soon as the bytes at
            this address (length watch_length) change from their value when
            this call started
        watch_length: Number of bytes to watch (default 1 when watch_address is set,
            server caps at 4096)
        port: Specific Ghidra instance port (optional)

    Returns:
        dict: final emulation state including stopReason and optional trace
    """
    port = _get_instance_port(port)
    body: dict = {"max_steps": max_steps, "trace": trace}
    if until:
        body["until"] = until
    if watch_address:
        body["watch_address"] = watch_address
        body["watch_length"] = watch_length or 1
    return simplify_response(safe_post(port, "emulation/run", body))
```

- [ ] **Step 9: Write the failing bridge wiring test**

Append to `tests/test_bridge_emulation_watch.py`:

```python
def test_emulation_run_sends_watch_params_when_given(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "WATCHPOINT", "steps": 3,
                                     "registers": {}, "watchHit": {"address": "0x223018"}},
        "timestamp": 1})

    b.emulation_run(watch_address="0x223018", watch_length=4)

    assert captured["watch_address"] == "0x223018"
    assert captured["watch_length"] == 4


def test_emulation_run_omits_watch_params_by_default(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "MAX_STEPS", "steps": 100,
                                     "registers": {}}, "timestamp": 1})

    b.emulation_run()

    assert "watch_address" not in captured
```

- [ ] **Step 10: Run test, verify it fails, then passes**

Run: `python -m pytest tests/test_bridge_emulation_watch.py -v`
Expected before Step 8: `FAIL` (no `watch_address` key sent). After Step 8: `PASS`.

- [ ] **Step 11: Add the live-Ghidra integration test**

Append to `test_emulation.py`:

```python
    def test_watchpoint_stops_on_write(self):
        # mov rax, <addr>; mov byte [rax], 0x41; ret -- a self-contained 14-byte stub
        # that writes one byte to an address we choose, independent of the loaded binary.
        target = self.entry  # reuse the already-mapped entry-point page as scratch
        write_addr_int = int(target, 16) + 0x40
        shellcode = ("48b8" + write_addr_int.to_bytes(8, "little").hex()
                     + "c60041" + "c3")
        _json(requests.post(f"{URL}/emulation/reset",
                            json={"start": self.entry, "auto_stack": True}))
        _json(requests.post(f"{URL}/emulation/memory",
                            json={"address": self.entry, "hex": shellcode}))
        run = _json(requests.post(f"{URL}/emulation/run", json={
            "max_steps": 10, "watch_address": hex(write_addr_int), "watch_length": 1}))
        self.assertTrue(run.get("success"))
        self.assertEqual("WATCHPOINT", run["result"]["stopReason"])
        self.assertEqual("41", run["result"]["watchHit"]["after"])
        self.assertEqual("00", run["result"]["watchHit"]["before"])
```

Run: `python test_emulation.py` (auto-skips if Ghidra isn't reachable on `:8192`; run against a
live instance with any binary open to actually exercise it).
Expected: `PASS` against a live instance.

- [ ] **Step 12: Run the full suites**

Run: `mvn test && python -m pytest`
Expected: everything passes.

- [ ] **Step 13: Bump versions and changelog**

`src/main/java/eu/starsong/ghidra/api/ApiConstants.java`: `PLUGIN_VERSION = "v3.4.0"`.
`bridge_mcp_hydra.py`: `BRIDGE_VERSION = "v3.4.2"`.
`pyproject.toml`: `version = "3.4.2"`.
Add a `## [3.4.2]` `CHANGELOG.md` section documenting `auto_stack` default and the PCode
watchpoint (covers Tasks 1 and 2 together since they ship in the same release).

- [ ] **Step 14: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/dto/EmulationStateDto.java \
        src/main/java/eu/starsong/ghidra/service/EmulationService.java \
        src/main/java/eu/starsong/ghidra/resource/EmulationResource.java \
        src/test/java/eu/starsong/ghidra/dto/EmulationStateDtoTest.java \
        bridge_mcp_hydra.py tests/test_bridge_emulation_watch.py test_emulation.py \
        pyproject.toml CHANGELOG.md src/main/java/eu/starsong/ghidra/api/ApiConstants.java
git commit -m "feat: PCode emulation watchpoints (run stops on memory write)

emulation_run gains watch_address/watch_length: stop as soon as that
region's bytes change, instead of requiring full trace=True instruction
tracing to find which instruction wrote a target buffer."
```

---

### Task 3: Unicorn watchpoint (`unicorn_run` stop-on-write)

Unlike the PCode engine, Unicorn already has the right primitive: `UC_HOOK_MEM_WRITE`
(`ghydra/dynamic/unicorn_engine.py:243-248`, `_write_hook`), currently installed only when
`trace=True` and only used to *collect* writes, never to stop early. Extend the same hook to
optionally call `uc.emu_stop()` the moment a write overlaps a target region — exactly the
pattern `_code_hook` already uses for hook `"trap"`/`"return_const"`/`"skip"` actions
(`uc.emu_stop()` inside the hook, then a `ctrl[...]` flag checked after `emu_start()` returns
normally).

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py`
- Modify: `bridge_mcp_hydra.py` (`unicorn_run` tool, `_unicorn_run_result`)
- Test: `tests/test_unicorn_engine.py`
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Produces: `StopReason.WATCHPOINT = "WATCHPOINT"`;
  `UnicornSession.run(..., watch_start: int | None = None, watch_length: int = 0)` returns a
  state dict with `state["watch_hit"]` (`None`, or `{"address", "size", "value", "pc"}` of raw
  ints) when triggered; bridge `unicorn_run(until, count=100000, trace=False,
  watch_address=None, watch_length=0, port=None)`; `_unicorn_run_result` treats
  `StopReason.WATCHPOINT` as `success=True` (the watch firing is the intended outcome, not a
  fault) and adds a hex-formatted `watch_hit` to the payload.

- [ ] **Step 1: Write the failing engine test**

Append to `tests/test_unicorn_engine.py` (reuses the exact shellcode already proven correct by
`test_run_records_memory_writes` two tests above it: `mov rbx, 0x140076000 ; mov [rbx], 0x41`):

```python
def test_run_stops_on_watchpoint_write():
    s = UnicornSession()
    base = 0x140075000
    code = bytes.fromhex("48bb0060074001000000" "c60341")
    s.map_bytes(base, code)
    s.map_bytes(0x140076000, b"\x00")
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + len(code), count=10,
                  watch_start=0x140076000, watch_length=1)
    assert state["stop_reason"] == "WATCHPOINT"
    assert state["watch_hit"]["address"] == 0x140076000
    assert state["watch_hit"]["value"] == 0x41
    assert state["watch_hit"]["pc"] == base + 10   # the `mov [rbx],0x41` instruction


def test_run_without_watch_args_is_unaffected():
    s = UnicornSession()
    base = 0x140075000
    s.map_bytes(base, b"\x90\x90")
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + 2, count=10)
    assert state["stop_reason"] == "DONE"
    assert state["watch_hit"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k watchpoint -v`
Expected: `FAIL` — `TypeError: run() got an unexpected keyword argument 'watch_start'`.

- [ ] **Step 3: Implement the engine changes**

In `ghydra/dynamic/unicorn_engine.py`, add `WATCHPOINT` to `StopReason`:

```python
class StopReason(str, Enum):
    DONE = "DONE"
    COUNT = "COUNT"
    ERROR = "ERROR"
    LAZY_FETCH_FAILED = "LAZY_FETCH_FAILED"
    LAZY_CAP_REACHED = "LAZY_CAP_REACHED"
    HOOK_TRAP = "HOOK_TRAP"
    REDIRECT_STORM = "REDIRECT_STORM"
    UNMAPPED = "UNMAPPED"
    WATCHPOINT = "WATCHPOINT"
```

Update the `run()` signature and body:

```python
    def run(self, begin, until=0, count=100000, timeout=0, trace=False,
            max_lazy_pages=4096, watch_start=None, watch_length=0):
        from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                             UC_HOOK_MEM_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UcError)
        steps = {"n": 0}
        executed: list[int] = []
        mem_writes: list[dict] = []
        hook_log: list[dict] = []
        trace_trunc = {"hit": False}
        ctrl = {"redirect": False, "trap": False, "hook_error": None}
        watch_end = watch_start + watch_length if watch_start is not None and watch_length > 0 else None
        watch_hit = {"hit": False, "address": None, "size": None, "value": None, "pc": None}
```

(unchanged: `_code_hook`)

Replace `_write_hook`:

```python
        def _write_hook(uc, access, address, size, value, _user):
            if trace:
                if len(mem_writes) < _TRACE_CAP:
                    mem_writes.append({"address": address, "size": size, "value": value})
                else:
                    trace_trunc["hit"] = True
            if watch_end is not None and not watch_hit["hit"] and address < watch_end and address + size > watch_start:
                watch_hit.update(hit=True, address=address, size=size, value=value,
                                 pc=self.get_register("RIP"))
                uc.emu_stop()
```

(unchanged: `_unmapped_hook`)

Update the hook install line:

```python
        h_code = self._uc.hook_add(UC_HOOK_CODE, _code_hook)
        h_write = self._uc.hook_add(UC_HOOK_MEM_WRITE, _write_hook) if (trace or watch_end is not None) else None
        h_unmapped = self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped_hook)
```

In the main loop, add a watch check right after the `ctrl["redirect"]` block and before the
"clean stop" comment:

```python
                if ctrl["redirect"]:
                    redirects += 1
                    if redirects >= _REDIRECT_CAP:
                        stop_reason = StopReason.REDIRECT_STORM
                        last_error = (
                            f"redirect storm: {redirects} hook redirects without progress "
                            f"(last RIP={hex(self.get_register('RIP'))})")
                        break
                    current = self.get_register("RIP")
                    continue
                if watch_hit["hit"]:
                    stop_reason = StopReason.WATCHPOINT
                    break
                # clean stop: until reached, or count exhausted
                if steps["n"] >= cap:
                    stop_reason = StopReason.COUNT
                break
```

Update the return dict:

```python
        return {
            "pc": self.get_register("RIP"),
            "steps": steps["n"],
            "stop_reason": stop_reason,
            "last_error": last_error,
            "registers": {r: self.get_register(r) for r in _ALL_REGS},
            "trace": executed if trace else [],
            "mem_writes": mem_writes if trace else [],
            "hook_log": hook_log,
            "trace_truncated": trace_trunc["hit"],
            "watch_hit": dict(watch_hit) if watch_hit["hit"] else None,
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -v`
Expected: all `PASS`, including the two new tests.

- [ ] **Step 5: Wire the bridge tool**

In `bridge_mcp_hydra.py`, update `_unicorn_run_result`:

```python
def _unicorn_run_result(state: dict) -> dict:
    """Shape an engine run() state dict into a bridge response.

    success is true for DONE and WATCHPOINT (both are an intended stop, not a
    fault). Every other stop_reason returns an error envelope (error.code =
    stop_reason, error.message from last_error) so the last_error message
    reaches the MCP client via text_output.
    """
    from ghydra.dynamic.unicorn_engine import StopReason
    stop = state["stop_reason"]
    payload = {
        "pc": hex(state["pc"]),
        "steps": state["steps"],
        "stop_reason": stop,
        "last_error": state["last_error"],
        "timestamp": int(time.time() * 1000),
    }
    if stop in (StopReason.DONE, StopReason.WATCHPOINT):
        payload["success"] = True
        payload["registers"] = {k: hex(v) for k, v in state["registers"].items()}
        payload["trace"] = [hex(a) for a in state["trace"]]
        payload["mem_writes"] = [{"address": hex(w["address"]), "size": w["size"],
                                  "value": hex(w["value"])} for w in state["mem_writes"]]
        payload["trace_truncated"] = state.get("trace_truncated", False)
        if stop == StopReason.WATCHPOINT:
            wh = state["watch_hit"]
            payload["watch_hit"] = {"address": hex(wh["address"]), "size": wh["size"],
                                    "value": hex(wh["value"]), "pc": hex(wh["pc"])}
        return payload
    if stop == StopReason.COUNT:
        message = (state["last_error"]
                   or f"instruction cap reached after {state['steps']} steps; "
                   "raise `count` or set a closer `until`")
    else:
        message = state["last_error"] or stop
    payload["success"] = False
    payload["error"] = {"code": stop, "message": message}
    return payload
```

Update `unicorn_run`:

```python
@mcp.tool()
@text_output
def unicorn_run(until: str, count: int = 100000, trace: bool = False,
                watch_address: str | None = None, watch_length: int = 0,
                port: int | None = None) -> dict:
    """Run the Unicorn session until an address, instruction count, fault, or
    (with watch_address) until that memory region changes.

    success is true only when the target address is reached (stop_reason DONE)
    or a watchpoint fires (stop_reason WATCHPOINT, result.watch_hit carries
    {address, size, value, pc} -- pc is the writing instruction). A run that
    hits the instruction cap returns stop_reason "COUNT" with success=false:
    it ran cleanly but stopped at the budget without reaching the target --
    raise `count` or set a closer `until`; it is NOT a fault, and the emulated
    memory up to the cap is valid (just incomplete). A failed lazy byte fetch
    from Ghidra returns "LAZY_FETCH_FAILED" with the cause in last_error;
    exhausting the lazy-page budget returns "LAZY_CAP_REACHED" (raise the
    engine's max_lazy_pages); any other emulator fault returns "ERROR". On a
    "LAZY_FETCH_FAILED"/"ERROR" stop the emulated memory may be partial or
    corrupt and must not be trusted.

    Args:
        until: Stop address in hex (required; emulation runs begin..until)
        count: Instruction cap (default 100000)
        trace: Return executed instruction addresses and memory writes
        watch_address: Optional hex address; run stops as soon as the bytes at
            this address (length watch_length) are written, without needing
            trace=True. The fast way to find "who writes buffer X".
        watch_length: Number of bytes to watch (default 1 when watch_address is set)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    begin = session.get_register("RIP")
    watch_start = int(watch_address, 16) if watch_address else None
    state = session.run(begin=begin, until=int(until, 16), count=count, trace=trace,
                        watch_start=watch_start, watch_length=watch_length or (1 if watch_start is not None else 0))
    return _unicorn_run_result(state)
```

- [ ] **Step 6: Write the failing bridge wiring test**

Append to `tests/test_bridge_unicorn.py`:

```python
def test_unicorn_run_watchpoint_stops_and_reports_hit():
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    base = 0x140075000
    code = bytes.fromhex("48bb0060074001000000" "c60341")
    session = UnicornSession()
    session.map_bytes(base, code)
    session.map_bytes(0x140076000, b"\x00")
    session.set_register("RIP", base)
    b._UNICORN_SESSIONS[8192] = session
    b.active_instances[8192] = {"url": "http://localhost:8192"}
    try:
        out = b.unicorn_run.__wrapped__(hex(base + len(code)), watch_address="0x140076000", port=8192)
        assert out["success"] is True
        assert out["stop_reason"] == "WATCHPOINT"
        assert out["watch_hit"]["value"] == "0x41"
        assert out["watch_hit"]["address"] == "0x140076000"
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)
```

- [ ] **Step 7: Run test, verify it fails, then implement-confirm pass**

Run: `python -m pytest tests/test_bridge_unicorn.py -v`
Expected: `FAIL` before Step 5's edits land (`TypeError`), `PASS` after (this step is really
verifying Steps 3–5 together since they're one cohesive change to `run()`'s contract).

- [ ] **Step 8: Run the full offline suite**

Run: `python -m pytest`
Expected: all pass.

- [ ] **Step 9: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py bridge_mcp_hydra.py \
        tests/test_unicorn_engine.py tests/test_bridge_unicorn.py
git commit -m "feat: Unicorn watchpoints (unicorn_run stops on memory write)

Reuses the existing UC_HOOK_MEM_WRITE hook (previously only active under
trace=True, and only for passive collection) to stop emulation the instant
a target region is written, returning the writing instruction's PC -- the
fast path for 'who writes buffer X' instead of full-trace + post-hoc scan."
```

(Version bump folded into Task 4's commit since both ship together as one Unicorn-side release.)

---

### Task 4: Unicorn Windows x64 TEB/PEB/PEB_LDR_DATA scaffold

A binary doing manual import resolution (the exact "0 imports, PEB-walk" pattern the original RE
session diagnosed) executes roughly: `mov rax, gs:[0x30]` (TEB self-pointer) → `[rax+0x60]`
(PEB) → `[peb+0x18]` (`PEB_LDR_DATA*`) → walk `Ldr->InMemoryOrderModuleList` (a `LIST_ENTRY` at
`Ldr+0x20`) comparing `BaseDllName` per `LDR_DATA_TABLE_ENTRY` to find `kernel32.dll`/`ntdll.dll`,
then reads `DllBase` (`+0x30`) to start walking that DLL's export table. Under bare Unicorn, `GS`
base is `0`, so the very first `gs:[0x30]` read faults (unmapped) and the whole unpacking stub
dies before doing anything interesting. These offsets (`NtTib.Self@0x30`,
`TEB.ProcessEnvironmentBlock@0x60`, `PEB.Ldr@0x18`, `LDR_DATA_TABLE_ENTRY.InMemoryOrderLinks@0x10`,
`.DllBase@0x30`, `.BaseDllName@0x58`) are the standard, stable x64 Windows (Vista+) layout used
throughout the public shellcode/reflective-loader literature.

This task does **not** attempt rdtsc/cpuid handling: Unicorn's QEMU-based x86 target already
executes both natively without faulting (no hook needed for vanilla use). If a specific binary
needs a particular CPUID feature bit or a monotonic-looking RDTSC for an anti-analysis check, the
existing `unicorn_hook_set(address, action="skip"|"return_const", ...)` escape hatch (already
shipped) covers it without new engine code — point a hook at the `cpuid`/`rdtsc` instruction
address.

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py`
- Modify: `ghydra/dynamic/registers.py`
- Modify: `bridge_mcp_hydra.py` (new `unicorn_setup_peb` tool)
- Test: `tests/test_unicorn_engine.py`
- Test: `tests/test_dynamic_registers.py`
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Produces: `resolve_register("GS_BASE")` / `resolve_register("FS_BASE")`;
  `UnicornSession.setup_peb(modules: list[dict] | None = None) -> dict` returning
  `{"teb": hex, "peb": hex, "ldr": hex, "modules": [hex, ...]}`; bridge tool
  `unicorn_setup_peb(modules: list[dict] | None = None, port: int | None = None) -> dict`. Each
  `modules` entry: `{"name": str, "base": "0x..."}`.

- [ ] **Step 1: Write the failing registers test**

Append to `tests/test_dynamic_registers.py`:

```python
def test_segment_base_registers_present():
    pytest.importorskip("unicorn")
    for name in ("GS_BASE", "FS_BASE"):
        assert name in X86_64_REGISTERS
```

(add `import pytest` at the top of the file alongside the existing import line if not already
present — check first; the file currently only imports from `ghydra.dynamic.registers`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dynamic_registers.py -v`
Expected: `FAIL` — `AssertionError: assert 'GS_BASE' in {...}`.

- [ ] **Step 3: Add the registers**

In `ghydra/dynamic/registers.py`:

```python
def _build_map():
    try:
        from unicorn.x86_const import (
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
            UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
            UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
            UC_X86_REG_R15, UC_X86_REG_EFLAGS, UC_X86_REG_GS_BASE, UC_X86_REG_FS_BASE,
        )
    except ImportError:
        return {}
    return {
        "RAX": UC_X86_REG_RAX, "RBX": UC_X86_REG_RBX, "RCX": UC_X86_REG_RCX,
        "RDX": UC_X86_REG_RDX, "RSI": UC_X86_REG_RSI, "RDI": UC_X86_REG_RDI,
        "RSP": UC_X86_REG_RSP, "RBP": UC_X86_REG_RBP, "RIP": UC_X86_REG_RIP,
        "R8": UC_X86_REG_R8, "R9": UC_X86_REG_R9, "R10": UC_X86_REG_R10,
        "R11": UC_X86_REG_R11, "R12": UC_X86_REG_R12, "R13": UC_X86_REG_R13,
        "R14": UC_X86_REG_R14, "R15": UC_X86_REG_R15, "EFLAGS": UC_X86_REG_EFLAGS,
        "GS_BASE": UC_X86_REG_GS_BASE, "FS_BASE": UC_X86_REG_FS_BASE,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dynamic_registers.py -v`
Expected: `PASS`.

- [ ] **Step 5: Write the failing engine tests**

Append to `tests/test_unicorn_engine.py`:

```python
def test_setup_peb_links_module_list():
    s = UnicornSession()
    info = s.setup_peb(modules=[{"name": "kernel32.dll", "base": "0x180000000"}])
    teb = int(info["teb"], 16)
    peb = int(info["peb"], 16)
    ldr = int(info["ldr"], 16)
    assert s.get_register("GS_BASE") == teb
    assert int.from_bytes(s.read_memory(teb + 0x30, 8), "little") == teb
    assert int.from_bytes(s.read_memory(teb + 0x60, 8), "little") == peb
    assert int.from_bytes(s.read_memory(peb + 0x18, 8), "little") == ldr
    head = ldr + 0x20
    entry = int(info["modules"][0], 16)
    assert int.from_bytes(s.read_memory(head, 8), "little") == entry + 0x10
    assert int.from_bytes(s.read_memory(entry + 0x30, 8), "little") == 0x180000000


def test_setup_peb_empty_module_list_is_self_referential():
    s = UnicornSession()
    info = s.setup_peb()
    ldr = int(info["ldr"], 16)
    head = ldr + 0x20
    assert int.from_bytes(s.read_memory(head, 8), "little") == head
    assert int.from_bytes(s.read_memory(head + 8, 8), "little") == head


def test_gs_segment_resolves_teb_via_real_instruction():
    s = UnicornSession()
    info = s.setup_peb()
    teb = int(info["teb"], 16)
    code = bytes.fromhex("65488b042530000000")  # mov rax, gs:[0x30]
    base = 0x140075000
    s.map_bytes(base, code)
    s.set_register("RIP", base)
    state = s.run(begin=base, until=base + len(code), count=2)
    assert state["stop_reason"] == "DONE"
    assert state["registers"]["RAX"] == teb
```

- [ ] **Step 6: Run test to verify it fails**

Run: `python -m pytest tests/test_unicorn_engine.py -k setup_peb -v`
Expected: `FAIL` — `AttributeError: 'UnicornSession' object has no attribute 'setup_peb'`.

- [ ] **Step 7: Implement `setup_peb`**

Add to `ghydra/dynamic/unicorn_engine.py` (class body of `UnicornSession`, e.g. right after
`map_bytes`):

```python
    TEB_BASE = 0x7ffff0010000
    PEB_BASE = 0x7ffff0011000
    LDR_BASE = 0x7ffff0012000
    _MODULE_SLAB_BASE = 0x7ffff0013000
    _MODULE_SLAB_STRIDE = 0x200

    def setup_peb(self, modules: list[dict] | None = None) -> dict:
        """Build a minimal Windows x64 TEB/PEB/PEB_LDR_DATA and point GS_BASE at it.

        Without this, any binary that manually resolves imports via a PEB-walk
        (gs:[0x30] -> TEB -> +0x60 -> PEB -> +0x18 -> Ldr ->
        InMemoryOrderModuleList) faults immediately on the first gs-relative
        read, since GS base defaults to 0 and address 0x30 is never mapped.
        `modules` lists the DLLs visible in the fake module list (empty by
        default -- PEB-walk code looking for a *specific* DLL needs one
        explicitly: {"name": "kernel32.dll", "base": "0x180000000"}).
        Offsets are the standard x64 (Vista+) layout used throughout public
        shellcode/reflective-loader references; not parameterized per Windows
        version.
        """
        from .registers import resolve_register
        self.map_bytes(self.TEB_BASE, b"\x00" * 0x1000)
        self.map_bytes(self.PEB_BASE, b"\x00" * 0x1000)
        self.map_bytes(self.LDR_BASE, b"\x00" * 0x1000)
        self._uc.mem_write(self.TEB_BASE + 0x30, self.TEB_BASE.to_bytes(8, "little"))
        self._uc.mem_write(self.TEB_BASE + 0x60, self.PEB_BASE.to_bytes(8, "little"))
        self._uc.mem_write(self.PEB_BASE + 0x18, self.LDR_BASE.to_bytes(8, "little"))

        head = self.LDR_BASE + 0x20
        entries: list[int] = []
        prev = head
        for i, m in enumerate(modules or []):
            entry = self._MODULE_SLAB_BASE + i * self._MODULE_SLAB_STRIDE
            self._ensure_mapped(entry, self._MODULE_SLAB_STRIDE)
            base = int(m["base"], 16)
            name_utf16 = m["name"].encode("utf-16-le")
            name_addr = entry + 0x100
            self._uc.mem_write(name_addr, name_utf16)
            self._uc.mem_write(entry + 0x30, base.to_bytes(8, "little"))               # DllBase
            self._uc.mem_write(entry + 0x58, (
                len(name_utf16).to_bytes(2, "little")          # UNICODE_STRING.Length
                + len(name_utf16).to_bytes(2, "little")        # .MaximumLength
                + b"\x00\x00\x00\x00"                          # padding
                + name_addr.to_bytes(8, "little")))             # .Buffer
            self._uc.mem_write(prev, (entry + 0x10).to_bytes(8, "little"))             # prev.Flink
            self._uc.mem_write(entry + 0x10 + 8, prev.to_bytes(8, "little"))           # entry.Blink
            entries.append(entry)
            prev = entry + 0x10
        self._uc.mem_write(prev, head.to_bytes(8, "little"))       # last.Flink = head
        self._uc.mem_write(head + 8, prev.to_bytes(8, "little"))   # head.Blink = last

        self._uc.reg_write(resolve_register("GS_BASE"), self.TEB_BASE)
        return {"teb": hex(self.TEB_BASE), "peb": hex(self.PEB_BASE), "ldr": hex(self.LDR_BASE),
                "modules": [hex(e) for e in entries]}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `python -m pytest tests/test_unicorn_engine.py -v`
Expected: all `PASS`, including the three new tests.

- [ ] **Step 9: Wire the bridge tool**

In `bridge_mcp_hydra.py`, add near the other `unicorn_*` tools (e.g. after `unicorn_map`):

```python
@mcp.tool()
@text_output
def unicorn_setup_peb(modules: list[dict] | None = None, port: int | None = None) -> dict:
    """Build a minimal Windows x64 TEB/PEB/PEB_LDR_DATA and point GS_BASE at it.

    Call once after unicorn_reset, before unicorn_run, when the target does
    manual import resolution via a PEB-walk (gs:[0x30] -> TEB -> PEB -> Ldr ->
    InMemoryOrderModuleList) -- without this, the first gs-relative read
    faults because GS base defaults to 0. modules lists the DLLs the
    PEB-walk should find; leave empty unless the target looks for a specific
    one by name.

    Args:
        modules: Optional [{"name": "kernel32.dll", "base": "0x180000000"}, ...]
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))
    info = session.setup_peb(modules)
    info["success"] = True
    info["timestamp"] = int(time.time() * 1000)
    return info
```

Register it in `FORMATTERS` next to the other `unicorn_*` entries:

```python
    "unicorn_setup_peb": format_dynamic_state,
```

- [ ] **Step 10: Write the failing bridge wiring test**

Append to `tests/test_bridge_unicorn.py`:

```python
def test_unicorn_setup_peb_sets_gs_base():
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    session = UnicornSession()
    b._UNICORN_SESSIONS[8192] = session
    b.active_instances[8192] = {"url": "http://localhost:8192"}
    try:
        out = b.unicorn_setup_peb.__wrapped__(port=8192)
        assert out["success"] is True
        assert int(out["teb"], 16) == session.get_register("GS_BASE")
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)
```

- [ ] **Step 11: Run test to verify it passes**

Run: `python -m pytest tests/test_bridge_unicorn.py -v`
Expected: `PASS`.

- [ ] **Step 12: Run the full offline suite**

Run: `python -m pytest`
Expected: all pass.

- [ ] **Step 13: Bump versions and changelog (covers Tasks 3 and 4)**

`bridge_mcp_hydra.py`: `BRIDGE_VERSION = "v3.4.3"`. `pyproject.toml`: `version = "3.4.3"`.
`PLUGIN_VERSION` unchanged (no Java touched in Tasks 3–4). Add a `## [3.4.3]` `CHANGELOG.md`
section covering Unicorn watchpoints and `unicorn_setup_peb`.

- [ ] **Step 14: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py ghydra/dynamic/registers.py bridge_mcp_hydra.py \
        tests/test_unicorn_engine.py tests/test_dynamic_registers.py tests/test_bridge_unicorn.py \
        pyproject.toml CHANGELOG.md
git commit -m "feat: unicorn_setup_peb builds a fake TEB/PEB for manual-import-resolution targets

Binaries that PEB-walk to resolve imports (gs:[0x30] -> TEB -> PEB -> Ldr ->
InMemoryOrderModuleList) faulted immediately under bare Unicorn since GS
base defaults to 0. setup_peb maps a minimal TEB/PEB/PEB_LDR_DATA and points
GS_BASE at it; modules is opt-in so a target looking for a specific DLL by
name can be given one."
```

---

## Self-Review

**1. Spec coverage** (against the three P2 items named in the prior turn):
- "auto-stack on emulation_reset" → Task 1. ✓
- "watchpoints" (and the related "mem_writes filtered by region" ask, which a stop-on-write
  primitive supersedes — no separate filtering feature needed) → Tasks 2 (PCode) and 3 (Unicorn).
  ✓
- "PEB/TEB stubs" → Task 4. ✓ (rdtsc/cpuid explicitly scoped out with justification: Unicorn
  already executes them without faulting; the existing hook escape hatch covers the rare
  binary that needs specific values.)

**2. Placeholder scan:** No "TBD"/"handle appropriately"/"similar to Task N" language; every
step has the actual code. The one open item is real and stated as a scope boundary, not a
placeholder: `setup_peb`'s offsets target the stable x64 Vista+ layout, not parameterized per
Windows version.

**3. Type consistency:** `EmulationStateDto.WatchHit` fields (`address`, `length`, `before`,
`after`, `writePc`) match what `EmulationService.run()` constructs and what `snapshot()` reads.
`UnicornSession.run()`'s `watch_hit` dict keys (`address`, `size`, `value`, `pc`) match what
`_unicorn_run_result` reads. `resolve_register("GS_BASE")` (Task 4) matches the import added in
the same task to `registers.py`. The 4-arg `EmulationService.run(...)` overload used by
`call()` (`EmulationService.java:335`) is preserved unchanged, so Task 2 doesn't touch `call()`.

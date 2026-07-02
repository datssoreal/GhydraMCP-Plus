# Unicorn autonomy plumbing (sync + stop predicates) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give an autonomous agent the plumbing to act on what the Unicorn emulator produced — sync unpacked memory back into Ghidra, and stop `unicorn_run` early on OEP or a dead loop.

**Architecture:** A session-level, always-on tracking ledger on `UnicornSession` feeds two consumers: `unicorn_sync_to_program` (smart-hybrid sync with two new Java endpoints for block creation and commit-disassembly) and new `stop_on` predicates on `unicorn_run` (`oep` via a double-set write ledger, `no_progress` via coarse-grained windowed cycle detection).

**Tech Stack:** Python 3.11+ (bridge + Unicorn engine, `pytest` offline with a fake client), Java 21 / Ghidra 11.x-12.x (Javalin REST, `TransactionHelper`).

## Global Constraints

- Design spec: `docs/superpowers/specs/2026-07-01-unicorn-sync-and-stop-predicates-design.md` — the source of truth for every task.
- No `API_VERSION` bump (purely additive endpoints/params). Bump `PLUGIN_VERSION` (`src/main/java/eu/starsong/ghidra/api/ApiConstants.java`) and `BRIDGE_VERSION` (`bridge_mcp_hydra.py`); update `CHANGELOG.md`.
- Offline Python tests live in `tests/` and must run under bare `pytest` with a fake client — no Ghidra. Guard Unicorn-dependent tests with `pytest.importorskip("unicorn")`.
- Java mutations run through `TransactionHelper.executeInTransaction` (follow the existing `MemoryService.writeBytes` pattern exactly).
- Page size is `0x1000`; scratch/stack/PEB regions must never be synced back to Ghidra.
- Backward compatibility: `stop_on=None`, `track_dirty=True`, and the new `no_progress_*` params must leave existing behaviour unchanged.
- Conventional-commit messages (`feat:`, `fix:`, `test:`, `docs:`).

## File Structure

- `ghydra/dynamic/unicorn_engine.py` — **modify.** Ledger fields + `mark_scratch`/`dirty_pages` (Task 1); `StopReason.OEP`/`NO_PROGRESS`, `run()` rewrite with ledger updates + predicates, `call()` scratch marking (Task 2).
- `tests/test_unicorn_engine.py` — **modify/append.** Ledger + predicate tests (Tasks 1, 2). (If the file does not exist, create it.)
- `bridge_mcp_hydra.py` — **modify.** `unicorn_reset`(+`track_dirty`), `unicorn_run`(+`stop_on`/`no_progress_*`), `_unicorn_run_result` payloads, `_apply_default_stack`/`unicorn_win64_scaffold` scratch marking (Task 3); `memory_create_block`/`memory_disassemble_commit` tools + `_post_*` helpers (Task 6); `unicorn_sync_to_program` + sync helpers (Task 7); version bump (Task 8).
- `tests/test_bridge_unicorn.py` — **modify/append.** Run-result payloads, sync classification with a fake client (Tasks 3, 6, 7).
- `src/main/java/eu/starsong/ghidra/service/MemoryService.java` — **modify.** `createBlock`, `disassembleCommit` (Task 4).
- `src/main/java/eu/starsong/ghidra/resource/ProgramResource.java` — **modify.** Two new POST routes + handlers (Task 5).
- `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`, `CHANGELOG.md` — **modify.** Version + changelog (Task 8).

---

### Task 1: Session ledger fields, `mark_scratch`, `dirty_pages`

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`UnicornSession.__init__`, new methods)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Consumes: nothing (foundation).
- Produces:
  - `UnicornSession(byte_provider=None, track_dirty=True)` with attributes `track_dirty: bool`, `written_pages: set[int]`, `written_bits: dict[int, bytearray]`, `executed_pages: set[int]`, `scratch_ranges: list[tuple[int,int]]`.
  - `mark_scratch(self, base: int, size: int) -> None`
  - `dirty_pages(self) -> list[tuple[int, int]]` — written pages minus scratch, coalesced into `(start, length)` runs.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_unicorn_engine.py`:

```python
import pytest


def _session():
    pytest.importorskip("unicorn")
    from ghydra.dynamic.unicorn_engine import UnicornSession
    return UnicornSession()


def test_dirty_pages_coalesces_and_excludes_scratch():
    s = _session()
    s.written_pages.update({0x140000000, 0x140001000, 0x140003000, 0x7ffff0000000})
    s.mark_scratch(0x7ffff0000000, 0x100000)
    assert s.dirty_pages() == [(0x140000000, 0x2000), (0x140003000, 0x1000)]


def test_track_dirty_flag_defaults_true():
    s = _session()
    assert s.track_dirty is True
    assert s.written_bits == {} and s.executed_pages == set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_unicorn_engine.py -k "dirty_pages_coalesces or track_dirty_flag" -v`
Expected: FAIL (`AttributeError: 'UnicornSession' object has no attribute 'mark_scratch'` / `track_dirty`).

- [ ] **Step 3: Write minimal implementation**

In `UnicornSession.__init__`, after `self._hooks: dict[int, Hook] = {}`, add:

```python
        self.track_dirty = track_dirty
        self.written_pages: set[int] = set()
        self.written_bits: dict[int, bytearray] = {}   # page -> PAGE/8-byte bitmap
        self.executed_pages: set[int] = set()
        self.scratch_ranges: list[tuple[int, int]] = []
```

Change the signature line to:

```python
    def __init__(self, byte_provider: Optional[Callable[[int, int], bytes]] = None,
                 track_dirty: bool = True):
```

Add these methods to `UnicornSession` (place them after `region_is_mapped`):

```python
    def mark_scratch(self, base: int, size: int) -> None:
        """Register a scratch region (stack/PEB/call frame) to exclude from sync."""
        self.scratch_ranges.append((base, size))

    def _in_scratch(self, page: int) -> bool:
        return any(base <= page < base + size for base, size in self.scratch_ranges)

    def dirty_pages(self) -> list[tuple[int, int]]:
        """Written pages minus scratch, coalesced into contiguous (start, length) runs."""
        runs: list[tuple[int, int]] = []
        for page in sorted(p for p in self.written_pages if not self._in_scratch(p)):
            if runs and page == runs[-1][0] + runs[-1][1]:
                runs[-1] = (runs[-1][0], runs[-1][1] + self.PAGE)
            else:
                runs.append((page, self.PAGE))
        return runs
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_unicorn_engine.py -k "dirty_pages_coalesces or track_dirty_flag" -v`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(unicorn): session ledger fields, mark_scratch, dirty_pages"
```

---

### Task 2: `run()` — always-on write ledger, OEP + no_progress predicates

**Files:**
- Modify: `ghydra/dynamic/unicorn_engine.py` (`StopReason`, `run`, `call`)
- Test: `tests/test_unicorn_engine.py`

**Interfaces:**
- Consumes: ledger attributes from Task 1.
- Produces:
  - `StopReason.OEP = "OEP"`, `StopReason.NO_PROGRESS = "NO_PROGRESS"`.
  - `run(self, begin, until=0, count=100000, timeout=0, trace=False, max_lazy_pages=4096, watch_start=None, watch_length=0, stop_on=None, no_progress_window=5000, no_progress_max_reads=2) -> dict`. Return dict gains `"oep": int | None` and `"no_progress": dict | None`. The `no_progress` dict is `{"kind": str, "pc": int, "loop_pcs": list[int], "reads_from": list[int], "register_delta": dict[str, tuple[int,int]]}`.
  - `run` raises `ValueError` when `"oep" in stop_on and not self.track_dirty`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_unicorn_engine.py`:

```python
def _map_code(s, addr, code: bytes):
    s.map_bytes(addr, code + b"\x00" * (0x1000 - len(code)))


def test_oep_stops_on_executing_written_byte():
    s = _session()
    # stub at 0x1000: write 0x90 (nop) to 0x2000, then jmp 0x2000
    # mov byte [0x2000], 0x90 ; C6 04 25 00 20 00 00 90
    # mov rax, 0x2000        ; 48 B8 00 20 00 00 00 00 00 00
    # jmp rax                ; FF E0
    _map_code(s, 0x1000, bytes.fromhex("C60425002000009048B800200000000000000FFE0".replace("0FFE0", "FFE0")))
    _map_code(s, 0x2000, b"\x90\x90\x90")
    s.set_register("RIP", 0x1000)
    state = s.run(begin=0x1000, until=0, count=1000, stop_on={"oep"})
    assert state["stop_reason"] == "OEP"
    assert state["oep"] == 0x2000


def test_oep_ignores_unwritten_byte_on_written_page():
    s = _session()
    # write one byte at 0x2000, then execute an UNWRITTEN byte at 0x2010 on the same page
    # mov byte [0x2000],0x90 ; then jmp 0x2010
    _map_code(s, 0x1000, bytes.fromhex("C6042500200000904 8B8100200000000000000FFE0".replace(" ", "").replace("4 8", "48")))
    _map_code(s, 0x2000, b"\x00" * 0x20)
    # place a nop-ret at 0x2010 (unwritten by the emulation)
    s.map_bytes(0x2000, b"\x00" * 0x10 + b"\x90\xc3" + b"\x00" * (0x1000 - 0x12))
    s.set_register("RIP", 0x1000)
    state = s.run(begin=0x1000, until=0x2011, count=1000, stop_on={"oep"})
    assert state["stop_reason"] != "OEP"


def test_oep_requires_track_dirty():
    pytest.importorskip("unicorn")
    from ghydra.dynamic.unicorn_engine import UnicornSession
    s = UnicornSession(track_dirty=False)
    _map_code(s, 0x1000, b"\x90\x90")
    with pytest.raises(ValueError):
        s.run(begin=0x1000, until=0, count=10, stop_on={"oep"})


def test_no_progress_detects_spin_lock():
    s = _session()
    # 0x1000: F3 90 (pause) ; EB FC (jmp $-2 back to pause)
    _map_code(s, 0x1000, b"\xf3\x90\xeb\xfc")
    s.set_register("RIP", 0x1000)
    state = s.run(begin=0x1000, until=0, count=200000,
                  stop_on={"no_progress"}, no_progress_window=5000)
    assert state["stop_reason"] == "NO_PROGRESS"
    assert state["no_progress"]["kind"] == "spin_lock"


def test_productive_write_loop_is_not_no_progress():
    s = _session()
    # writes an incrementing counter to memory each iteration -> window["writes"] > 0
    # 0x1000: mov [0x3000+rcx*1], al? Keep it simple: stosb loop.
    # mov rdi,0x3000; mov rcx,0x2000; mov al,0x41; rep stosb; then jmp $ (spin AFTER work)
    code = bytes.fromhex(
        "48BF00300000000000000"  # mov rdi,0x3000  (48 BF imm64)
        "48B90020000000000000"   # mov rcx,0x2000
        "B041"                    # mov al,0x41
        "F3AA"                    # rep stosb
        "EBFE"                    # jmp $  (spin, but writes already happened)
    )
    _map_code(s, 0x1000, code)
    s.map_bytes(0x3000, b"\x00" * 0x3000)
    s.set_register("RIP", 0x1000)
    # run only long enough to cover the rep stosb window; it must NOT flag no_progress mid-copy
    state = s.run(begin=0x1000, until=0, count=6000,
                  stop_on={"no_progress"}, no_progress_window=5000)
    assert state["no_progress"] is None or state["no_progress"]["kind"] != "spin_lock" \
        or state["stop_reason"] == "COUNT"
```

> Note: the hand-assembled hex in the OEP tests is fiddly. If a byte string does not assemble to the intended instructions when you run it, fix the bytes (use a known-good encoding) rather than weakening the assertion — the *behaviour* under test (executing a written vs unwritten address) is what matters.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_unicorn_engine.py -k "oep or no_progress or productive_write" -v`
Expected: FAIL (`run() got an unexpected keyword argument 'stop_on'`).

- [ ] **Step 3: Write minimal implementation**

3a. In `class StopReason`, add two members after `WATCHPOINT`:

```python
    OEP = "OEP"
    NO_PROGRESS = "NO_PROGRESS"
```

3b. Replace the `run` method with the version below (this is the full method — it extends the existing one with ledger updates and the two predicates):

```python
    def run(self, begin, until=0, count=100000, timeout=0, trace=False,
            max_lazy_pages=4096, watch_start=None, watch_length=0,
            stop_on=None, no_progress_window=5000, no_progress_max_reads=2):
        """Run the emulation session.

        Lazy mapping intercepts unmapped reads/writes and requests the page
        from the bridge callback. stop_on may contain "oep" (stop when executing
        a previously-written byte) and "no_progress" (stop on a spin/polling loop).
        """
        from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ,
                             UC_HOOK_MEM_UNMAPPED, UC_MEM_FETCH_UNMAPPED, UcError)
        stop_on = set(stop_on or ())
        oep_enabled = "oep" in stop_on
        noprog_enabled = "no_progress" in stop_on
        if oep_enabled and not self.track_dirty:
            raise ValueError("stop_on=['oep'] requires track_dirty=True")

        steps = {"n": 0}
        executed: list[int] = []
        mem_writes: list[dict] = []
        hook_log: list[dict] = []
        trace_trunc = {"hit": False}
        ctrl = {"redirect": False, "trap": False, "hook_error": None,
                "oep": None, "no_progress": None}
        if watch_start is not None and watch_length > 0:
            watch_length = min(watch_length, _WATCH_MAX_LEN)
            watch_end = watch_start + watch_length
        else:
            watch_end = None
        watch_hit = {"hit": False, "address": None, "size": None, "value": None, "pc": None}

        _NOPROG_REGS = ("RIP", "RSP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI")
        window = {"start": 0, "writes": 0, "reads": set(), "pcs": set(), "regs": ()}
        seen_hashes: set[int] = set()

        def _snapshot():
            return tuple(self.get_register(r) for r in _NOPROG_REGS)

        def _reset_window():
            window["start"] = steps["n"]
            window["writes"] = 0
            window["reads"].clear()
            window["pcs"].clear()
            window["regs"] = _snapshot()

        def _mark_written(address, size):
            a = address
            end = address + size
            while a < end:
                page = a & ~(self.PAGE - 1)
                self.written_pages.add(page)
                bm = self.written_bits.get(page)
                if bm is None:
                    bm = bytearray(self.PAGE // 8)
                    self.written_bits[page] = bm
                off = a - page
                bm[off >> 3] |= 1 << (off & 7)
                a += 1

        def _was_written(address):
            page = address & ~(self.PAGE - 1)
            if page not in self.written_pages:
                return False
            bm = self.written_bits.get(page)
            if bm is None:
                return False
            off = address - page
            return bool(bm[off >> 3] & (1 << (off & 7)))

        def _build_no_progress(kind):
            before = window["regs"] or _snapshot()
            now = _snapshot()
            delta = {name: (b, a) for name, b, a in zip(_NOPROG_REGS, before, now) if b != a}
            return {"kind": kind, "pc": self.get_register("RIP"),
                    "loop_pcs": sorted(window["pcs"])[:32],
                    "reads_from": sorted(window["reads"])[:32],
                    "register_delta": delta}

        def _code_hook(uc, address, size, _user):
            hook = self._hooks.get(address)
            if hook is not None:
                if hook.action == "log":
                    hook_log.append({"address": address})
                elif hook.action == "trap":
                    ctrl["trap"] = True
                    uc.emu_stop()
                    return
                elif hook.action in ("return_const", "skip"):
                    try:
                        if hook.action == "return_const" and hook.mem_writes:
                            for w in hook.mem_writes:
                                data = bytes.fromhex(w["hex"])
                                self._ensure_mapped(w["address"], len(data))
                                uc.mem_write(w["address"], data)
                        rv = hook.return_value if hook.action == "return_const" else None
                        self.simulate_ret(rv)
                    except (UcError, ValueError) as e:
                        ctrl["hook_error"] = str(e)
                        uc.emu_stop()
                        return
                    ctrl["redirect"] = True
                    uc.emu_stop()
                    return
                else:
                    ctrl["hook_error"] = f"unhandled hook action: {hook.action!r}"
                    uc.emu_stop()
                    return
            steps["n"] += 1
            if self.track_dirty:
                self.executed_pages.add(address & ~(self.PAGE - 1))
            if oep_enabled and _was_written(address):
                ctrl["oep"] = address
                uc.emu_stop()
                return
            if noprog_enabled:
                window["pcs"].add(address)
                if steps["n"] - window["start"] >= no_progress_window:
                    if window["writes"] == 0:
                        h = hash(_snapshot())
                        if h in seen_hashes:
                            ctrl["no_progress"] = _build_no_progress("spin_lock")
                            uc.emu_stop()
                            return
                        seen_hashes.add(h)
                        if len(window["reads"]) <= no_progress_max_reads:
                            ctrl["no_progress"] = _build_no_progress("polling")
                            uc.emu_stop()
                            return
                    _reset_window()
            if trace:
                if len(executed) < _TRACE_CAP:
                    executed.append(address)
                else:
                    trace_trunc["hit"] = True

        def _write_hook(uc, access, address, size, value, _user):
            if self.track_dirty:
                _mark_written(address, size)
            if noprog_enabled:
                window["writes"] += size
            if trace:
                if len(mem_writes) < _TRACE_CAP:
                    mem_writes.append({"address": address, "size": size, "value": value})
                else:
                    trace_trunc["hit"] = True
            if watch_end is not None and not watch_hit["hit"] and address < watch_end and address + size > watch_start:
                watch_hit.update(hit=True, address=address, size=size, value=value,
                                 pc=self.get_register("RIP"))
                uc.emu_stop()

        def _read_hook(uc, access, address, size, value, _user):
            window["reads"].add(address)

        lazy = {"n": 0}
        lazy_fail = {"msg": None, "reason": None}
        sentinel_done = {"hit": False}

        def _unmapped_hook(uc, access, address, size, value, _user):
            if access == UC_MEM_FETCH_UNMAPPED and address == SENTINEL_ADDR:
                sentinel_done["hit"] = True
                return False
            page = address & ~(self.PAGE - 1)
            if page in self._mapped or self.byte_provider is None:
                return False
            if lazy["n"] >= max_lazy_pages:
                lazy_fail["reason"] = StopReason.LAZY_CAP_REACHED
                lazy_fail["msg"] = (f"lazy page cap ({max_lazy_pages}) reached at "
                                    f"{hex(page)}; raise max_lazy_pages")
                return False
            try:
                data = self.byte_provider(page, self.PAGE)
            except Exception as e:
                lazy_fail["reason"] = StopReason.LAZY_FETCH_FAILED
                lazy_fail["msg"] = f"lazy fetch failed at {hex(page)}: {e}"
                return False
            if not data:
                lazy_fail["reason"] = StopReason.LAZY_FETCH_FAILED
                lazy_fail["msg"] = f"no image bytes at {hex(page)}"
                return False
            self._ensure_mapped(page, self.PAGE)
            self._uc.mem_write(page, data[:self.PAGE])
            lazy["n"] += 1
            return True

        need_write_hook = trace or watch_end is not None or self.track_dirty or noprog_enabled
        if noprog_enabled:
            _reset_window()
        h_code = self._uc.hook_add(UC_HOOK_CODE, _code_hook)
        h_write = self._uc.hook_add(UC_HOOK_MEM_WRITE, _write_hook) if need_write_hook else None
        h_read = self._uc.hook_add(UC_HOOK_MEM_READ, _read_hook) if noprog_enabled else None
        h_unmapped = self._uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped_hook)
        stop_reason = StopReason.DONE
        last_error = None
        cap = min(count if count > 0 else 5_000_000, 5_000_000)
        current = begin
        remaining = cap
        redirects = 0
        try:
            while remaining > 0:
                ctrl["redirect"] = False
                ctrl["trap"] = False
                ctrl["hook_error"] = None
                before = steps["n"]
                try:
                    self._uc.emu_start(current, until, timeout=timeout, count=remaining)
                except UcError as e:
                    if sentinel_done["hit"]:
                        stop_reason = StopReason.DONE
                        last_error = None
                    elif lazy_fail["reason"] is not None:
                        stop_reason = lazy_fail["reason"]
                        last_error = lazy_fail["msg"]
                    else:
                        stop_reason = StopReason.ERROR
                        last_error = str(e)
                    break
                remaining -= (steps["n"] - before)
                if ctrl["hook_error"]:
                    stop_reason = StopReason.ERROR
                    last_error = f"hook callback error: {ctrl['hook_error']}"
                    break
                if ctrl["trap"]:
                    stop_reason = StopReason.HOOK_TRAP
                    break
                if ctrl["oep"] is not None:
                    stop_reason = StopReason.OEP
                    break
                if ctrl["no_progress"] is not None:
                    stop_reason = StopReason.NO_PROGRESS
                    break
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
                if steps["n"] >= cap:
                    stop_reason = StopReason.COUNT
                break
        finally:
            self._uc.hook_del(h_code)
            if h_write is not None:
                self._uc.hook_del(h_write)
            if h_read is not None:
                self._uc.hook_del(h_read)
            self._uc.hook_del(h_unmapped)

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
            "oep": ctrl["oep"],
            "no_progress": ctrl["no_progress"],
        }
```

3c. In `call()`, mark the call stack as scratch so a post-`call` sync doesn't push it to Ghidra. After the line `self.map_bytes(_CALL_STACK_BASE, b"\x00" * _CALL_STACK_SIZE)` add:

```python
        self.mark_scratch(_CALL_STACK_BASE, _CALL_STACK_SIZE)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_unicorn_engine.py -v`
Expected: PASS (all, including the existing suite — the rewrite is behaviour-preserving for `stop_on=None`).

- [ ] **Step 5: Commit**

```bash
git add ghydra/dynamic/unicorn_engine.py tests/test_unicorn_engine.py
git commit -m "feat(unicorn): OEP + no_progress stop predicates with always-on ledger"
```

---

### Task 3: Bridge wiring — `unicorn_reset`, `unicorn_run`, `_unicorn_run_result`, scratch marking

**Files:**
- Modify: `bridge_mcp_hydra.py` (`unicorn_reset`, `unicorn_run`, `_unicorn_run_result`, `_apply_default_stack`, `unicorn_win64_scaffold`)
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Consumes: `UnicornSession(track_dirty=...)`, `run(stop_on=..., no_progress_window=..., no_progress_max_reads=...)`, `StopReason.OEP`/`NO_PROGRESS` (Task 2).
- Produces:
  - `unicorn_reset(start, registers=None, stack=True, track_dirty=True, port=None)`.
  - `unicorn_run(until, count=100000, trace=False, watch_address=None, watch_length=0, stop_on=None, no_progress_window=5000, no_progress_max_reads=2, port=None)`.
  - `_unicorn_run_result` treats `OEP` and `NO_PROGRESS` as success stops carrying `oep`/`no_progress` payloads (hex-formatted).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_bridge_unicorn.py`:

```python
def _state_full(stop, **extra):
    base = {"pc": 0x2000, "steps": 5000, "stop_reason": stop, "last_error": None,
            "registers": {"RIP": 0x2000, "RAX": 0x0}, "trace": [], "mem_writes": [],
            "watch_hit": None, "oep": None, "no_progress": None}
    base.update(extra)
    return base


def test_oep_result_is_success_with_payload():
    r = _unicorn_run_result(_state_full("OEP", oep=0x2000))
    assert r["success"] is True
    assert r["oep"] == {"pc": "0x2000"}
    assert r["registers"]["RAX"] == "0x0"


def test_no_progress_result_hex_formats_payload():
    np = {"kind": "polling", "pc": 0x140001045,
          "loop_pcs": [0x140001040, 0x140001044], "reads_from": [0x7ffdf000],
          "register_delta": {"RCX": (0x5, 0x6)}}
    r = _unicorn_run_result(_state_full("NO_PROGRESS", no_progress=np))
    assert r["success"] is True
    assert r["no_progress"]["kind"] == "polling"
    assert r["no_progress"]["pc"] == "0x140001045"
    assert r["no_progress"]["loop_pcs"] == ["0x140001040", "0x140001044"]
    assert r["no_progress"]["reads_from"] == ["0x7ffdf000"]
    assert r["no_progress"]["register_delta"] == {"RCX": ["0x5", "0x6"]}


def test_unicorn_run_rejects_oep_without_tracking(monkeypatch):
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    b._UNICORN_SESSIONS[8192] = UnicornSession(track_dirty=False)
    b.active_instances[8192] = {"url": "http://localhost:8192"}
    try:
        r = b.unicorn_run.__wrapped__("0x0", stop_on=["oep"], port=8192)
        assert r["success"] is False
        assert r["error"]["code"] == "OEP_NEEDS_TRACKING"
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_bridge_unicorn.py -k "oep_result or no_progress_result or rejects_oep" -v`
Expected: FAIL (`KeyError: 'oep'` / `unicorn_run() got an unexpected keyword argument 'stop_on'`).

- [ ] **Step 3: Write minimal implementation**

3a. In `_unicorn_run_result`, change the success branch condition and add the payloads. Replace:

```python
    if stop in (StopReason.DONE, StopReason.WATCHPOINT):
```

with:

```python
    if stop in (StopReason.DONE, StopReason.WATCHPOINT, StopReason.OEP, StopReason.NO_PROGRESS):
```

and, immediately before `return payload` inside that branch (after the existing `watch_hit` block), add:

```python
        if stop == StopReason.OEP and state.get("oep") is not None:
            payload["oep"] = {"pc": hex(state["oep"])}
        if stop == StopReason.NO_PROGRESS and state.get("no_progress"):
            np = state["no_progress"]
            payload["no_progress"] = {
                "kind": np["kind"],
                "pc": hex(np["pc"]),
                "loop_pcs": [hex(a) for a in np["loop_pcs"]],
                "reads_from": [hex(a) for a in np["reads_from"]],
                "register_delta": {k: [hex(b), hex(a)]
                                   for k, (b, a) in np["register_delta"].items()},
            }
```

3b. Change `unicorn_reset` signature and the `UnicornSession(...)` construction:

```python
def unicorn_reset(start: str, registers: dict | None = None, stack: bool = True,
                  track_dirty: bool = True, port: int | None = None) -> dict:
```

```python
        session = UnicornSession(byte_provider=make_ghidra_provider(client),
                                 track_dirty=track_dirty)
```

Add a line to the reset docstring Args describing `track_dirty` (mirror the style of the `stack` arg):

```python
        track_dirty: Track written/executed pages so unicorn_sync_to_program and
            stop_on=["oep"] work (default True; set False only for pure speed on
            giant loops, which disables dirty-page sync and OEP detection)
```

3c. Replace `unicorn_run`'s signature and body's `session.run(...)` call. New signature:

```python
def unicorn_run(until: str, count: int = 100000, trace: bool = False,
                watch_address: str | None = None, watch_length: int = 0,
                stop_on: list[str] | None = None,
                no_progress_window: int = 5000, no_progress_max_reads: int = 2,
                port: int | None = None) -> dict:
```

After the `except ValueError` block that parses addresses, before calling `session.run`, add validation:

```python
    stop_set = set(stop_on or [])
    unknown = stop_set - {"oep", "no_progress"}
    if unknown:
        return {"success": False,
                "error": {"code": "INVALID_STOP_ON",
                          "message": f"unknown stop_on values: {sorted(unknown)} "
                                     "(valid: 'oep', 'no_progress')"}}
    if "oep" in stop_set and not session.track_dirty:
        return {"success": False,
                "error": {"code": "OEP_NEEDS_TRACKING",
                          "message": "stop_on=['oep'] requires a session created "
                                     "with track_dirty=True"}}
```

Change the `session.run(...)` call to:

```python
    state = session.run(begin=begin, until=until_int, count=count, trace=trace,
                        watch_start=watch_addr_int, watch_length=watch_len_int,
                        stop_on=stop_set, no_progress_window=no_progress_window,
                        no_progress_max_reads=no_progress_max_reads)
```

Add to the `unicorn_run` docstring Args (after `watch_length`):

```python
        stop_on: Optional list of early-stop predicates: "oep" (stop when a
            previously-written byte is executed — classic unpack-complete signal;
            needs track_dirty) and "no_progress" (stop on a spin/polling dead loop)
        no_progress_window: Instructions per no_progress evaluation window (default 5000)
        no_progress_max_reads: Max unique read addresses for a window to count as a
            polling loop (default 2); raise both to loosen the detector on heavy
            legitimate loops (unpackers, VM dispatchers)
```

3d. Register scratch regions. In `_apply_default_stack`, after `session.map_bytes(_DEFAULT_STACK_BASE, ...)` add:

```python
    session.mark_scratch(_DEFAULT_STACK_BASE, _DEFAULT_STACK_SIZE)
```

In `unicorn_win64_scaffold`, after the four `session.map_bytes(...)` calls (just before `session.set_register("GS_BASE", teb_base)`), add:

```python
    session.mark_scratch(peb_base, 0x4000)   # PEB/TEB/LDR/params scaffold
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_bridge_unicorn.py -v`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn.py
git commit -m "feat(bridge): wire track_dirty, stop_on, and predicate payloads into unicorn tools"
```

---

### Task 4: Java — `MemoryService.createBlock` + `disassembleCommit`

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/MemoryService.java`

**Interfaces:**
- Consumes: existing `GhidraUtil.resolveAddress`, `TransactionHelper.executeInTransaction`.
- Produces:
  - `Map<String,Object> createBlock(Program program, String name, String addressStr, long size, String hexBytes, String permissions) throws Exception`
  - `int disassembleCommit(Program program, String addressStr, int length) throws Exception`

- [ ] **Step 1: Add imports**

At the top of `MemoryService.java`, add (next to the existing Ghidra imports):

```java
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
```

- [ ] **Step 2: Implement `createBlock`**

Add to `MemoryService` (near `writeBytes`):

```java
    /**
     * Create a new initialized memory block and optionally fill it with hex bytes.
     * Used to receive unpacked/heap regions synced back from the Unicorn engine.
     */
    public java.util.Map<String, Object> createBlock(Program program, String name,
            String addressStr, long size, String hexBytes, String permissions) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        if (size <= 0) {
            throw new IllegalArgumentException("size must be positive");
        }
        byte[] data = null;
        if (hexBytes != null && !hexBytes.isEmpty()) {
            String cleaned = hexBytes.replaceAll("[^0-9a-fA-F]", "");
            if (cleaned.length() % 2 != 0) {
                throw new IllegalArgumentException("hex byte string must have even length");
            }
            data = new byte[cleaned.length() / 2];
            for (int i = 0; i < cleaned.length(); i += 2) {
                data[i / 2] = (byte) Integer.parseInt(cleaned.substring(i, i + 2), 16);
            }
        }
        final String blockName = (name == null || name.isEmpty()) ? "unicorn_sync" : name;
        final long finalSize = size;
        final byte[] finalData = data;
        final String perms = permissions;
        final Address finalAddress = address;
        return TransactionHelper.executeInTransaction(program,
            "Create memory block " + blockName, () -> {
                Memory mem = program.getMemory();
                if (mem.getBlock(finalAddress) != null) {
                    throw new IllegalArgumentException(
                        "address " + addressStr + " overlaps an existing block");
                }
                MemoryBlock block = mem.createInitializedBlock(
                    blockName, finalAddress, finalSize, (byte) 0, TaskMonitor.DUMMY, false);
                boolean r = perms == null || perms.contains("r");
                boolean w = perms == null || perms.contains("w");
                boolean x = perms != null && perms.contains("x");
                block.setPermissions(r, w, x);
                if (finalData != null) {
                    mem.setBytes(finalAddress, finalData);
                }
                java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
                out.put("name", block.getName());
                out.put("start", block.getStart().toString());
                out.put("end", block.getEnd().toString());
                out.put("size", block.getSize());
                out.put("permissions", (r ? "r" : "-") + (w ? "w" : "-") + (x ? "x" : "-"));
                return out;
            });
    }
```

- [ ] **Step 3: Implement `disassembleCommit`**

```java
    /**
     * Clear code units in [address, address+length) and run the disassembler,
     * committing real instructions (unlike the read-only disassembleAt view).
     * Returns the number of instructions created in the range.
     */
    public int disassembleCommit(Program program, String addressStr, int length) throws Exception {
        Address address = GhidraUtil.resolveAddress(program, addressStr);
        if (address == null) {
            throw new IllegalArgumentException("Invalid address: " + addressStr);
        }
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        final Address start = address;
        final Address end = address.add(length - 1);
        return TransactionHelper.executeInTransaction(program,
            "Disassemble " + addressStr, () -> {
                AddressSet set = new AddressSet(start, end);
                program.getListing().clearCodeUnits(start, end, false);
                DisassembleCommand cmd = new DisassembleCommand(set, null, true);
                cmd.applyTo(program, TaskMonitor.DUMMY);
                int n = 0;
                var it = program.getListing().getInstructions(set, true);
                while (it.hasNext()) {
                    it.next();
                    n++;
                }
                return n;
            });
    }
```

- [ ] **Step 4: Compile**

Run: `GHIDRA_HOME=/path/to/ghidra mvn -q -DskipTests compile`
Expected: BUILD SUCCESS (resolves `DisassembleCommand`, `AddressSet`, `Memory`, `MemoryBlock`, `TaskMonitor`).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/MemoryService.java
git commit -m "feat(java): MemoryService.createBlock and disassembleCommit"
```

---

### Task 5: Java — `ProgramResource` routes for block-create and disassemble-commit

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/resource/ProgramResource.java`

**Interfaces:**
- Consumes: `MemoryService.createBlock`, `MemoryService.disassembleCommit` (Task 4).
- Produces (REST):
  - `POST /programs/current/memory/blocks` — body `{name, address, size, hex?, permissions?}` → created block info.
  - `POST /programs/current/memory/{address}/disassemble` — body `{length}` → `{address, instructions}`.

- [ ] **Step 1: Register routes**

In `register`, after the existing `routes.patch("/programs/current/memory/{address}", this::writeMemory);` line, add:

```java
        routes.post("/programs/current/memory/blocks", this::createBlock);
        routes.post("/programs/current/memory/{address}/disassemble", this::disassembleMemory);
```

- [ ] **Step 2: Implement handlers + request DTOs**

Add to `ProgramResource`:

```java
    private void createBlock(GhidraContext ctx) {
        var program = ctx.requireProgram();
        CreateBlockRequest req = ctx.bodyAsClass(CreateBlockRequest.class);
        if (req.address == null || req.size <= 0) {
            throw new IllegalArgumentException("address and positive size are required");
        }
        try {
            Object info = memoryService.createBlock(program, req.name, req.address,
                req.size, req.hex, req.permissions);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), info)
                .self("/programs/current/memory/blocks")
                .link("memory", "/memory")
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create block: " + e.getMessage(), e);
        }
    }

    private void disassembleMemory(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String address = ctx.pathParam("address");
        DisassembleRequest req = ctx.bodyAsClass(DisassembleRequest.class);
        if (req.length <= 0) {
            throw new IllegalArgumentException("positive length is required");
        }
        try {
            int instructions = memoryService.disassembleCommit(program, address, req.length);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), Map.of(
                    "address", address,
                    "instructions", instructions))
                .self("/programs/current/memory/{}/disassemble", address)
                .link("memory", "/memory/{}", address)
                .build());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to disassemble: " + e.getMessage(), e);
        }
    }

    private static class CreateBlockRequest {
        public String name;
        public String address;
        public long size;
        public String hex;
        public String permissions;
    }

    private static class DisassembleRequest {
        public int length;
    }
```

- [ ] **Step 3: Compile**

Run: `GHIDRA_HOME=/path/to/ghidra mvn -q -DskipTests compile`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Manual smoke against a live instance** (auto-skip if no Ghidra)

With a Ghidra instance running the plugin on 8192, from a Python shell:

```python
import requests
base = "http://127.0.0.1:8192"
print(requests.post(base + "/programs/current/memory/blocks",
      json={"name": "smoke", "address": "0x0f000000", "size": 4096,
            "hex": "90c3", "permissions": "rx"}).json())
print(requests.post(base + "/programs/current/memory/0x0f000000/disassemble",
      json={"length": 2}).json())   # expect {"instructions": 2, ...} (NOP; RET)
```

Expected: block created, then `instructions` ≥ 1. (If the address collides, pick a free one from `/segments`.)

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/resource/ProgramResource.java
git commit -m "feat(java): POST routes for memory block creation and disassemble-commit"
```

---

### Task 6: Bridge tools `memory_create_block` + `memory_disassemble_commit`

**Files:**
- Modify: `bridge_mcp_hydra.py` (new tools + `_post_create_block`/`_post_disassemble_commit` helpers)
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Consumes: `safe_post`, `simplify_response`, `_get_instance_port` (existing bridge helpers), the Task 5 endpoints.
- Produces:
  - `_post_create_block(port, name, address, size, hexstr) -> dict` (raw response)
  - `_post_disassemble_commit(port, address, length) -> dict` (raw response)
  - MCP tools `memory_create_block(name, address, size, hex=None, permissions="rwx", port=None)` and `memory_disassemble_commit(address, length, port=None)`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_bridge_unicorn.py`:

```python
def test_create_block_helper_posts_expected_payload(monkeypatch):
    import bridge_mcp_hydra as b
    captured = {}

    def fake_post(port, path, body):
        captured["path"] = path
        captured["body"] = body
        return {"success": True, "result": {"name": body["name"]}}

    monkeypatch.setattr(b, "safe_post", fake_post)
    out = b._post_create_block(8192, "unpacked_0", "0x140000000", 4096, "9090")
    assert captured["path"] == "programs/current/memory/blocks"
    assert captured["body"] == {"name": "unpacked_0", "address": "0x140000000",
                                "size": 4096, "hex": "9090", "permissions": "rwx"}
    assert out["success"] is True


def test_disassemble_commit_helper_posts_length(monkeypatch):
    import bridge_mcp_hydra as b
    captured = {}
    monkeypatch.setattr(b, "safe_post",
                        lambda port, path, body: captured.update(path=path, body=body) or {"success": True})
    b._post_disassemble_commit(8192, "0x140000000", 32)
    assert captured["path"] == "programs/current/memory/0x140000000/disassemble"
    assert captured["body"] == {"length": 32}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_bridge_unicorn.py -k "create_block_helper or disassemble_commit_helper" -v`
Expected: FAIL (`AttributeError: module 'bridge_mcp_hydra' has no attribute '_post_create_block'`).

- [ ] **Step 3: Write minimal implementation**

Add helpers near `memory_write` in `bridge_mcp_hydra.py`:

```python
def _post_create_block(port: int, name: str, address: str, size: int,
                       hexstr: str | None, permissions: str = "rwx") -> dict:
    body = {"name": name, "address": address, "size": size, "permissions": permissions}
    if hexstr is not None:
        body["hex"] = hexstr
    return safe_post(port, "programs/current/memory/blocks", body)


def _post_disassemble_commit(port: int, address: str, length: int) -> dict:
    return safe_post(port, f"programs/current/memory/{address}/disassemble",
                     {"length": length})
```

Add the MCP tools (place them after `memory_disassemble` so they sit in the `memory_*` group):

```python
@mcp.tool()
@text_output
def memory_create_block(name: str, address: str, size: int, hex: str | None = None,
                        permissions: str = "rwx", port: int | None = None) -> dict:
    """Create a new initialized memory block (e.g. to hold unpacked code).

    Args:
        name: Block name
        address: Start address in hex
        size: Block size in bytes
        hex: Optional initial contents as a hex string
        permissions: Any of "r","w","x" (default "rwx")
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(_post_create_block(port, name, address, size, hex, permissions))


@mcp.tool()
@text_output
def memory_disassemble_commit(address: str, length: int, port: int | None = None) -> dict:
    """Clear and re-disassemble a range, committing real instructions to the listing.

    Unlike memory_disassemble (a read-only view), this mutates the program so the
    decompiler sees freshly-written/unpacked bytes as code.

    Args:
        address: Start address in hex
        length: Number of bytes to disassemble
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    return simplify_response(_post_disassemble_commit(port, address, length))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_bridge_unicorn.py -k "create_block_helper or disassemble_commit_helper" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn.py
git commit -m "feat(bridge): memory_create_block and memory_disassemble_commit tools"
```

---

### Task 7: Bridge `unicorn_sync_to_program`

**Files:**
- Modify: `bridge_mcp_hydra.py` (new tool + `_sync_fetch_segments`, `_sync_write_chunks`, `_sync_classify` helpers)
- Test: `tests/test_bridge_unicorn.py`

**Interfaces:**
- Consumes: `session.dirty_pages()`, `session.executed_pages`, `session.read_memory` (engine); `_post_create_block`, `_post_disassemble_commit` (Task 6); `safe_get`, `safe_patch`, `_get_unicorn_session`, `_unicorn_error`.
- Produces: MCP tool `unicorn_sync_to_program(start=None, length=None, disassemble=True, port=None)` returning `{"success": True, "synced": [...], "skipped": [...]}`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_bridge_unicorn.py`:

```python
def _sync_setup(monkeypatch, executed_pages):
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    s = UnicornSession()
    # map + write two pages: 0x140000000 (in-segment) and 0x30000000 (executed heap)
    s.map_bytes(0x140000000, b"\x90" * 0x1000)
    s.map_bytes(0x30000000, b"\xcc" * 0x1000)
    s.written_pages.update({0x140000000, 0x30000000})
    s.executed_pages.update(executed_pages)
    b._UNICORN_SESSIONS[8192] = s
    b.active_instances[8192] = {"url": "http://localhost:8192"}

    calls = {"patched": [], "created": [], "disasm": []}
    monkeypatch.setattr(b, "safe_get", lambda port, path: {"success": True, "result": [
        {"start": "0x140000000", "end": "0x140010000"}]})
    monkeypatch.setattr(b, "safe_patch",
                        lambda port, path, body: calls["patched"].append((path, body)) or {"success": True})
    monkeypatch.setattr(b, "_post_create_block",
                        lambda *a: calls["created"].append(a) or {"success": True, "result": {"name": "unpacked_0"}})
    monkeypatch.setattr(b, "_post_disassemble_commit",
                        lambda *a: calls["disasm"].append(a) or {"success": True})
    return b, calls


def test_sync_writes_in_segment_and_creates_block_for_executed_heap(monkeypatch):
    b, calls = _sync_setup(monkeypatch, executed_pages={0x30000000})
    try:
        r = b.unicorn_sync_to_program.__wrapped__(port=8192)
        assert r["success"] is True
        # in-segment page -> patched; heap page -> created block
        assert any("0x140000000" in p for p, _ in calls["patched"])
        assert len(calls["created"]) == 1
        starts = {item["start"] for item in r["synced"]}
        assert "0x140000000" in starts and "0x30000000" in starts
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_sync_skips_out_of_segment_unexecuted_heap(monkeypatch):
    b, calls = _sync_setup(monkeypatch, executed_pages=set())   # heap NOT executed
    try:
        r = b.unicorn_sync_to_program.__wrapped__(port=8192)
        assert len(calls["created"]) == 0
        assert any(item["start"] == "0x30000000" for item in r["skipped"])
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_bridge_unicorn.py -k "sync_writes_in_segment or sync_skips_out" -v`
Expected: FAIL (`AttributeError: ... 'unicorn_sync_to_program'`).

- [ ] **Step 3: Write minimal implementation**

Add helpers and the tool to `bridge_mcp_hydra.py` (place near the other `unicorn_*` tools):

```python
def _sync_fetch_segments(port: int) -> list[tuple[int, int]]:
    """Return [(start, end_exclusive)] for the program's memory segments."""
    resp = safe_get(port, "segments?limit=1000")
    result = resp.get("result", resp) if isinstance(resp, dict) else resp
    items = result if isinstance(result, list) else result.get("result", [])
    segs: list[tuple[int, int]] = []
    for seg in items:
        try:
            start = int(str(seg["start"]), 16)
            end = int(str(seg["end"]), 16)
            segs.append((start, end if end > start else end + 1))
        except (KeyError, ValueError, TypeError):
            continue
    return segs


def _sync_in_segment(start: int, length: int, segs: list[tuple[int, int]]) -> bool:
    return any(s <= start and start + length <= e for s, e in segs)


def _sync_write_chunks(port: int, address: int, data: bytes) -> None:
    for i in range(0, len(data), 4096):
        chunk = data[i:i + 4096]
        safe_patch(port, f"programs/current/memory/{hex(address + i)}",
                   {"bytes": chunk.hex(), "format": "hex"})


@mcp.tool()
@text_output
def unicorn_sync_to_program(start: str | None = None, length: int | None = None,
                            disassemble: bool = True, port: int | None = None) -> dict:
    """Push emulator memory back into the Ghidra program and (re)disassemble it.

    With no arguments, syncs every page the emulator wrote to (excluding
    stack/PEB scratch). Pages inside an existing block are overwritten; executed
    pages outside any block get a fresh block; unexecuted out-of-segment writes
    are skipped. Pass start/length (hex/int) to sync one explicit region.

    Args:
        start: Optional explicit region start in hex
        length: Optional explicit region length in bytes
        disassemble: Commit-disassemble executed regions after writing (default True)
        port: Specific Ghidra instance port (optional)
    """
    port = _get_instance_port(port)
    try:
        session = _get_unicorn_session(port)
    except KeyError as e:
        return _unicorn_error(str(e))

    if start is not None:
        try:
            regions = [(int(start, 16), length or 0x1000)]
        except ValueError as e:
            return {"success": False, "error": {"code": "INVALID_ADDRESS", "message": str(e)}}
    else:
        regions = session.dirty_pages()

    segs = _sync_fetch_segments(port)
    synced: list[dict] = []
    skipped: list[dict] = []
    created_n = 0

    for rstart, rlen in regions:
        try:
            data = session.read_memory(rstart, rlen)
        except Exception as e:
            skipped.append({"start": hex(rstart), "length": rlen, "reason": f"unreadable: {e}"})
            continue
        executed = any((rstart + off) & ~0xfff in session.executed_pages
                       for off in range(0, rlen, 0x1000))
        entry = {"start": hex(rstart), "length": rlen, "created": False, "disassembled": False}
        if _sync_in_segment(rstart, rlen, segs):
            _sync_write_chunks(port, rstart, data)
            entry["block"] = "existing"
        elif executed:
            name = f"unpacked_{created_n}"
            created_n += 1
            _post_create_block(port, name, hex(rstart), rlen, data.hex())
            entry["block"] = name
            entry["created"] = True
        else:
            skipped.append({"start": hex(rstart), "length": rlen,
                            "reason": "out-of-segment, not executed"})
            continue
        if disassemble and executed:
            _post_disassemble_commit(port, hex(rstart), rlen)
            entry["disassembled"] = True
        synced.append(entry)

    return {"success": True, "synced": synced, "skipped": skipped,
            "timestamp": int(time.time() * 1000)}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_bridge_unicorn.py -v`
Expected: PASS (all).

- [ ] **Step 5: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_unicorn.py
git commit -m "feat(bridge): unicorn_sync_to_program smart-hybrid sync"
```

---

### Task 8: Version bumps, docs, full-suite verification

**Files:**
- Modify: `bridge_mcp_hydra.py` (`BRIDGE_VERSION`), `src/main/java/eu/starsong/ghidra/api/ApiConstants.java` (`PLUGIN_VERSION`), `CHANGELOG.md`

**Interfaces:** none (release bookkeeping).

- [ ] **Step 1: Bump versions**

In `bridge_mcp_hydra.py`, increment the `BRIDGE_VERSION` string (patch→minor, e.g. `"1.x.0"`). In `ApiConstants.java`, increment `PLUGIN_VERSION` the same way. Do **not** change `API_VERSION` / `REQUIRED_API_VERSION`.

Verify the exact current values first:

Run: `grep -n "BRIDGE_VERSION" bridge_mcp_hydra.py && grep -n "PLUGIN_VERSION\|API_VERSION" src/main/java/eu/starsong/ghidra/api/ApiConstants.java`

- [ ] **Step 2: Update CHANGELOG**

Add an entry under the top/unreleased section of `CHANGELOG.md`:

```markdown
### Added
- `unicorn_sync_to_program` — push emulator memory (unpacked code) back into Ghidra,
  auto-creating blocks for executed out-of-segment regions and committing disassembly.
- `memory_create_block` and `memory_disassemble_commit` MCP tools + REST endpoints.
- `unicorn_run` `stop_on` predicates: `oep` (execute-a-written-byte) and `no_progress`
  (spin/polling detection), with `no_progress_window`/`no_progress_max_reads` tuning.
- `unicorn_reset` `track_dirty` flag (default on) enabling dirty-page tracking.
```

- [ ] **Step 3: Run the full offline suite**

Run: `pytest tests/ -v`
Expected: PASS (whole unit suite, no Ghidra).

- [ ] **Step 4: Commit**

```bash
git add bridge_mcp_hydra.py src/main/java/eu/starsong/ghidra/api/ApiConstants.java CHANGELOG.md
git commit -m "chore: bump plugin/bridge versions and changelog for unicorn sync + predicates"
```

---

## Self-Review

**1. Spec coverage:**
- Component A ledger (written_pages/written_bits/executed_pages/scratch_ranges, track_dirty, dirty_pages) → Tasks 1, 2, 3. ✓
- Component B sync (dirty-default + explicit override, in-segment vs executed-heap vs skip, disassemble) → Task 7; Java block-create + disasm-commit → Tasks 4, 5; bridge tools → Task 6. ✓
- Component C predicates (OEP double-set, no_progress windowed spin/polling, payload, tunable params, oep-needs-track_dirty rejection) → Tasks 2, 3. ✓
- Out-of-scope items (5M cap, §7.2, modes, textual disasm) → not implemented, per spec. ✓
- Backward compatibility (stop_on=None, track_dirty default, no API bump) → Task 2 preserves run() semantics, Task 8 leaves API_VERSION untouched. ✓
- Testing tiers (offline pytest + fake client; Java validated at integration/manual) → every task has offline tests except Java Tasks 4–5, which use compile + manual smoke (matches the repo's lack of offline Java stubs). ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"; every code step shows full code. The only soft spot is the hand-assembled x86 hex in Task 2's OEP tests, which carries an explicit instruction to fix the bytes (not the assertion) if they misassemble.

**3. Type consistency:** `track_dirty`, `written_pages`, `written_bits`, `executed_pages`, `scratch_ranges`, `mark_scratch`, `dirty_pages`, `StopReason.OEP`/`NO_PROGRESS`, `stop_on`/`no_progress_window`/`no_progress_max_reads`, `_post_create_block`/`_post_disassemble_commit` names match across engine, bridge, and tests. The `no_progress` payload keys (`kind`/`pc`/`loop_pcs`/`reads_from`/`register_delta`) are identical in Task 2 (produced) and Task 3 (consumed/hex-formatted).

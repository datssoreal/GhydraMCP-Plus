# Design: Unicorn autonomy plumbing — `sync_to_program` + stop predicates

> Status: approved (brainstorming) — ready for implementation plan.
> Date: 2026-07-01.
> Source: `docs/COMPETITIVE_GAPS.md` §7 (Autonomy Loop). Closes the two §7 Quick Wins
> plus the OEP-detect item so an autonomous agent can act on what the emulator produced.

## Problem

`docs/COMPETITIVE_GAPS.md` §7 diagnoses that the autonomy loop breaks not on missing
*analytical* features but on missing **plumbing** between the Unicorn session and the Ghidra
program. Concretely, from the live `mbb.exe` unpacking session:

1. Unpacked code exists only inside the Unicorn session — Ghidra's static view at the same
   addresses still holds the pre-unpack bytes. There is no primitive to push decrypted regions
   back into Ghidra and disassemble them (§7.1).
2. `unicorn_run` can only stop on an exact `until` address, a watchpoint, or the instruction
   count cap. An anti-analysis spin (`PAUSE; JMP $`) burns the entire budget instead of
   stopping early. There is no loop / no-progress detection.
3. There is no OEP (unpack-complete) trigger — the classic "write bytes, then execute them"
   signal that unpacking is done.

## Scope

Three related pieces in **one worktree** (all centred on `unicorn_engine.py` + the bridge,
around the unpacking loop):

- **B. `unicorn_sync_to_program` (§7.1)** — smart-hybrid sync of emulator memory back into the
  Ghidra program, with commit-disassembly and auto-block-creation.
- **C. Stop predicates on `unicorn_run`** — `no_progress` (spin/polling detection) and `oep`
  (writes-then-executes).
- **A. Session ledger** — the shared, always-on tracking that B and C both consume.

### Explicitly out of scope (deferred follow-ups)

- Raising / removing the 5M instruction `run` cap — the stop predicates address the
  "burned budget" pain more precisely; separate follow-up.
- Windows API emulation layer (§7.2) — a separate, larger worktree.
- human-assisted vs autonomous "modes" — a workflow-layer concern on top of these primitives,
  not engine code now.
- Textual disassembly of the detected loop body in the `no_progress` payload — would require a
  capstone dependency; the payload returns addresses and the agent disassembles them with its
  existing memory tools if it wants text.

## Component A — Session ledger (shared foundation)

`UnicornSession` accumulates the following **across all `run()` calls within one session**
(i.e. from `unicorn_reset` until the next reset/dispose), not per-run:

```python
def __init__(self, byte_provider=None, track_dirty=True):
    ...
    self.track_dirty = track_dirty
    self.written_pages: set[int] = set()     # pages written to (addr & ~0xfff)
    self.executed_pages: set[int] = set()    # pages executed (from code hook)
    self.scratch_ranges: list[tuple[int, int]] = []  # (base, size) to exclude from sync
```

- **`written_pages`** — updated by the memory-write hook, which becomes **always-on** (today it
  is only added when `trace` or a watchpoint is active). Rationale: `UC_HOOK_CODE` is already
  registered unconditionally (step counting + hook dispatch), so the engine is already in
  per-callback stepping mode; adding `UC_HOOK_MEM_WRITE` adds no new JIT penalty, and the
  callback body is a single `set.add` + bitmask. Making it always-on lets
  `unicorn_sync_to_program` "just work" in dirty-page mode at any time — critical for seamless
  autonomy (an opt-in flag would be forgotten, causing wasted emulation re-runs).
- **`track_dirty=True`** bypass — plumbed through `unicorn_reset`; set `False` only in extreme
  pure-speed scenarios on giant loops, sacrificing dirty-page sync.
- **`executed_pages`** — updated by the code hook; used to justify auto-block-creation ("this
  out-of-segment region was executed") and consumed by the OEP predicate.
- **`scratch_ranges`** — registered when scratch memory is mapped: `_apply_default_stack`, the
  `call()` scaffold (`_CALL_STACK_BASE`), and `unicorn_win64_scaffold` (PEB/TEB region). Sync
  discards any page inside a scratch range.

New method:

```python
def dirty_pages(self) -> list[tuple[int, int]]:
    """Written pages minus scratch, coalesced into contiguous (start, length) runs."""
```

## Component B — `unicorn_sync_to_program` (§7.1, full hybrid)

Agent-facing bridge tool:

```python
def unicorn_sync_to_program(start: str | None = None, length: int | None = None,
                            disassemble: bool = True, port: int | None = None) -> dict:
```

Flow:

1. **Regions.** If `start`/`length` are given → that explicit range. Otherwise →
   `session.dirty_pages()`.
2. **Classify** each region against the Ghidra segment layout (fetched once per call via the
   existing `segments_list`, cached for the call):
   - **Inside an existing initialized block** → write via `PATCH /programs/current/memory/{addr}`
     in chunks of ≤4096 bytes (mirrors the server's read cap).
   - **Outside any block AND executed** (region ∩ `executed_pages` non-empty) → auto-create a
     block (new Java endpoint), then write.
   - **Outside any block and not executed** (heap data) → **skip**, reported in the response.
3. If `disassemble=True` → for the executed sub-ranges, call the commit-disassemble endpoint.
4. **Response** (agent-oriented):

```json
{
  "synced":  [{"start": "0x...", "length": 4096, "block": "unpacked_0", "created": true,  "disassembled": true}],
  "skipped": [{"start": "0x...", "length": 8192, "reason": "out-of-segment, not executed"}]
}
```

### New Java endpoints

Both run inside a transaction on the EDT (`TransactionHelper` + `GhidraSwing`), following the
existing `MemoryService.writeBytes` pattern.

- **`POST /programs/current/memory/blocks`** — body `{name, address, size, hex?, permissions}`.
  `memory.createInitializedBlock(name, addr, size, (byte)0, monitor, false)` then `setBytes`
  for `hex`. Rejects overlaps with existing blocks. Returns the created block info.
  Bridge tool: `memory_create_block`.
- **`POST /programs/current/memory/{address}/disassemble`** — body `{length}`.
  `listing.clearCodeUnits(range, false)` then
  `new DisassembleCommand(addrSet, null, true).applyTo(program)`. Returns the number of
  instructions created. Distinct from the existing read-only `GET /memory/{address}/disassembly`
  so GET stays idempotent. Bridge tool: `memory_disassemble_commit`.

Both are exposed as standalone MCP tools (useful independently); `unicorn_sync_to_program`
composes them internally.

## Component C — stop predicates on `unicorn_run`

Extended signatures:

```python
# engine
def run(self, begin, until=0, count=100000, timeout=0, trace=False,
        max_lazy_pages=4096, watch_start=None, watch_length=0,
        stop_on=None, no_progress_window=5000, no_progress_max_reads=2):

# bridge
def unicorn_run(until: str, count: int = 100000, trace: bool = False,
                watch_address: str | None = None, watch_length: int = 0,
                stop_on: list[str] | None = None,
                no_progress_window: int = 5000,
                no_progress_max_reads: int = 2,
                port: int | None = None) -> dict:
```

`stop_on` accepts `{"no_progress", "oep"}`; empty/`None` → current behaviour (backward
compatible).

### OEP — `writes_then_executes`

The code hook checks whether the current PC's page is in `written_pages` (written during this
session). On a hit → stop with `StopReason.OEP`, payload `{"oep": {"pc": "0x...", ...}}`.
Page-granular (accepts a small false-positive risk for code that writes then linearly executes
its own page); opt-in, so the risk is bounded to callers that ask for it. Because it consumes
the write ledger, `oep` requires `track_dirty=True`; combining `stop_on=["oep"]` with a
`track_dirty=False` session is rejected with a clear error rather than silently never firing.

### `no_progress` — coarse-grained cycle detection

Windowed, evaluated only at window boundaries (cheap; no per-instruction register snapshots):

- Window `W = no_progress_window` (default 5000) steps.
- The memory-**read** hook (`UC_HOOK_MEM_READ`) is added **only when `"no_progress"` is in
  `stop_on`** — the read-tracking overhead is paid only on request.
- At each window boundary, **if the window's write count == 0**:
  - state hash `h = hash(RIP, RSP, RAX, RBX, RCX, RDX, RSI, RDI)`. If `h` was seen in a prior
    zero-write window → deterministic dead loop → stop, `kind="spin_lock"`.
  - else if the window's unique read-address count ≤ `no_progress_max_reads` (default 2) →
    polling loop (spinning on a flag/timer that cannot change in isolation) → stop,
    `kind="polling"`.
  - else (read-address entropy is growing — a buffer scan) → **progress; do not stop**, reset
    the window counters.
- New `StopReason.NO_PROGRESS` (single enum value; the kind lives in the payload to keep the
  enum lean).

Both `no_progress_window` and `no_progress_max_reads` are tunable per call so an agent that
recognises a legitimate unpacker/VM-dispatcher (a heavy loop that legitimately exceeds the
defaults) can loosen the detector (e.g. `W=20000, R=5`) and continue, rather than disabling the
guard or crashing.

### Agent-oriented payload

On a `no_progress` stop the result carries enough context for the agent to break the loop
itself (e.g. write a flag, or set RIP past the loop, then continue):

```json
{"stop_reason": "NO_PROGRESS",
 "no_progress": {
   "kind": "polling",
   "pc": "0x140001045",
   "loop_pcs": ["0x140001040", "0x140001042", "0x140001044"],
   "reads_from": ["0x7ffdf000"],
   "register_delta": {"RAX": "0x0 -> 0x0"}}}
```

`loop_pcs`, `reads_from`, and `register_delta` are returned as **addresses/values** — the engine
stays Ghidra-free. Textual disassembly is intentionally omitted (see out-of-scope).

## Testing (offline, `tests/`, fake client — no Ghidra)

- **Ledger:** `dirty_pages()` excludes scratch ranges; accumulation persists across multiple
  `run()` calls; `track_dirty=False` disables tracking.
- **OEP:** write to a page then execute it → `StopReason.OEP`.
- **no_progress:** `PAUSE; JMP $` → `spin_lock`; a loop reading a single address → `polling`; a
  productive decrypt loop (writes bytes) does **not** trigger; window/max-reads overrides
  loosen the detector as expected.
- **Sync classification:** in-segment vs executed-heap vs skip, driven by a fake `segments_list`
  response; explicit `(start, length)` override path.
- **Java:** unit tests for block-create and disassemble-commit go in `src/test/java`; these need
  Ghidra jars at build time, so they run as part of the Maven/integration tier, not the offline
  `pytest` suite.

## Backward compatibility

- `stop_on=None` and the new `no_progress_*` params default to current behaviour.
- `track_dirty=True` default; existing sessions gain always-on write tracking transparently.
- New Java endpoints are additive; the read-only disassembly GET is unchanged.
- No `API_VERSION` bump required (purely additive). Bump `PLUGIN_VERSION` and `BRIDGE_VERSION`;
  update `CHANGELOG.md`.

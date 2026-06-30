# Batch Mode Pipeline — Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the correctness, error-handling, and test-coverage findings from the PR #7 review of the batch-mode pipeline, so an atomic batch never leaks a raw 500, best-effort isolation always holds, and the new code is unit-tested.

**Architecture:** The batch pipeline (`POST /batch`) dispatches virtual sub-requests in-process to existing handlers via a `RouteRegistry`, capturing each handler's response through a `SyntheticGhidraContext`. The central fix makes `BatchService.dispatch()` *total* (it always returns a result, never throws), which simultaneously closes the atomic-rollback 500 leak and a best-effort isolation hole. The remaining changes add error mapping at the HTTP boundary, structured errors in the Python bridge, and unit tests for the four new Java types.

**Tech Stack:** Java 21 (Ghidra plugin, Javalin/Jetty, Gson, JUnit 4.13.2), Python 3.11+ (MCP bridge, pytest), Maven.

## Global Constraints

- **Java:** Java 21, Ghidra 11.x/12.x. Build needs `GHIDRA_HOME` set and `-Dghidra.version` matching the install (see CLAUDE.md "Build & test commands"). JUnit is **4.13.2** — `org.junit.Assert.assertThrows`, `assertSame` are available.
- **No `API_VERSION` change.** All fixes are additive/behavioral; `API_VERSION` stays `3000`.
- **No new version bump.** The feature is still unreleased on this branch (`PLUGIN_VERSION` `v3.3.0`, `BRIDGE_VERSION` `v3.4.0` already set, under `## [Unreleased]` in CHANGELOG). These are pre-merge refinements to that unreleased feature — do not bump again.
- **Conventions:** business logic in `service/`, not `resource/`; every response is the HATEOAS envelope via `Response`; the bridge's per-tool error shape is `{"success": false, "error": {"code", "message"}, "timestamp": <ms>}`; conventional-commit messages; update `CHANGELOG.md` for user-facing changes.
- **`ErrorMapper` is the single source of truth** for exception → (status, code, message). Never hand-roll status codes that `ErrorMapper` already produces.

---

## File Structure

**Modified (production):**
- `src/main/java/eu/starsong/ghidra/service/BatchService.java` — make `dispatch()` total; add per-sub-request 5xx logging; fix the `execute()` rollback comment; log genuine transaction failures.
- `src/main/java/eu/starsong/ghidra/resource/BatchResource.java` — map exceptions escaping `execute()` through `ErrorMapper`; reject an empty `requests` array with 400.
- `src/main/java/eu/starsong/ghidra/server/RouteRegistry.java` — defensive-copy `Match` maps; document first-match-wins ordering.
- `bridge_mcp_hydra.py` — add `_port_or_error` and `_safe_build` helpers; route all batch tools through them so malformed input / no-instance produce structured errors instead of raw exceptions.

**Created (tests):**
- `src/test/java/eu/starsong/ghidra/service/BatchServiceTest.java` — best-effort isolation, dispatch totality (the Critical #1 regression guard), `NO_ROUTE`, `NO_NESTED_BATCH`, `BAD_REQUEST`, atomic-without-program.

**Modified (tests/docs):**
- `src/test/java/eu/starsong/ghidra/middleware/ErrorMapperTest.java` — cover the 4 untested exception branches.
- `src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java` — DELETE/PUT, first-match-wins, `Match` immutability.
- `tests/test_bridge_batch.py` — malformed-input error, no-instance error, atomic-flag threading.
- `test_batch.py` — strengthen the atomic-rollback assertion; add `ROLLED_BACK` (409) and empty-requests (400) integration cases.
- `GHIDRA_HTTP_API.md` — note per-item `success` semantics on a rolled-back atomic batch.
- `CHANGELOG.md` — record the hardening under the existing batch entry.

---

## Task Ordering & Rationale

1. **Task 1 (BatchService)** is the keystone — it fixes the Critical finding and is fully unit-testable without Ghidra. Do it first.
2. **Task 2 (BatchResource)** depends on Task 1's behavior being correct (it maps what escapes `execute()`).
3. **Tasks 3–4 (Java tests + RouteRegistry)** are independent of 1–2 and of each other.
4. **Task 5 (bridge)** is pure Python, independent of the Java tasks.
5. **Task 6 (docs + integration tests)** comes last; the integration tests describe the end-state behavior of Tasks 1–2.

---

### Task 1: Make `BatchService.dispatch()` total + add logging

**Why:** Critical finding — in an atomic batch, an exception thrown by `RouteRegistry.match()` (it URL-decodes the path; a malformed `%` escape makes `URLDecoder` throw `IllegalArgumentException`) or by `GSON.toJson(body)` is raised *outside* `dispatch()`'s `try`. `TransactionHelper` re-throws `IllegalArgumentException` **unwrapped**, so `execute()`'s `catch (TransactionException)` never sees it: the `AbortBatch` partial results are lost and the client gets a bare 500. The same escape breaks **best-effort isolation** (one bad path aborts the whole loop). Fix the root cause: make `dispatch()` total so its only exit is a result map. Also addresses the missing 5xx logging and the now-inaccurate `execute()` comment.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/service/BatchService.java`
- Test: `src/test/java/eu/starsong/ghidra/service/BatchServiceTest.java` (create)

**Interfaces:**
- Consumes: `BatchService.execute(GhidraContext, RouteRegistry, BatchRequestDto) : List<Map<String,Object>>`; `RouteRegistry.add(String method, String pattern, Consumer<GhidraContext> handler)`; `BatchRequestDto` / `BatchRequestDto.SubRequest` (public fields `atomic`, `requests`, `method`, `path`, `body`); `GhidraContext(Context, PluginTool, int, Map<Integer,?>)`; `GhidraContext.NoProgramException`.
- Produces: no signature changes. Per-result map shape is unchanged: `{index:int, status:Integer, success:Boolean, body:Object}`.

- [ ] **Step 1: Write the failing test (create `BatchServiceTest`)**

```java
package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.BatchRequestDto;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.RouteRegistry;
import org.junit.Test;

import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class BatchServiceTest {

    private final BatchService service = new BatchService();

    /** A batch context with no tool -> program() is null (fine for best-effort dispatch). */
    private GhidraContext batchCtx() {
        return new GhidraContext(null, null, 8192, Map.of());
    }

    private BatchRequestDto.SubRequest sub(String method, String path) {
        BatchRequestDto.SubRequest s = new BatchRequestDto.SubRequest();
        s.method = method;
        s.path = path;
        return s;
    }

    private BatchRequestDto bestEffort(BatchRequestDto.SubRequest... subs) {
        BatchRequestDto dto = new BatchRequestDto();
        dto.atomic = false;
        dto.requests = List.of(subs);
        return dto;
    }

    @SuppressWarnings("unchecked")
    private String errorCode(Map<String, Object> result) {
        Map<String, Object> body = (Map<String, Object>) result.get("body");
        Map<String, Object> err = (Map<String, Object>) body.get("error");
        return (String) err.get("code");
    }

    @Test
    public void bestEffortIsolatesFailureAndRunsRest() {
        // "%ZZ" is an illegal percent-escape; RouteRegistry.match() URL-decodes the
        // path and throws IllegalArgumentException. dispatch() MUST contain it as a
        // per-sub-request 400 and still run the next sub-request. (Critical #1 guard.)
        RouteRegistry reg = new RouteRegistry();
        reg.add("GET", "/data/{address}", c -> c.json(Map.of("seen", c.pathParam("address"))));
        reg.add("GET", "/ok", c -> c.json(Map.of("done", true)));

        List<Map<String, Object>> out = service.execute(
            batchCtx(), reg, bestEffort(sub("GET", "/data/%ZZ"), sub("GET", "/ok")));

        assertEquals(2, out.size());
        assertEquals(Integer.valueOf(400), out.get(0).get("status"));
        assertEquals(Boolean.FALSE, out.get(0).get("success"));
        assertEquals(Integer.valueOf(200), out.get(1).get("status"));   // second still ran
        assertEquals(Boolean.TRUE, out.get(1).get("success"));
    }

    @Test
    public void handlerExceptionBecomes500() {
        RouteRegistry reg = new RouteRegistry();
        reg.add("GET", "/boom", c -> { throw new RuntimeException("kaboom"); });

        List<Map<String, Object>> out = service.execute(
            batchCtx(), reg, bestEffort(sub("GET", "/boom")));

        assertEquals(Integer.valueOf(500), out.get(0).get("status"));
        assertEquals("INTERNAL_ERROR", errorCode(out.get(0)));
    }

    @Test
    public void unknownRouteYields404NoRoute() {
        List<Map<String, Object>> out = service.execute(
            batchCtx(), new RouteRegistry(), bestEffort(sub("GET", "/nope")));
        assertEquals(Integer.valueOf(404), out.get(0).get("status"));
        assertEquals("NO_ROUTE", errorCode(out.get(0)));
    }

    @Test
    public void nestedBatchIsRejected() {
        List<Map<String, Object>> out = service.execute(
            batchCtx(), new RouteRegistry(), bestEffort(sub("POST", "/batch")));
        assertEquals(Integer.valueOf(400), out.get(0).get("status"));
        assertEquals("NO_NESTED_BATCH", errorCode(out.get(0)));
    }

    @Test
    public void missingMethodOrPathYields400() {
        List<Map<String, Object>> out = service.execute(
            batchCtx(), new RouteRegistry(), bestEffort(sub(null, "/data")));
        assertEquals(Integer.valueOf(400), out.get(0).get("status"));
        assertEquals("BAD_REQUEST", errorCode(out.get(0)));
    }

    @Test
    public void atomicWithoutProgramThrowsNoProgram() {
        RouteRegistry reg = new RouteRegistry();
        reg.add("GET", "/ok", c -> c.json(Map.of()));
        BatchRequestDto dto = new BatchRequestDto();
        dto.atomic = true;
        dto.requests = List.of(sub("GET", "/ok"));
        // batchCtx() has a null tool -> requireProgram() throws; BatchResource maps this to 503.
        assertThrows(GhidraContext.NoProgramException.class,
            () -> service.execute(batchCtx(), reg, dto));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `mvn test -Dtest=BatchServiceTest` (with `GHIDRA_HOME` set and `-Dghidra.version=<your install>`, per CLAUDE.md)
Expected: `bestEffortIsolatesFailureAndRunsRest` FAILS — the `%ZZ` `IllegalArgumentException` escapes `dispatch()` and propagates out of `execute()` (the whole call throws) instead of producing a 400 + running `/ok`. Other tests may pass already.

- [ ] **Step 3: Add the `Msg` import to `BatchService.java`**

Find:
```java
import ghidra.program.model.listing.Program;
```
Replace with:
```java
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
```

- [ ] **Step 4: Make `dispatch()` total + log 5xx**

Find the whole `dispatch(...)` method (the version that ends with the `catch (Exception e)` returning `error(index, mapped.status(), ...)`) and replace it with:

```java
    private Map<String, Object> dispatch(GhidraContext ctx, RouteRegistry registry,
                                         BatchRequestDto.SubRequest req, int index) {
        if (req == null || req.method == null || req.path == null) {
            return error(index, 400, "BAD_REQUEST", "Sub-request requires method and path");
        }
        if (req.path.equals("/batch") || req.path.startsWith("/batch?")) {
            return error(index, 400, "NO_NESTED_BATCH", "Nested /batch is not allowed");
        }
        // Everything below can throw on bad input -- RouteRegistry.match() URL-decodes the
        // path (a malformed % escape throws IllegalArgumentException) and GSON.toJson()
        // serializes the body -- or inside the handler. Keep it ALL in one try so dispatch()
        // is total: it always returns a result and never lets an exception escape. That is
        // what makes best-effort isolation hold and lets the atomic loop rely on AbortBatch
        // being the operation's only escape path.
        try {
            RouteRegistry.Match m = registry.match(req.method, req.path);
            if (m == null) {
                return error(index, 404, "NO_ROUTE", "No route for " + req.method + " " + req.path);
            }
            String bodyJson = req.body == null ? "{}" : GSON.toJson(req.body);
            SyntheticGhidraContext sctx = new SyntheticGhidraContext(
                ctx.tool(), ctx.port(), ctx.activeInstances(),
                req.method, req.path, m.pathParams(), m.queryParams(), bodyJson);
            m.handler().accept(sctx);
            int status = sctx.capturedStatus();
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("index", index);
            r.put("status", status);
            r.put("success", status < 400);
            r.put("body", sctx.capturedBody());
            return r;
        } catch (Exception e) {
            ErrorMapper.Mapped mapped = ErrorMapper.map(e);
            if (mapped.status() >= 500) {
                Msg.error(BatchService.class, "Batch sub-request [" + index + "] "
                    + req.method + " " + req.path + " failed", e);
            }
            return error(index, mapped.status(), mapped.code(), mapped.message());
        }
    }
```

- [ ] **Step 5: Fix the `execute()` rollback comment + log genuine failures**

Find:
```java
        } catch (TransactionHelper.TransactionException e) {
            // TransactionHelper catches every exception thrown inside the operation
            // (including our AbortBatch), rolls the transaction back, and re-throws it
            // wrapped as the *cause* of a TransactionException. So AbortBatch never
            // propagates directly -- recover it (and its partial results) from the
            // cause here. Anything else is a genuine transaction failure.
            if (e.getCause() instanceof AbortBatch ab) {
                return ab.results;          // transaction already rolled back by the throw
            }
            throw new RuntimeException("Batch transaction failed: " + e.getMessage(), e);
        }
```
Replace with:
```java
        } catch (TransactionHelper.TransactionException e) {
            // dispatch() is total, so the operation's only escape is our AbortBatch (a
            // RuntimeException). TransactionHelper rolls the transaction back and re-throws
            // it wrapped as the *cause* of a TransactionException, so recover AbortBatch
            // (and its partial results) from the cause here. Any other cause is a genuine
            // commit/transaction failure.
            if (e.getCause() instanceof AbortBatch ab) {
                return ab.results;          // transaction already rolled back by the throw
            }
            Msg.error(BatchService.class, "Atomic batch transaction failed", e);
            throw new RuntimeException("Batch transaction failed: " + e.getMessage(), e);
        }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `mvn test -Dtest=BatchServiceTest`
Expected: PASS (6 tests). If `handlerExceptionBecomes500` errors out on the `Msg.error` call (it should not — Ghidra's `Msg` logs to stderr without an initialized application), that is the only Ghidra-coupled line; report it rather than deleting the logging.

- [ ] **Step 7: Run the full Java suite to confirm no regressions**

Run: `mvn test`
Expected: BUILD SUCCESS; previously-green tests still pass, now `+6`.

- [ ] **Step 8: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/service/BatchService.java \
        src/test/java/eu/starsong/ghidra/service/BatchServiceTest.java
git commit -m "fix: make batch dispatch total so atomic rollback never leaks a 500

A malformed sub-request path (RouteRegistry.match URL-decodes it) or body
threw outside dispatch()'s try; TransactionHelper re-throws
IllegalArgumentException unwrapped, bypassing the AbortBatch recovery and
surfacing atomic failures as HTTP 500 with lost partial results. The same
escape broke best-effort isolation. dispatch() is now total (always returns
a result), 5xx sub-requests are logged, and the execute() comment is corrected.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Map `/batch` endpoint failures via `ErrorMapper` + reject empty batches

**Why:** Important finding — `BatchResource.handle()` has no `try/catch` around `batchService.execute()`. A `NoProgramException` (atomic batch, no program) or a genuine transaction failure escapes to Javalin's global `ErrorHandler`, which does **not** use `ErrorMapper`, so a missing program returns `500 INTERNAL_ERROR` instead of `503 NO_PROGRAM_LOADED`. Also, an empty `requests: []` currently returns `200` with an empty result (a silent no-op for an almost-certain caller bug); reject it with `400`.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/resource/BatchResource.java`
- Test: `test_batch.py` (live integration; verifies the empty-batch 400 — auto-skips without Ghidra)

**Interfaces:**
- Consumes: `ErrorMapper.map(Exception) : ErrorMapper.Mapped` with `.status()`, `.code()`, `.message()`; `Response.error(Context, int, String code, String message) : Response`; `Response.ok(Context, int, Object) : Response`; `GhidraContext.status(int)`, `.json(Object)`, `.ctx()`, `.port()`, `.bodyAsClass(Class)`.
- Produces: no signature changes.

- [ ] **Step 1: Add the `ErrorMapper` import**

Find:
```java
import eu.starsong.ghidra.dto.BatchRequestDto;
```
Replace with:
```java
import eu.starsong.ghidra.dto.BatchRequestDto;
import eu.starsong.ghidra.middleware.ErrorMapper;
```

- [ ] **Step 2: Rewrite `handle()` to reject empty batches and map escaped exceptions**

Find:
```java
    private void handle(GhidraContext ctx) {
        BatchRequestDto dto = ctx.bodyAsClass(BatchRequestDto.class);
        if (dto == null || dto.requests == null) {
            ctx.status(400).json(Response.error(ctx.ctx(), ctx.port(),
                "BAD_REQUEST", "Body must contain a 'requests' array").build());
            return;
        }
        List<Map<String, Object>> results = batchService.execute(ctx, registry, dto);
        ctx.json(Response.ok(ctx.ctx(), ctx.port(), results).self("/batch").build());
    }
```
Replace with:
```java
    private void handle(GhidraContext ctx) {
        BatchRequestDto dto = ctx.bodyAsClass(BatchRequestDto.class);
        if (dto == null || dto.requests == null || dto.requests.isEmpty()) {
            ctx.status(400).json(Response.error(ctx.ctx(), ctx.port(),
                "BAD_REQUEST", "Body must contain a non-empty 'requests' array").build());
            return;
        }
        try {
            List<Map<String, Object>> results = batchService.execute(ctx, registry, dto);
            ctx.json(Response.ok(ctx.ctx(), ctx.port(), results).self("/batch").build());
        } catch (Exception e) {
            // execute() can surface NoProgramException (atomic batch, no program loaded) or
            // a genuine transaction failure. Route them through the same ErrorMapper the
            // Javalin exception handlers use so the batch endpoint returns the right
            // status/code (e.g. 503 NO_PROGRAM_LOADED) instead of a bare 500.
            ErrorMapper.Mapped m = ErrorMapper.map(e);
            ctx.status(m.status()).json(Response.error(ctx.ctx(), ctx.port(),
                m.code(), m.message()).build());
        }
    }
```

- [ ] **Step 3: Add the empty-requests integration test**

In `test_batch.py`, inside `class BatchTests`, add this method after `test_best_effort_mixed_batch`:

```python
    def test_empty_requests_is_rejected(self):
        r = requests.post(f"{BASE}/batch", json={"requests": []}, timeout=30)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json()["error"]["code"], "BAD_REQUEST")
```

- [ ] **Step 4: Compile and run the Java suite**

Run: `mvn test`
Expected: BUILD SUCCESS (no unit test exercises `BatchResource` directly; this step confirms the change compiles and nothing regresses).

- [ ] **Step 5: Run the integration test if a Ghidra instance is available**

Run: `python test_batch.py`
Expected: with a loaded program, `test_empty_requests_is_rejected` PASSES; without Ghidra, the whole suite auto-skips (`OK (skipped=...)`). If it skips, note that the endpoint change is verified by reasoning + the `ErrorMapper` unit tests in Task 3.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/resource/BatchResource.java test_batch.py
git commit -m "fix: map /batch execute() failures via ErrorMapper; reject empty batches

NoProgramException and transaction failures escaping BatchService.execute()
hit Javalin's global handler as 500 INTERNAL_ERROR instead of, e.g., 503
NO_PROGRAM_LOADED. Wrap the call and map through ErrorMapper, matching
single-call behavior. An empty requests array is now a 400, not a silent
200 no-op.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Complete `ErrorMapperTest` coverage

**Why:** Important finding — `ErrorMapper.map()` has 7 branches; only 3 are tested. The `NotFoundException`/`BadRequestException` branches carry a **caller-supplied** `errorCode` (`nf.errorCode()` / `br.errorCode()`); a regression dropping it to the default code would be invisible. Add the 4 missing branches. These cover already-correct code, so they pass on first run and act as regression guards.

**Files:**
- Modify: `src/test/java/eu/starsong/ghidra/middleware/ErrorMapperTest.java`

**Interfaces:**
- Consumes: `ProjectService.NoProjectException(String)`; `GhydraServer.NotFoundException(String message, String errorCode)`; `GhydraServer.BadRequestException(String message, String errorCode)`; `com.google.gson.JsonSyntaxException(String)`.

- [ ] **Step 1: Add imports**

Find:
```java
import eu.starsong.ghidra.server.GhidraContext;
import org.junit.Test;
```
Replace with:
```java
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.GhydraServer;
import eu.starsong.ghidra.service.ProjectService;
import com.google.gson.JsonSyntaxException;
import org.junit.Test;
```

- [ ] **Step 2: Add the four branch tests**

Find:
```java
    @Test
    public void mapsUnknownTo500() {
        ErrorMapper.Mapped m = ErrorMapper.map(new RuntimeException("boom"));
        assertEquals(500, m.status());
        assertEquals("INTERNAL_ERROR", m.code());
    }
}
```
Replace with:
```java
    @Test
    public void mapsUnknownTo500() {
        ErrorMapper.Mapped m = ErrorMapper.map(new RuntimeException("boom"));
        assertEquals(500, m.status());
        assertEquals("INTERNAL_ERROR", m.code());
    }

    @Test
    public void mapsNoProjectTo503() {
        ErrorMapper.Mapped m = ErrorMapper.map(new ProjectService.NoProjectException("none"));
        assertEquals(503, m.status());
        assertEquals("NO_PROJECT_OPEN", m.code());
    }

    @Test
    public void mapsNotFoundWithCustomCode() {
        ErrorMapper.Mapped m = ErrorMapper.map(
            new GhydraServer.NotFoundException("no fn", "FUNCTION_NOT_FOUND"));
        assertEquals(404, m.status());
        assertEquals("FUNCTION_NOT_FOUND", m.code());
    }

    @Test
    public void mapsBadRequestWithCustomCode() {
        ErrorMapper.Mapped m = ErrorMapper.map(
            new GhydraServer.BadRequestException("bad addr", "INVALID_ADDRESS"));
        assertEquals(400, m.status());
        assertEquals("INVALID_ADDRESS", m.code());
    }

    @Test
    public void mapsJsonSyntaxTo400() {
        ErrorMapper.Mapped m = ErrorMapper.map(new JsonSyntaxException("bad json"));
        assertEquals(400, m.status());
        assertEquals("INVALID_JSON", m.code());
    }
}
```

- [ ] **Step 3: Run the test**

Run: `mvn test -Dtest=ErrorMapperTest`
Expected: PASS (8 tests). These pin existing branches; they should be green immediately.

- [ ] **Step 4: Commit**

```bash
git add src/test/java/eu/starsong/ghidra/middleware/ErrorMapperTest.java
git commit -m "test: cover all ErrorMapper branches (NoProject, NotFound, BadRequest, JsonSyntax)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Harden `RouteRegistry.Match` immutability + document ordering + tests

**Why:** Suggestion — `Match.pathParams()` / `queryParams()` currently return the live `LinkedHashMap`s the registry built; `SyntheticGhidraContext` stores them directly, so a handler could mutate match state. Defensive-copy them. Also pin the registry's **first-match-wins** contract with tests, because real same-depth literal/param overlaps exist (`/memory/search` vs `/memory/{address}`, `/symbols/imports` vs `/symbols/{address}`) and only resolve correctly because the literal is registered first.

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/server/RouteRegistry.java`
- Modify: `src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java`

**Interfaces:**
- Consumes: `RouteRegistry.add(String, String, Consumer<GhidraContext>)`, `RouteRegistry.match(String, String) : Match`, `Match.handler()`, `Match.pathParams()`, `Match.queryParams()`.
- Produces: `Match.pathParams()` / `Match.queryParams()` now return **immutable** maps (`Map.copyOf`).

- [ ] **Step 1: Write the failing immutability test + the new coverage tests**

In `src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java`, find:
```java
    @Test
    public void matchIsCaseInsensitiveOnMethod() {
        RouteRegistry r = registryWith("POST", "/data");
        assertNotNull(r.match("post", "/data"));
    }
}
```
Replace with:
```java
    @Test
    public void matchIsCaseInsensitiveOnMethod() {
        RouteRegistry r = registryWith("POST", "/data");
        assertNotNull(r.match("post", "/data"));
    }

    @Test
    public void matchesDeleteRoute() {
        RouteRegistry r = registryWith("DELETE", "/data/{address}");
        RouteRegistry.Match m = r.match("DELETE", "/data/0x401000");
        assertNotNull(m);
        assertEquals("0x401000", m.pathParams().get("address"));
    }

    @Test
    public void matchesPutRoute() {
        RouteRegistry r = registryWith("PUT", "/data/{address}");
        assertNotNull(r.match("PUT", "/data/0x401000"));
    }

    @Test
    public void firstRegisteredRouteWinsForSameDepthOverlap() {
        // Mirrors SymbolResource: the literal route is registered before the param route,
        // so both Javalin and this registry resolve /symbols/imports to the literal handler.
        Consumer<GhidraContext> literal = c -> {};
        Consumer<GhidraContext> param = c -> {};
        RouteRegistry r = new RouteRegistry();
        r.add("GET", "/symbols/imports", literal);
        r.add("GET", "/symbols/{address}", param);
        assertSame(literal, r.match("GET", "/symbols/imports").handler());
        assertTrue(r.match("GET", "/symbols/imports").pathParams().isEmpty());
        assertSame(param, r.match("GET", "/symbols/0x401000").handler());
        assertEquals("0x401000", r.match("GET", "/symbols/0x401000").pathParams().get("address"));
    }

    @Test
    public void matchParamsAreImmutable() {
        RouteRegistry r = registryWith("PATCH", "/functions/{address}");
        RouteRegistry.Match m = r.match("PATCH", "/functions/0x401000");
        assertThrows(UnsupportedOperationException.class, () -> m.pathParams().put("x", "y"));
    }
}
```

(`RouteRegistryTest` already imports `java.util.function.Consumer` and `static org.junit.Assert.*`; `GhidraContext` is in the same package — no new imports needed.)

- [ ] **Step 2: Run to verify the immutability test fails**

Run: `mvn test -Dtest=RouteRegistryTest`
Expected: `matchParamsAreImmutable` FAILS (the live `LinkedHashMap` accepts `put`, so no exception is thrown). The DELETE/PUT/first-match tests pass already.

- [ ] **Step 3: Defensive-copy the `Match` maps + document ordering**

In `RouteRegistry.java`, find:
```java
    public record Match(Consumer<GhidraContext> handler,
                        Map<String, String> pathParams,
                        Map<String, String> queryParams) {}
```
Replace with:
```java
    public record Match(Consumer<GhidraContext> handler,
                        Map<String, String> pathParams,
                        Map<String, String> queryParams) {
        public Match {
            // Defensive copies: a Match is handed to SyntheticGhidraContext, which must
            // not be able to mutate the maps the registry built for this dispatch.
            pathParams = Map.copyOf(pathParams);
            queryParams = Map.copyOf(queryParams);
        }
    }
```

Then find:
```java
        for (Route route : routes) {
            if (!route.method().equals(m)) continue;
```
Replace with:
```java
        // First registered route that matches wins (mirrors Javalin's own
        // registration-order matching). Where a literal and a param route share the same
        // depth (e.g. /symbols/imports vs /symbols/{address}), the literal MUST be
        // registered first by its resource so both Javalin and this registry resolve it
        // the same way.
        for (Route route : routes) {
            if (!route.method().equals(m)) continue;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `mvn test -Dtest=RouteRegistryTest`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/server/RouteRegistry.java \
        src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java
git commit -m "fix: make RouteRegistry.Match maps immutable; pin first-match-wins ordering

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Structured errors in the Python bridge batch tools

**Why:** Important findings — the named wrappers build sub-requests with direct dict-key access (`r['old']`, `it['address']`, …); malformed caller input raises a raw `KeyError` that escapes the `@text_output` decorator as a Python exception instead of the bridge's structured error envelope. Separately, `_get_instance_port()` raises `ValueError` when no instance is reachable, which also escapes uncaught. Add two helpers and route every batch tool through them.

**Files:**
- Modify: `bridge_mcp_hydra.py`
- Test: `tests/test_bridge_batch.py`

**Interfaces:**
- Consumes: `_get_instance_port(port) : int` (raises `ValueError`); `safe_post(port, "batch", payload) : dict`; `simplify_response(dict) : dict`; `quote(str) : str`; `time.time()`.
- Produces: `_port_or_error(port|None) -> tuple[int|None, dict|None]`; `_safe_build(build: Callable[[], list]) -> tuple[list|None, dict|None]`. Each returns `(value, None)` on success or `(None, error_dict)` where `error_dict` is the standard `{"success": False, "error": {"code", "message"}, "timestamp"}` envelope.

- [ ] **Step 1: Write the failing tests**

In `tests/test_bridge_batch.py`, append:

```python
def test_rename_batch_missing_key_returns_error():
    # missing "old" -> structured error string, not a raw KeyError
    out = b.functions_rename_batch([{"new": "parse"}])
    assert isinstance(out, str)
    assert "old" in out


def test_batch_wrapper_handles_no_instance(monkeypatch):
    def boom(p=None):
        raise ValueError("No active Ghidra instance on port 8192")
    monkeypatch.setattr(b, "_get_instance_port", boom)
    out = b.functions_rename_batch([{"old": "a", "new": "b"}])
    assert isinstance(out, str)
    assert "instance" in out.lower()


def test_rename_batch_threads_atomic_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post",
                        lambda port, ep, payload: captured.update(payload) or {"success": True, "result": []})
    b.functions_rename_batch([{"old": "a", "new": "b"}], atomic=True)
    assert captured["atomic"] is True
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `pytest tests/test_bridge_batch.py -k "missing_key or no_instance or atomic_flag" -v`
Expected: `test_rename_batch_missing_key_returns_error` FAILS with a raw `KeyError: 'old'`; `test_batch_wrapper_handles_no_instance` FAILS with the uncaught `ValueError`. (`atomic_flag` already passes.)

- [ ] **Step 3: Add the two helpers above `batch_execute`**

Find:
```python
@mcp.tool()
@text_output
def batch_execute(requests: list[dict], atomic: bool = False, port: int | None = None) -> dict:
```
Insert immediately **before** it:
```python
def _port_or_error(port: int | None) -> tuple[int | None, dict | None]:
    """Resolve the target instance port. Returns (port, None) on success or
    (None, error_dict) when no live instance is available, so batch tools surface a
    structured error instead of letting _get_instance_port's ValueError escape raw."""
    try:
        return _get_instance_port(port), None
    except ValueError as e:
        return None, {
            "success": False,
            "error": {"code": "NO_INSTANCE", "message": str(e)},
            "timestamp": int(time.time() * 1000),
        }


def _safe_build(build) -> tuple[list | None, dict | None]:
    """Run a sub-request builder, converting malformed-input errors (a list item missing a
    required key, or not a dict) into a structured MISSING_PARAMETER error instead of a raw
    KeyError/TypeError. Returns (requests, None) or (None, error_dict)."""
    try:
        return build(), None
    except (KeyError, TypeError) as e:
        return None, {
            "success": False,
            "error": {"code": "MISSING_PARAMETER",
                      "message": f"Malformed batch item (missing or invalid key {e})"},
            "timestamp": int(time.time() * 1000),
        }


```

- [ ] **Step 4: Route `batch_execute` and `_run_batch` through `_port_or_error`**

In `batch_execute`, find:
```python
    port = _get_instance_port(port)
    payload = {"atomic": atomic, "requests": requests}
    response = safe_post(port, "batch", payload)
    return simplify_response(response)
```
Replace with:
```python
    port, err = _port_or_error(port)
    if err:
        return err
    payload = {"atomic": atomic, "requests": requests}
    response = safe_post(port, "batch", payload)
    return simplify_response(response)
```

In `_run_batch`, find:
```python
    port = _get_instance_port(port)
    response = safe_post(port, "batch", {"atomic": atomic, "requests": requests})
    return simplify_response(response)
```
Replace with:
```python
    port, err = _port_or_error(port)
    if err:
        return err
    response = safe_post(port, "batch", {"atomic": atomic, "requests": requests})
    return simplify_response(response)
```

- [ ] **Step 5: Wrap every wrapper's request-builder with `_safe_build`**

Apply each replacement below.

`functions_decompile_batch` — find:
```python
    reqs = [{"method": "GET", "path": f"/functions/by-name/{quote(n)}/decompile"} for n in names]
    return _run_batch(reqs, False, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [
        {"method": "GET", "path": f"/functions/by-name/{quote(n)}/decompile"} for n in names])
    if err:
        return err
    return _run_batch(reqs, False, port)
```

`functions_rename_batch` — find:
```python
    reqs = [{"method": "PATCH", "path": f"/functions/by-name/{quote(r['old'])}", "body": {"name": r["new"]}}
            for r in renames]
    return _run_batch(reqs, atomic, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [
        {"method": "PATCH", "path": f"/functions/by-name/{quote(r['old'])}", "body": {"name": r["new"]}}
        for r in renames])
    if err:
        return err
    return _run_batch(reqs, atomic, port)
```

`data_create_batch` — find:
```python
    reqs = [{"method": "POST", "path": "/data", "body": it} for it in items]
    return _run_batch(reqs, atomic, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [{"method": "POST", "path": "/data", "body": it} for it in items])
    if err:
        return err
    return _run_batch(reqs, atomic, port)
```

`data_set_type_batch` — find:
```python
    reqs = [{"method": "PATCH", "path": f"/data/{quote(it['address'])}", "body": {"type": it["type"]}}
            for it in items]
    return _run_batch(reqs, atomic, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [
        {"method": "PATCH", "path": f"/data/{quote(it['address'])}", "body": {"type": it["type"]}}
        for it in items])
    if err:
        return err
    return _run_batch(reqs, atomic, port)
```

`data_rename_batch` — find:
```python
    reqs = [{"method": "PATCH", "path": f"/data/{quote(it['address'])}", "body": {"name": it["name"]}}
            for it in items]
    return _run_batch(reqs, atomic, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [
        {"method": "PATCH", "path": f"/data/{quote(it['address'])}", "body": {"name": it["name"]}}
        for it in items])
    if err:
        return err
    return _run_batch(reqs, atomic, port)
```

`structs_add_field_batch` — find:
```python
    reqs = [{"method": "POST", "path": f"/structs/{quote(it['struct'])}/fields", "body": it.get("field", {})}
            for it in items]
    return _run_batch(reqs, atomic, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [
        {"method": "POST", "path": f"/structs/{quote(it['struct'])}/fields", "body": it.get("field", {})}
        for it in items])
    if err:
        return err
    return _run_batch(reqs, atomic, port)
```

`structs_update_field_batch` — find:
```python
    reqs = [{"method": "PATCH", "path": f"/structs/{quote(it['struct'])}/fields/{quote(str(it['field_ref']))}",
             "body": it.get("updates", {})} for it in items]
    return _run_batch(reqs, atomic, port)
```
Replace with:
```python
    reqs, err = _safe_build(lambda: [
        {"method": "PATCH", "path": f"/structs/{quote(it['struct'])}/fields/{quote(str(it['field_ref']))}",
         "body": it.get("updates", {})} for it in items])
    if err:
        return err
    return _run_batch(reqs, atomic, port)
```

- [ ] **Step 6: Run the bridge unit tests**

Run: `pytest tests/test_bridge_batch.py -v`
Expected: PASS — the 3 new tests plus all pre-existing ones (the existing `test_functions_rename_batch_builds_patch_requests` and `test_functions_decompile_batch_builds_get_requests` still pass because `_safe_build` returns the same list on valid input).

- [ ] **Step 7: Run the full Python unit suite**

Run: `pytest`
Expected: PASS (previous count `+3`).

- [ ] **Step 8: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_batch.py
git commit -m "fix: batch bridge tools return structured errors on bad input / no instance

Named wrappers used direct dict-key access, so a malformed item raised a raw
KeyError past @text_output; _get_instance_port's ValueError likewise escaped.
Add _safe_build and _port_or_error so both produce the standard error envelope.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Strengthen integration tests + document rollback semantics

**Why:** Suggestions — the atomic-rollback integration assertion is too weak (`assertFalse(a and b)` passes if *either* sub-request failed, so it would not catch a regression where the first rename never ran). Add a tighter assertion and a 3-request case that actually exercises the `ROLLED_BACK` (409) entry (only reachable with a live transaction, so it belongs in integration). Document that pre-failure sub-requests in a rolled-back atomic batch still report `success: true`.

**Files:**
- Modify: `test_batch.py`
- Modify: `GHIDRA_HTTP_API.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Strengthen the existing atomic assertion**

In `test_batch.py`, inside `test_atomic_rollback_reverts_first_success`, find:
```python
        r = requests.post(f"{BASE}/batch", json=body, timeout=60).json()
        self.assertFalse(r["result"][0]["success"] and r["result"][1]["success"])
        # Verify the first rename was rolled back:
```
Replace with:
```python
        r = requests.post(f"{BASE}/batch", json=body, timeout=60).json()
        # First rename was applied, the second failed -> the whole batch rolled back.
        self.assertTrue(r["result"][0]["success"])
        self.assertFalse(r["result"][1]["success"])
        self.assertGreaterEqual(r["result"][1]["status"], 400)
        # Verify the first rename was rolled back:
```

- [ ] **Step 2: Add a `ROLLED_BACK` (409) case**

In `test_batch.py`, add this method after `test_atomic_rollback_reverts_first_success`:

```python
    def test_atomic_marks_later_requests_rolled_back(self):
        # 3-request atomic batch: idx0 succeeds, idx1 fails, idx2 must report ROLLED_BACK.
        fns = requests.get(f"{BASE}/functions?limit=1", timeout=30).json()["result"]
        if not fns:
            self.skipTest("no functions in program")
        addr = fns[0]["address"]
        original = fns[0]["name"]
        body = {"atomic": True, "requests": [
            {"method": "PATCH", "path": f"/functions/{addr}", "body": {"name": "batch_probe_rb"}},
            {"method": "PATCH", "path": "/functions/0xdeadbeef", "body": {"name": "y"}},  # fails
            {"method": "GET",   "path": "/functions"},                                    # never runs
        ]}
        results = requests.post(f"{BASE}/batch", json=body, timeout=60).json()["result"]
        self.assertTrue(results[0]["success"])
        self.assertFalse(results[1]["success"])
        self.assertEqual(results[2]["status"], 409)
        self.assertEqual(results[2]["body"]["error"]["code"], "ROLLED_BACK")
        # The applied rename must have been reverted.
        after = requests.get(f"{BASE}/functions/{addr}", timeout=30).json()["result"]
        self.assertEqual(after["name"], original)
```

- [ ] **Step 3: Run the integration tests if Ghidra is available**

Run: `python test_batch.py`
Expected: with a loaded program, all `BatchTests` pass; otherwise the suite auto-skips. Record which (passed vs skipped) — do not claim a live pass if it skipped.

- [ ] **Step 4: Document the per-item `success` semantics**

In `GHIDRA_HTTP_API.md`, find:
```
  **Atomic mode (`atomic: true`):** the whole batch runs inside a single Ghidra transaction.
  On the first sub-request whose `success` is `false`, the transaction is rolled back (reverting
  every mutation made earlier in the batch) and all remaining sub-requests are reported as
  `ROLLED_BACK`. Requires a program to be loaded.
```
Replace with:
```
  **Atomic mode (`atomic: true`):** the whole batch runs inside a single Ghidra transaction.
  On the first sub-request whose `success` is `false`, the transaction is rolled back (reverting
  every mutation made earlier in the batch) and all remaining sub-requests are reported as
  `ROLLED_BACK`. Requires a program to be loaded.

  > **Per-item `success` after a rollback:** sub-requests that ran *before* the failing one keep
  > their original `status`/`success: true` in the result array **even though the rollback
  > reverted their mutations**. Only sub-requests *after* the failure carry `ROLLED_BACK`. Treat
  > an atomic batch as all-or-nothing based on the failing item — do not read a pre-failure
  > sub-request's `success: true` as "this change persisted".
```

- [ ] **Step 5: Record the hardening in the changelog**

In `CHANGELOG.md`, find (the trailing sentence of the batch "Added" bullet under `## [Unreleased]`):
```
  `structs_update_field_batch`). Plugin → `v3.3.0`, bridge → `v3.4.0` (API_VERSION unchanged — additive).
```
Replace with:
```
  `structs_update_field_batch`). Plugin → `v3.3.0`, bridge → `v3.4.0` (API_VERSION unchanged — additive).
  Hardening: batch dispatch is total (a malformed sub-request path or body is isolated as a
  per-item 4xx rather than aborting the batch or leaking a 500 from an atomic rollback); the
  `/batch` endpoint maps `execute()` failures through `ErrorMapper` (e.g. `503 NO_PROGRAM_LOADED`
  for an atomic batch with no program); an empty `requests` array is rejected with `400`; and the
  named MCP wrappers return a structured `MISSING_PARAMETER`/`NO_INSTANCE` error instead of raising
  on malformed input or an unreachable instance.
```

- [ ] **Step 6: Commit**

```bash
git add test_batch.py GHIDRA_HTTP_API.md CHANGELOG.md
git commit -m "test: strengthen atomic-batch integration coverage; docs: rollback semantics

Tighten the rollback assertion, add a ROLLED_BACK (409) case, document that
pre-failure sub-requests still report success after a rollback, and record the
batch hardening in the changelog.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Considered and Rejected / Deferred

- **Make `SyntheticGhidraContext.ctx()` throw `UnsupportedOperationException`** (type-design suggestion). **Rejected — it would break batch dispatch.** Batch-dispatched handlers build responses via `Response.ok(ctx.ctx(), ctx.port(), …)`, whose `addMeta()` calls `ctx.header("X-Request-ID")`. In batch dispatch `ctx.ctx()` is the no-op proxy that returns `null` (→ a generated UUID), which is exactly why it must keep returning the proxy. Throwing would make every mutating handler fail under `/batch`. The existing `SyntheticGhidraContextTest.rawContextHeaderReturnsNull` encodes this contract. Leave it.
- **Introduce an `HttpMethod` enum** to replace raw method strings across `BatchRequestDto`, `RouteRegistry`, `Routes`, `BatchService`. **Deferred** — broad, cross-cutting refactor the reviewers rated low-confidence; no correctness defect today (unknown methods already fall through to `NO_ROUTE`). Not worth the churn in a fix PR.
- **`RouteRegistry.match()` → `Optional<Match>`** and **null-guards in `add()`**. **Deferred** — stylistic; all current callers null-check correctly. Revisit if the registry grows more consumers.
- **Tighten `Routes.app()/registry()/contextFactory()` visibility.** **Deferred** — no current code bypasses `Routes`; package-private tightening is a separate cleanup.
- **Unit-test the atomic rollback / `ROLLED_BACK` path in Java.** **Not feasible without Ghidra** — it is bound to `TransactionHelper` → `Swing.runNow` → `program.startTransaction`. Covered at the integration level in Task 6 instead; the recoverable parts (dispatch totality, guards, error mapping) are unit-tested in Task 1.

---

## Self-Review

- **Spec coverage (review findings → tasks):**
  - Critical #1 (`IllegalArgumentException` escapes atomic rollback) → Task 1 (root-cause: total `dispatch()`) + regression test `bestEffortIsolatesFailureAndRunsRest`.
  - Important: BatchResource no catch → Task 2; KeyError in wrappers → Task 5; missing 5xx dispatch logging → Task 1; `_get_instance_port` ValueError → Task 5; no `BatchService` unit tests → Task 1; `ErrorMapperTest` incomplete → Task 3; empty-batch 200 → Task 2.
  - Issues #3/#9 (execute logging + wrong comment) → Task 1.
  - Suggestions: mutable `Match` maps → Task 4; RouteRegistry DELETE/PUT + first-match → Task 4; weak atomic assertion → Task 6; Python atomic-flag test → Task 5; rollback doc note → Task 6.
  - `SyntheticGhidraContext.ctx()` suggestion → explicitly rejected with reason.
- **Placeholder scan:** none — every code step shows complete before/after text and an exact command with expected output.
- **Type/name consistency:** `_port_or_error`/`_safe_build` signatures and the `(value, err)` tuple usage match across Steps 3–5; `Match` immutability change matches the `matchParamsAreImmutable` assertion; `error_dict` shape matches the bridge's existing envelope; Java result-map keys (`index/status/success/body`) unchanged.

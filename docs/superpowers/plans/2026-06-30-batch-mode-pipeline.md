# Batch Mode Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a single `POST /batch` endpoint that dispatches an array of virtual HTTP sub-requests to existing controllers in-process within one optional transaction, plus a generic `batch_execute` MCP tool and named convenience wrappers.

**Architecture:** Resources register routes through a thin `Routes` wrapper that records every `(method, pattern) → Consumer<GhidraContext>` into a `RouteRegistry`. `BatchService` matches each sub-request against the registry, builds a `SyntheticGhidraContext` (serves request data from the sub-request, captures the handler's `json()` output instead of writing HTTP), and invokes the existing handler. Best-effort by default (no outer transaction, each handler commits independently); `atomic:true` wraps the whole loop in one Ghidra transaction and rolls everything back on the first failure.

**Tech Stack:** Java 21, Javalin/Jetty, Gson, JUnit 4 (`org.junit`); Python 3.11+, FastMCP bridge, pytest.

## Global Constraints

- Java 21; Ghidra 11.x/12.x. Building/`mvn test` needs `GHIDRA_HOME` set (or jars in `lib/`) and `-Dghidra.version=<installed>`.
- Java tests are JUnit 4: `import org.junit.Test;` + `import static org.junit.Assert.*;`.
- Python unit tests live in `tests/` and run with bare `pytest` (offline, no Ghidra). Integration tests are root-level `test_*.py`, run via `python run_tests.py`, and auto-skip without a live Ghidra.
- Bump `PLUGIN_VERSION` (`src/main/java/eu/starsong/ghidra/api/ApiConstants.java`) and `BRIDGE_VERSION` (`bridge_mcp_hydra.py`). **Do NOT** change `API_VERSION` / `REQUIRED_API_VERSION` — this feature is backward-compatible.
- Conventional-commit messages; end every commit message with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Work on branch `feature/batch-mode-pipeline` (already checked out).
- `docs/COMPETITIVE_GAPS.md` is **not committed** to the repo — edit it (Task 9) but never `git add` it.
- Every response envelope is `{id, instance, success, result, timestamp, _links}`; the bridge's `simplify_response()` strips `id/instance/timestamp`.

## File Structure

**Java — create:**
- `src/main/java/eu/starsong/ghidra/server/RouteRegistry.java` — route table + `(method, path)` matcher.
- `src/main/java/eu/starsong/ghidra/server/Routes.java` — registration wrapper (Javalin + registry).
- `src/main/java/eu/starsong/ghidra/server/SyntheticGhidraContext.java` — in-process request/response context for a sub-request.
- `src/main/java/eu/starsong/ghidra/middleware/ErrorMapper.java` — shared `Exception → (status, code, message)` mapping.
- `src/main/java/eu/starsong/ghidra/dto/BatchRequestDto.java` — parsed `/batch` body.
- `src/main/java/eu/starsong/ghidra/service/BatchService.java` — orchestration (dispatch loop, transactions).
- `src/main/java/eu/starsong/ghidra/resource/BatchResource.java` — registers `POST /batch`.
- `src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java`
- `src/test/java/eu/starsong/ghidra/server/SyntheticGhidraContextTest.java`
- `src/test/java/eu/starsong/ghidra/middleware/ErrorMapperTest.java`

**Java — modify:**
- `server/Resource.java` — interface signature → `register(Routes)`.
- `server/GhydraServer.java` — build registry + `Routes`, rewire exception handlers to `ErrorMapper`, auto-register `BatchResource`.
- All 17 `resource/*.java` — mechanical migration to `Routes`.

**Python — modify:**
- `bridge_mcp_hydra.py` — `batch_execute` + 7 named wrappers + `format_batch_results` + register formatter + `BRIDGE_VERSION` bump.
- `tests/test_bridge_batch.py` (create) — offline tests.
- `test_batch.py` (create, repo root) — integration tests.

**Docs:** `CHANGELOG.md`, `GHIDRA_HTTP_API.md`, `README.md`, `docs/COMPETITIVE_GAPS.md` (not committed).

---

## Task 1: RouteRegistry (pure Java path matcher)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/server/RouteRegistry.java`
- Test: `src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java`

**Interfaces:**
- Produces:
  - `RouteRegistry` with `void add(String method, String pattern, Consumer<GhidraContext> handler)` and `Match match(String method, String rawPath)` (returns `null` if no route).
  - `RouteRegistry.Match` record: `Consumer<GhidraContext> handler()`, `Map<String,String> pathParams()`, `Map<String,String> queryParams()`.

- [ ] **Step 1: Write the failing test**

```java
package eu.starsong.ghidra.server;

import org.junit.Test;
import java.util.function.Consumer;
import static org.junit.Assert.*;

public class RouteRegistryTest {

    private RouteRegistry registryWith(String method, String pattern) {
        RouteRegistry r = new RouteRegistry();
        r.add(method, pattern, c -> {});
        return r;
    }

    @Test
    public void matchesLiteralRoute() {
        RouteRegistry r = registryWith("POST", "/data");
        RouteRegistry.Match m = r.match("POST", "/data");
        assertNotNull(m);
        assertTrue(m.pathParams().isEmpty());
    }

    @Test
    public void capturesSinglePathParam() {
        RouteRegistry r = registryWith("PATCH", "/functions/{address}");
        RouteRegistry.Match m = r.match("PATCH", "/functions/0x401000");
        assertNotNull(m);
        assertEquals("0x401000", m.pathParams().get("address"));
    }

    @Test
    public void urlDecodesCapturedParam() {
        RouteRegistry r = registryWith("GET", "/functions/by-name/{name}/decompile");
        RouteRegistry.Match m = r.match("GET", "/functions/by-name/FOM%3A%3ARead/decompile");
        assertNotNull(m);
        assertEquals("FOM::Read", m.pathParams().get("name"));
    }

    @Test
    public void parsesQueryString() {
        RouteRegistry r = registryWith("GET", "/functions/by-name/{name}/decompile");
        RouteRegistry.Match m = r.match("GET", "/functions/by-name/main/decompile?max_lines=20&style=normalize");
        assertNotNull(m);
        assertEquals("main", m.pathParams().get("name"));
        assertEquals("20", m.queryParams().get("max_lines"));
        assertEquals("normalize", m.queryParams().get("style"));
    }

    @Test
    public void returnsNullOnSegmentCountMismatch() {
        RouteRegistry r = registryWith("PATCH", "/functions/{address}");
        assertNull(r.match("PATCH", "/functions/0x401000/decompile"));
    }

    @Test
    public void returnsNullOnMethodMismatch() {
        RouteRegistry r = registryWith("PATCH", "/functions/{address}");
        assertNull(r.match("GET", "/functions/0x401000"));
    }

    @Test
    public void matchIsCaseInsensitiveOnMethod() {
        RouteRegistry r = registryWith("POST", "/data");
        assertNotNull(r.match("post", "/data"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test -Dtest=RouteRegistryTest`
Expected: FAIL — `RouteRegistry` does not exist (compilation error).

- [ ] **Step 3: Write minimal implementation**

```java
package eu.starsong.ghidra.server;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Records every registered route as (method, pattern, handler) and matches an
 * incoming (method, path) against them. Used by the /batch pipeline to dispatch
 * virtual sub-requests to the same handlers Javalin would invoke.
 */
public class RouteRegistry {

    public record Match(Consumer<GhidraContext> handler,
                        Map<String, String> pathParams,
                        Map<String, String> queryParams) {}

    private record Route(String method, String[] segments, Consumer<GhidraContext> handler) {}

    private final List<Route> routes = new ArrayList<>();

    public void add(String method, String pattern, Consumer<GhidraContext> handler) {
        routes.add(new Route(method.toUpperCase(), splitPath(pattern), handler));
    }

    public Match match(String method, String rawPath) {
        String m = method.toUpperCase();
        int q = rawPath.indexOf('?');
        String pathPart = q >= 0 ? rawPath.substring(0, q) : rawPath;
        String queryPart = q >= 0 ? rawPath.substring(q + 1) : "";
        String[] pathSegments = splitPath(pathPart);

        for (Route route : routes) {
            if (!route.method().equals(m)) continue;
            if (route.segments().length != pathSegments.length) continue;
            Map<String, String> params = new LinkedHashMap<>();
            if (segmentsMatch(route.segments(), pathSegments, params)) {
                return new Match(route.handler(), params, parseQuery(queryPart));
            }
        }
        return null;
    }

    private boolean segmentsMatch(String[] pattern, String[] actual, Map<String, String> out) {
        for (int i = 0; i < pattern.length; i++) {
            String p = pattern[i];
            if (p.length() > 1 && p.charAt(0) == '{' && p.charAt(p.length() - 1) == '}') {
                out.put(p.substring(1, p.length() - 1), decode(actual[i]));
            } else if (!p.equals(actual[i])) {
                return false;
            }
        }
        return true;
    }

    private static String[] splitPath(String path) {
        String trimmed = path.startsWith("/") ? path.substring(1) : path;
        if (trimmed.endsWith("/")) trimmed = trimmed.substring(0, trimmed.length() - 1);
        if (trimmed.isEmpty()) return new String[0];
        return trimmed.split("/");
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        if (query.isEmpty()) return out;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            if (eq < 0) {
                out.put(decode(pair), "");
            } else {
                out.put(decode(pair.substring(0, eq)), decode(pair.substring(eq + 1)));
            }
        }
        return out;
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test -Dtest=RouteRegistryTest`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/server/RouteRegistry.java \
        src/test/java/eu/starsong/ghidra/server/RouteRegistryTest.java
git commit -m "$(printf 'feat: add RouteRegistry for batch sub-request dispatch\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 2: Routes wrapper + Resource interface migration

This task changes the `Resource` interface and therefore must migrate **all** resources in one compiling unit. The migration is a single mechanical transform repeated per file.

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/server/Routes.java`
- Modify: `src/main/java/eu/starsong/ghidra/server/Resource.java`
- Modify: `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:165-177`
- Modify (mechanical, identical transform each): `resource/FunctionResource.java`, `resource/SymbolResource.java`, `resource/DataResource.java`, `resource/MemoryResource.java`, `resource/SegmentResource.java`, `resource/XrefResource.java`, `resource/ProgramResource.java`, `resource/InstanceResource.java`, `resource/AnalysisResource.java`, `resource/StructResource.java`, `resource/DataTypeResource.java`, `resource/ClassResource.java`, `resource/NamespaceResource.java`, `resource/ProjectResource.java`, `resource/UiResource.java`, `resource/ScriptResource.java`, `resource/EmulationResource.java`, `resource/VariableResource.java`

**Interfaces:**
- Consumes: `RouteRegistry` (Task 1).
- Produces:
  - `Routes` with `Javalin app()`, `Function<Context,GhidraContext> contextFactory()`, `RouteRegistry registry()`, and `get/post/patch/put/delete(String path, Consumer<GhidraContext> handler)`.
  - `Resource.register(Routes routes)` is the new interface method.

- [ ] **Step 1: Create `Routes.java`**

```java
package eu.starsong.ghidra.server;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Registration surface for resources. Each call registers the route with
 * Javalin AND records (method, pattern, handler) in the RouteRegistry so the
 * /batch pipeline can dispatch virtual sub-requests to the same handler.
 */
public class Routes {

    private final Javalin app;
    private final Function<Context, GhidraContext> contextFactory;
    private final RouteRegistry registry;

    public Routes(Javalin app, Function<Context, GhidraContext> contextFactory, RouteRegistry registry) {
        this.app = app;
        this.contextFactory = contextFactory;
        this.registry = registry;
    }

    public Javalin app() { return app; }
    public Function<Context, GhidraContext> contextFactory() { return contextFactory; }
    public RouteRegistry registry() { return registry; }

    public void get(String path, Consumer<GhidraContext> handler)    { wire("GET", path, handler); }
    public void post(String path, Consumer<GhidraContext> handler)   { wire("POST", path, handler); }
    public void patch(String path, Consumer<GhidraContext> handler)  { wire("PATCH", path, handler); }
    public void put(String path, Consumer<GhidraContext> handler)    { wire("PUT", path, handler); }
    public void delete(String path, Consumer<GhidraContext> handler) { wire("DELETE", path, handler); }

    private void wire(String method, String path, Consumer<GhidraContext> handler) {
        registry.add(method, path, handler);
        switch (method) {
            case "GET"    -> app.get(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "POST"   -> app.post(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "PATCH"  -> app.patch(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "PUT"    -> app.put(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "DELETE" -> app.delete(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        }
    }
}
```

- [ ] **Step 2: Change the `Resource` interface**

Replace the body of `src/main/java/eu/starsong/ghidra/server/Resource.java` with:

```java
package eu.starsong.ghidra.server;

/**
 * Interface for REST resources that register routes with the server.
 */
@FunctionalInterface
public interface Resource {

    /**
     * Register routes via the {@link Routes} wrapper, which both wires Javalin
     * and records the route in the {@link RouteRegistry} for batch dispatch.
     */
    void register(Routes routes);
}
```

- [ ] **Step 3: Rewire `GhydraServer.registerResources()` and `createContext`**

In `src/main/java/eu/starsong/ghidra/server/GhydraServer.java`, add a field and build the registry + Routes. Replace `registerResources()` (lines 165-169) with:

```java
    private final RouteRegistry routeRegistry = new RouteRegistry();

    public RouteRegistry routeRegistry() { return routeRegistry; }

    private void registerResources() {
        Routes routes = new Routes(app, this::createContext, routeRegistry);
        for (Resource resource : resources) {
            resource.register(routes);
        }
        // Auto-register the batch pipeline last so every other route is already
        // present in the registry (BatchResource only needs the registry instance).
        new eu.starsong.ghidra.resource.BatchResource(routeRegistry).register(routes);
    }
```

(Place the `routeRegistry` field next to the other fields near line 30; shown here for clarity. `BatchResource` is created in Task 6 — until then, comment out the `new BatchResource(...)` line so the module compiles, and uncomment it in Task 6.)

- [ ] **Step 4: Migrate every resource — the mechanical transform**

Apply this identical transform to each resource file listed under **Files**:

1. Change the method signature
   from `public void register(Javalin app, java.util.function.Function<Context, GhidraContext> contextFactory) {`
   to   `public void register(Routes routes) {`
2. For every route line, rewrite
   `app.VERB("/path", ctx -> handlerMethod(contextFactory.apply(ctx)));`
   to `routes.VERB("/path", this::handlerMethod);`
   (VERB ∈ get/post/patch/put/delete; `handlerMethod` already takes a single `GhidraContext` and returns void, so it is a `Consumer<GhidraContext>` method reference.)
3. Remove now-unused imports (`io.javalin.Javalin`, `java.util.function.Function`) if the file no longer references them. Keep `io.javalin.http.Context` only if still used elsewhere in the file.

**Worked example — `FunctionResource.java`** (current lines 42-61) becomes:

```java
    @Override
    public void register(Routes routes) {
        // By-address routes
        routes.get("/functions", this::list);
        routes.post("/functions", this::create);
        routes.get("/functions/{address}", this::getByAddress);
        routes.patch("/functions/{address}", this::update);
        routes.delete("/functions/{address}", this::delete);
        routes.get("/functions/{address}/decompile", this::decompile);
        routes.get("/functions/{address}/disassembly", this::disassembly);
        routes.get("/functions/{address}/variables", this::variables);
        routes.patch("/functions/{address}/variables/{varName}", this::updateVariable);

        // By-name routes
        routes.get("/functions/by-name/{name}", this::getByName);
        routes.patch("/functions/by-name/{name}", this::updateByName);
        routes.delete("/functions/by-name/{name}", this::deleteByName);
        routes.get("/functions/by-name/{name}/decompile", this::decompileByName);
        routes.get("/functions/by-name/{name}/disassembly", this::disassemblyByName);
        routes.get("/functions/by-name/{name}/variables", this::variablesByName);
    }
```

Add `import eu.starsong.ghidra.server.Routes;` where needed (same package is `server`; resources are in `resource`, so the import is required). Apply the identical transform to each remaining resource file. Do not change handler method bodies.

- [ ] **Step 5: Compile the whole module**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test-compile`
Expected: BUILD SUCCESS (no references to the old `register(Javalin, Function)` signature remain).

- [ ] **Step 6: Run the full Java test suite (regression)**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test`
Expected: PASS — existing tests unaffected; `RouteRegistryTest` green.

- [ ] **Step 7: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/server/Routes.java \
        src/main/java/eu/starsong/ghidra/server/Resource.java \
        src/main/java/eu/starsong/ghidra/server/GhydraServer.java \
        src/main/java/eu/starsong/ghidra/resource/
git commit -m "$(printf 'refactor: register routes via Routes wrapper feeding RouteRegistry\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 3: ErrorMapper (shared exception → status/code/message)

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/middleware/ErrorMapper.java`
- Modify: `src/main/java/eu/starsong/ghidra/server/GhydraServer.java:126-163` (exception handlers delegate to `ErrorMapper`)
- Test: `src/test/java/eu/starsong/ghidra/middleware/ErrorMapperTest.java`

**Interfaces:**
- Produces: `ErrorMapper.Mapped` record `(int status, String code, String message)` and `static Mapped map(Exception e)`.

- [ ] **Step 1: Write the failing test**

```java
package eu.starsong.ghidra.middleware;

import eu.starsong.ghidra.server.GhidraContext;
import org.junit.Test;
import static org.junit.Assert.*;

public class ErrorMapperTest {

    @Test
    public void mapsNoProgramTo503() {
        ErrorMapper.Mapped m = ErrorMapper.map(new GhidraContext.NoProgramException("none"));
        assertEquals(503, m.status());
        assertEquals("NO_PROGRAM_LOADED", m.code());
    }

    @Test
    public void mapsIllegalArgumentTo400() {
        ErrorMapper.Mapped m = ErrorMapper.map(new IllegalArgumentException("bad addr"));
        assertEquals(400, m.status());
        assertEquals("BAD_REQUEST", m.code());
        assertEquals("bad addr", m.message());
    }

    @Test
    public void mapsUnknownTo500() {
        ErrorMapper.Mapped m = ErrorMapper.map(new RuntimeException("boom"));
        assertEquals(500, m.status());
        assertEquals("INTERNAL_ERROR", m.code());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test -Dtest=ErrorMapperTest`
Expected: FAIL — `ErrorMapper` does not exist.

- [ ] **Step 3: Write `ErrorMapper.java`**

```java
package eu.starsong.ghidra.middleware;

import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.GhydraServer;
import eu.starsong.ghidra.service.ProjectService;
import com.google.gson.JsonSyntaxException;

/**
 * Single source of truth for mapping an exception to an HTTP status, error
 * code, and message. Used both by the Javalin exception handlers and by the
 * /batch pipeline (which bypasses middleware) so per-sub-request errors stay
 * consistent with single-call errors.
 */
public final class ErrorMapper {

    public record Mapped(int status, String code, String message) {}

    private ErrorMapper() {}

    public static Mapped map(Exception e) {
        String msg = e.getMessage();
        if (e instanceof GhidraContext.NoProgramException) {
            return new Mapped(503, "NO_PROGRAM_LOADED", msg);
        }
        if (e instanceof ProjectService.NoProjectException) {
            return new Mapped(503, "NO_PROJECT_OPEN", msg);
        }
        if (e instanceof GhydraServer.NotFoundException nf) {
            return new Mapped(404, nf.errorCode(), msg);
        }
        if (e instanceof GhydraServer.BadRequestException br) {
            return new Mapped(400, br.errorCode(), msg);
        }
        if (e instanceof IllegalArgumentException) {
            return new Mapped(400, "BAD_REQUEST", msg);
        }
        if (e instanceof JsonSyntaxException) {
            return new Mapped(400, "INVALID_JSON", "Malformed JSON body: " + msg);
        }
        return new Mapped(500, "INTERNAL_ERROR", "Internal server error: " + msg);
    }
}
```

> If `GhydraServer.BadRequestException` is package-private or nested differently, confirm its accessor name (`errorCode()`) against `GhydraServer.java:208+`; `NotFoundException.errorCode()` is used at `GhydraServer.java:141`.

- [ ] **Step 4: Rewire `GhydraServer.configureMiddleware()` exception handlers**

Replace the six `app.exception(...)` blocks (lines 129-162) so each delegates to `ErrorMapper` (keeps identical behavior, single mapping source):

```java
        app.exception(GhidraContext.NoProgramException.class, this::handleMapped);
        app.exception(eu.starsong.ghidra.service.ProjectService.NoProjectException.class, this::handleMapped);
        app.exception(NotFoundException.class, this::handleMapped);
        app.exception(BadRequestException.class, this::handleMapped);
        app.exception(IllegalArgumentException.class, this::handleMapped);
        app.exception(com.google.gson.JsonSyntaxException.class, this::handleMapped);
        app.exception(Exception.class, this::handleMapped);
```

And add the helper method to `GhydraServer`:

```java
    private void handleMapped(Exception e, io.javalin.http.Context ctx) {
        eu.starsong.ghidra.middleware.ErrorMapper.Mapped m =
            eu.starsong.ghidra.middleware.ErrorMapper.map(e);
        if (m.status() >= 500) {
            ghidra.util.Msg.error(this, "Unhandled exception in " + ctx.path(), e);
        }
        ctx.status(io.javalin.http.HttpStatus.forStatus(m.status()));
        ctx.json(eu.starsong.ghidra.hateoas.Response.error(ctx, port, m.code(), m.message()).build());
    }
```

The standalone `ErrorHandler` class may remain unused or be deleted; leave it for now to keep the diff focused.

- [ ] **Step 5: Run tests**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test -Dtest=ErrorMapperTest` then full `mvn -q -Dghidra.version=$GHIDRA_VERSION test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/middleware/ErrorMapper.java \
        src/test/java/eu/starsong/ghidra/middleware/ErrorMapperTest.java \
        src/main/java/eu/starsong/ghidra/server/GhydraServer.java
git commit -m "$(printf 'refactor: extract ErrorMapper for shared exception mapping\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 4: SyntheticGhidraContext + CapturedResponse

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/server/SyntheticGhidraContext.java`
- Test: `src/test/java/eu/starsong/ghidra/server/SyntheticGhidraContextTest.java`

**Interfaces:**
- Consumes: `GhidraContext` (superclass).
- Produces:
  - `SyntheticGhidraContext(PluginTool tool, int port, Map<Integer,?> activeInstances, String method, String path, Map<String,String> pathParams, Map<String,String> queryParams, String bodyJson)`.
  - `int capturedStatus()` (default 200), `Object capturedBody()` (the object passed to `json(...)`, or null if the handler never responded).

- [ ] **Step 1: Write the failing test**

```java
package eu.starsong.ghidra.server;

import com.google.gson.JsonObject;
import org.junit.Test;
import java.util.Map;
import static org.junit.Assert.*;

public class SyntheticGhidraContextTest {

    private SyntheticGhidraContext ctx(String body) {
        return new SyntheticGhidraContext(
            null, 8192, Map.of(), "PATCH", "/functions/0x401000",
            Map.of("address", "0x401000"),
            Map.of("max_lines", "20"),
            body);
    }

    @Test
    public void servesPathAndQueryParams() {
        SyntheticGhidraContext c = ctx("{}");
        assertEquals("0x401000", c.pathParam("address"));
        assertEquals("20", c.queryParam("max_lines"));
        assertEquals(20, c.queryParamAsInt("max_lines", -1));
        assertEquals("PATCH", c.method());
    }

    @Test
    public void parsesBody() {
        SyntheticGhidraContext c = ctx("{\"name\":\"parse_header\"}");
        JsonObject body = c.bodyAsClass(JsonObject.class);
        assertEquals("parse_header", body.get("name").getAsString());
    }

    @Test
    public void capturesJsonResponse() {
        SyntheticGhidraContext c = ctx("{}");
        Object payload = Map.of("success", true);
        c.json(payload);
        assertEquals(200, c.capturedStatus());
        assertSame(payload, c.capturedBody());
    }

    @Test
    public void capturesStatusOverride() {
        SyntheticGhidraContext c = ctx("{}");
        c.status(201);
        assertEquals(201, c.capturedStatus());
    }

    @Test
    public void rawContextHeaderReturnsNull() {
        SyntheticGhidraContext c = ctx("{}");
        assertNull(c.ctx().header("X-Request-ID"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test -Dtest=SyntheticGhidraContextTest`
Expected: FAIL — class does not exist.

- [ ] **Step 3: Write `SyntheticGhidraContext.java`**

```java
package eu.starsong.ghidra.server;

import com.google.gson.Gson;
import ghidra.framework.plugintool.PluginTool;
import io.javalin.http.Context;

import java.lang.reflect.Proxy;
import java.util.Map;

/**
 * A GhidraContext that serves request data from an in-process batch sub-request
 * and captures the handler's response instead of writing it to a real HTTP
 * response. The raw Javalin Context is a no-op proxy that only answers
 * header(...) (returns null), which is all Response.addMeta needs.
 */
public class SyntheticGhidraContext extends GhidraContext {

    private static final Gson GSON = new Gson();

    private final String method;
    private final String path;
    private final Map<String, String> pathParams;
    private final Map<String, String> queryParams;
    private final String bodyJson;

    private int capturedStatus = 200;
    private Object capturedBody;

    public SyntheticGhidraContext(PluginTool tool, int port, Map<Integer, ?> activeInstances,
                                  String method, String path,
                                  Map<String, String> pathParams,
                                  Map<String, String> queryParams,
                                  String bodyJson) {
        super(noopContext(), tool, port, activeInstances);
        this.method = method;
        this.path = path;
        this.pathParams = pathParams;
        this.queryParams = queryParams;
        this.bodyJson = bodyJson == null ? "{}" : bodyJson;
    }

    private static Context noopContext() {
        return (Context) Proxy.newProxyInstance(
            SyntheticGhidraContext.class.getClassLoader(),
            new Class<?>[]{Context.class},
            (proxy, m, args) -> {
                if ("header".equals(m.getName())) {
                    return null;
                }
                Class<?> rt = m.getReturnType();
                if (rt.equals(void.class)) return null;
                if (rt.equals(boolean.class)) return false;
                if (rt.equals(int.class)) return 0;
                return null;
            });
    }

    @Override public String pathParam(String name) { return pathParams.get(name); }
    @Override public String method() { return method; }
    @Override public String path() { return path; }

    @Override public String queryParam(String name) { return queryParams.get(name); }

    @Override public String queryParam(String name, String defaultValue) {
        String v = queryParams.get(name);
        return v != null ? v : defaultValue;
    }

    @Override public int queryParamAsInt(String name, int defaultValue) {
        String v = queryParams.get(name);
        if (v == null || v.isEmpty()) return defaultValue;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return defaultValue; }
    }

    @Override public <T> T bodyAsClass(Class<T> clazz) { return GSON.fromJson(bodyJson, clazz); }

    @Override public GhidraContext status(int code) { this.capturedStatus = code; return this; }

    @Override public void json(Object obj) { this.capturedBody = obj; }

    public int capturedStatus() { return capturedStatus; }
    public Object capturedBody() { return capturedBody; }
}
```

> `pagination()` in the superclass calls `this.queryParamAsInt(...)`, which is overridden here, so paginated handlers work without extra overrides.

- [ ] **Step 4: Run test to verify it passes**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test -Dtest=SyntheticGhidraContextTest`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/server/SyntheticGhidraContext.java \
        src/test/java/eu/starsong/ghidra/server/SyntheticGhidraContextTest.java
git commit -m "$(printf 'feat: add SyntheticGhidraContext for in-process batch dispatch\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 5: BatchRequestDto + BatchService

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/dto/BatchRequestDto.java`
- Create: `src/main/java/eu/starsong/ghidra/service/BatchService.java`

**Interfaces:**
- Consumes: `RouteRegistry`, `SyntheticGhidraContext`, `ErrorMapper`, `TransactionHelper`, `GhidraContext`.
- Produces:
  - `BatchRequestDto` fields: `boolean atomic`, `List<SubRequest> requests`; nested `SubRequest { String method; String path; Object body; }`.
  - `BatchService.execute(GhidraContext ctx, RouteRegistry registry, BatchRequestDto dto) → List<Map<String,Object>>` — ordered per-sub-request results, each `{index, status, success, body}`.

- [ ] **Step 1: Create `BatchRequestDto.java`**

```java
package eu.starsong.ghidra.dto;

import java.util.List;

/** Parsed body of POST /batch. */
public class BatchRequestDto {
    public boolean atomic = false;
    public List<SubRequest> requests;

    public static class SubRequest {
        public String method;
        public String path;
        public Object body;   // Gson-decoded JSON object/array/primitive, may be null
    }
}
```

- [ ] **Step 2: Create `BatchService.java`**

```java
package eu.starsong.ghidra.service;

import com.google.gson.Gson;
import eu.starsong.ghidra.dto.BatchRequestDto;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.middleware.ErrorMapper;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.RouteRegistry;
import eu.starsong.ghidra.server.SyntheticGhidraContext;
import eu.starsong.ghidra.util.TransactionHelper;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Executes a batch of virtual HTTP sub-requests against existing handlers.
 * Best-effort by default (each handler manages its own transaction); atomic
 * wraps the whole loop in one Ghidra transaction and rolls back on first failure.
 */
public class BatchService {

    private static final Gson GSON = new Gson();

    /** Thrown inside an atomic batch to force a full rollback while carrying partial results. */
    private static class AbortBatch extends RuntimeException {
        final List<Map<String, Object>> results;
        AbortBatch(List<Map<String, Object>> results) { this.results = results; }
    }

    public List<Map<String, Object>> execute(GhidraContext ctx, RouteRegistry registry, BatchRequestDto dto) {
        List<BatchRequestDto.SubRequest> reqs = dto.requests == null ? List.of() : dto.requests;

        if (!dto.atomic) {
            List<Map<String, Object>> out = new ArrayList<>(reqs.size());
            for (int i = 0; i < reqs.size(); i++) {
                out.add(dispatch(ctx, registry, reqs.get(i), i));
            }
            return out;
        }

        // Atomic: one transaction around the whole loop; abort on first failure.
        Program program = ctx.requireProgram();
        try {
            return TransactionHelper.executeInTransaction(program, "Batch operation", () -> {
                List<Map<String, Object>> out = new ArrayList<>(reqs.size());
                for (int i = 0; i < reqs.size(); i++) {
                    Map<String, Object> r = dispatch(ctx, registry, reqs.get(i), i);
                    out.add(r);
                    if (Boolean.FALSE.equals(r.get("success"))) {
                        // Mark remaining sub-requests as rolled back, then abort.
                        for (int j = i + 1; j < reqs.size(); j++) {
                            out.add(rolledBack(j));
                        }
                        throw new AbortBatch(out);
                    }
                }
                return out;
            });
        } catch (AbortBatch ab) {
            return ab.results;          // transaction rolled back by the thrown exception
        } catch (TransactionHelper.TransactionException e) {
            throw new RuntimeException("Batch transaction failed: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> dispatch(GhidraContext ctx, RouteRegistry registry,
                                         BatchRequestDto.SubRequest req, int index) {
        if (req == null || req.method == null || req.path == null) {
            return error(index, 400, "BAD_REQUEST", "Sub-request requires method and path");
        }
        if (req.path.equals("/batch") || req.path.startsWith("/batch?")) {
            return error(index, 400, "NO_NESTED_BATCH", "Nested /batch is not allowed");
        }
        RouteRegistry.Match m = registry.match(req.method, req.path);
        if (m == null) {
            return error(index, 404, "NO_ROUTE", "No route for " + req.method + " " + req.path);
        }
        String bodyJson = req.body == null ? "{}" : GSON.toJson(req.body);
        SyntheticGhidraContext sctx = new SyntheticGhidraContext(
            ctx.tool(), ctx.port(), ctx.activeInstances(),
            req.method, req.path, m.pathParams(), m.queryParams(), bodyJson);
        try {
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
            return error(index, mapped.status(), mapped.code(), mapped.message());
        }
    }

    private Map<String, Object> error(int index, int status, String code, String message) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("index", index);
        r.put("status", status);
        r.put("success", false);
        r.put("body", Response.error(code, message).build());
        return r;
    }

    private Map<String, Object> rolledBack(int index) {
        return error(index, 409, "ROLLED_BACK", "Rolled back due to atomic batch failure");
    }
}
```

> Note: in atomic mode the `out` list ends up with the failing index plus the rolled-back tail appended after it; that ordering is acceptable because each entry carries its own `index`. If strict positional ordering is desired, sort `out` by `index` before returning — add `out.sort(Comparator.comparingInt(r -> (int) r.get("index")));` in the `AbortBatch` catch. Keep it simple unless the integration test (Task 8) requires sorting.

- [ ] **Step 3: Compile**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test-compile`
Expected: BUILD SUCCESS.

- [ ] **Step 4: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/dto/BatchRequestDto.java \
        src/main/java/eu/starsong/ghidra/service/BatchService.java
git commit -m "$(printf 'feat: add BatchService dispatch with best-effort/atomic modes\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 6: BatchResource + wire POST /batch

**Files:**
- Create: `src/main/java/eu/starsong/ghidra/resource/BatchResource.java`
- Modify: `src/main/java/eu/starsong/ghidra/server/GhydraServer.java` (uncomment the `new BatchResource(routeRegistry)` line from Task 2 Step 3)

**Interfaces:**
- Consumes: `RouteRegistry`, `BatchService`, `BatchRequestDto`, `Routes`, `Response`.

- [ ] **Step 1: Create `BatchResource.java`**

```java
package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.BatchRequestDto;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.server.RouteRegistry;
import eu.starsong.ghidra.server.Routes;
import eu.starsong.ghidra.service.BatchService;

import java.util.List;
import java.util.Map;

public class BatchResource implements Resource {

    private final RouteRegistry registry;
    private final BatchService batchService = new BatchService();

    public BatchResource(RouteRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void register(Routes routes) {
        routes.post("/batch", this::handle);
    }

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
}
```

- [ ] **Step 2: Uncomment the auto-registration in `GhydraServer.registerResources()`**

Ensure the line `new eu.starsong.ghidra.resource.BatchResource(routeRegistry).register(routes);` (added in Task 2 Step 3) is active.

- [ ] **Step 3: Compile + full test suite**

Run: `mvn -q -Dghidra.version=$GHIDRA_VERSION test`
Expected: BUILD SUCCESS, all Java tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/main/java/eu/starsong/ghidra/resource/BatchResource.java \
        src/main/java/eu/starsong/ghidra/server/GhydraServer.java
git commit -m "$(printf 'feat: register POST /batch endpoint\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 7: Bridge — batch_execute, named wrappers, formatter

**Files:**
- Modify: `bridge_mcp_hydra.py` (add tools near the analysis tools ~line 2558+; add `format_batch_results` near `format_call_paths` ~line 940; register in `FORMATTERS` ~line 1345; bump `BRIDGE_VERSION` line 65)
- Test: `tests/test_bridge_batch.py` (create)

**Interfaces:**
- Consumes (existing bridge helpers): `mcp.tool`, `text_output`, `safe_post`, `simplify_response`, `_get_instance_port`, `FORMATTERS`, `format_error`.
- Produces: `batch_execute`, `functions_decompile_batch`, `functions_rename_batch`, `data_create_batch`, `data_set_type_batch`, `data_rename_batch`, `structs_add_field_batch`, `structs_update_field_batch`, `format_batch_results`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_bridge_batch.py`:

```python
"""Offline tests for the batch bridge tools."""

import bridge_mcp_hydra as b


def test_batch_tools_are_callable():
    for name in ["batch_execute", "functions_decompile_batch", "functions_rename_batch",
                 "data_create_batch", "data_set_type_batch", "data_rename_batch",
                 "structs_add_field_batch", "structs_update_field_batch"]:
        assert callable(getattr(b, name)), name


def test_batch_execute_missing_requests_is_rejected():
    out = b.batch_execute([])
    assert "requests" in out  # MISSING_PARAMETER message rendered by text_output


def test_functions_rename_batch_builds_patch_requests(monkeypatch):
    captured = {}

    def fake_post(port, endpoint, payload):
        captured["endpoint"] = endpoint
        captured["payload"] = payload
        return {"success": True, "result": []}

    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", fake_post)

    b.functions_rename_batch([{"old": "FUN_00401000", "new": "parse"}])

    assert captured["endpoint"] == "batch"
    reqs = captured["payload"]["requests"]
    assert reqs == [{"method": "PATCH",
                     "path": "/functions/by-name/FUN_00401000",
                     "body": {"name": "parse"}}]


def test_functions_decompile_batch_builds_get_requests(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, payload: captured.update(payload) or {"success": True, "result": []})

    b.functions_decompile_batch(["main", "init"])

    paths = [r["path"] for r in captured["requests"]]
    assert paths == ["/functions/by-name/main/decompile", "/functions/by-name/init/decompile"]
    assert all(r["method"] == "GET" for r in captured["requests"])


def test_format_batch_results_renders_table():
    response = {"success": True, "result": [
        {"index": 0, "status": 200, "success": True, "body": {}},
        {"index": 1, "status": 400, "success": False,
         "body": {"error": {"code": "BAD_REQUEST", "message": "bad addr"}}},
    ]}
    out = b.format_batch_results(response)
    assert "0" in out and "200" in out and "ok" in out
    assert "1" in out and "400" in out and "BAD_REQUEST" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_bridge_batch.py -v`
Expected: FAIL — attributes (`batch_execute`, etc.) do not exist.

- [ ] **Step 3: Add `format_batch_results`** (place after `format_string_usage`, ~line 1000)

```python
def format_batch_results(response: dict, **kwargs) -> str:
    """Format a batch_execute response as a compact table."""
    if not response.get("success", False):
        return format_error(response)
    items = response.get("result", [])
    if not items:
        return "Batch: 0 sub-requests."
    ok = sum(1 for it in items if it.get("success"))
    lines = [f"Batch: {len(items)} sub-request(s), {ok} ok, {len(items) - ok} failed", ""]
    lines.append(f"  {'idx':>3}  {'status':>6}  result")
    for it in items:
        idx = it.get("index", "?")
        status = it.get("status", "?")
        if it.get("success"):
            note = "ok"
        else:
            err = (it.get("body") or {}).get("error", {})
            note = err.get("code", "error")
        lines.append(f"  {idx:>3}  {status:>6}  {note}")
    return "\n".join(lines)
```

- [ ] **Step 4: Register the formatter** (in the `FORMATTERS` dict, after the `analysis_find_call_paths` line ~1345)

```python
    "batch_execute": format_batch_results,
```

- [ ] **Step 5: Add the tools** (place near the other function tools, e.g. after `functions_rename`, ~line 2739)

```python
@mcp.tool()
@text_output
def batch_execute(requests: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Execute multiple API operations in a single request (one HTTP roundtrip).

    Each entry in `requests` is a virtual sub-request {method, path, body?} routed
    to an existing endpoint. Returns an ordered array of {index, status, success, body}.

    Args:
        requests: list of {"method": "GET|POST|PATCH|PUT|DELETE", "path": "/...",
                  "body": {..}? } — body optional for GET/DELETE.
        atomic: if True, the whole batch runs in one Ghidra transaction and rolls
                back entirely on the first failure (default False = best-effort).
        port: specific Ghidra instance port (optional).

    Examples:
        batch_execute([
            {"method": "GET",   "path": "/functions/by-name/main/decompile"},
            {"method": "PATCH", "path": "/functions/0x401000", "body": {"name": "parse"}},
        ])
    """
    if not requests:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "requests list is required and must be non-empty"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    payload = {"atomic": atomic, "requests": requests}
    response = safe_post(port, "batch", payload)
    return simplify_response(response)


def _run_batch(requests: list[dict], atomic: bool, port: int | None) -> dict:
    """Shared helper for named batch wrappers."""
    if not requests:
        return {
            "success": False,
            "error": {"code": "MISSING_PARAMETER", "message": "input list is required and must be non-empty"},
            "timestamp": int(time.time() * 1000),
        }
    port = _get_instance_port(port)
    response = safe_post(port, "batch", {"atomic": atomic, "requests": requests})
    return simplify_response(response)


@mcp.tool()
@text_output
def functions_decompile_batch(names: list[str], port: int | None = None) -> dict:
    """Decompile multiple functions in one request. names: fully-qualified names."""
    reqs = [{"method": "GET", "path": f"/functions/by-name/{quote(n)}/decompile"} for n in names]
    return _run_batch(reqs, False, port)


@mcp.tool()
@text_output
def functions_rename_batch(renames: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Rename multiple functions. renames: list of {"old": <fqn>, "new": <fqn>}."""
    reqs = [{"method": "PATCH", "path": f"/functions/by-name/{quote(r['old'])}", "body": {"name": r["new"]}}
            for r in renames]
    return _run_batch(reqs, atomic, port)


@mcp.tool()
@text_output
def data_create_batch(items: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Create multiple data items. items: list of {"address", "type", "name"?}."""
    reqs = [{"method": "POST", "path": "/data", "body": it} for it in items]
    return _run_batch(reqs, atomic, port)


@mcp.tool()
@text_output
def data_set_type_batch(items: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Set type on multiple data items. items: list of {"address", "type"}."""
    reqs = [{"method": "PATCH", "path": f"/data/{quote(it['address'])}", "body": {"type": it["type"]}}
            for it in items]
    return _run_batch(reqs, atomic, port)


@mcp.tool()
@text_output
def data_rename_batch(items: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Rename multiple data items. items: list of {"address", "name"}."""
    reqs = [{"method": "PATCH", "path": f"/data/{quote(it['address'])}", "body": {"name": it["name"]}}
            for it in items]
    return _run_batch(reqs, atomic, port)


@mcp.tool()
@text_output
def structs_add_field_batch(items: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Add fields to structs. items: list of {"struct", "field": {...}} matching the
    single structs_add_field body shape."""
    reqs = [{"method": "POST", "path": f"/structs/{quote(it['struct'])}/fields", "body": it.get("field", {})}
            for it in items]
    return _run_batch(reqs, atomic, port)


@mcp.tool()
@text_output
def structs_update_field_batch(items: list[dict], atomic: bool = False, port: int | None = None) -> dict:
    """Update struct fields. items: list of {"struct", "field_ref", "updates": {...}}."""
    reqs = [{"method": "PATCH", "path": f"/structs/{quote(it['struct'])}/fields/{quote(str(it['field_ref']))}",
             "body": it.get("updates", {})} for it in items]
    return _run_batch(reqs, atomic, port)
```

> Before finalizing the struct wrapper paths, confirm the exact struct field routes against `resource/StructResource.java` (`/structs/{name}/fields` and `/structs/{name}/fields/{ref}` or equivalent). Adjust the `path` templates if they differ; the test in Step 1 only pins the function/data wrappers, which use the verified routes.

- [ ] **Step 6: Bump `BRIDGE_VERSION`** (line 65)

```python
BRIDGE_VERSION = "v3.4.0"
```

- [ ] **Step 7: Run tests**

Run: `pytest tests/test_bridge_batch.py -v`
Expected: PASS. Then `pytest` (full unit suite) — expected: all green.

- [ ] **Step 8: Commit**

```bash
git add bridge_mcp_hydra.py tests/test_bridge_batch.py
git commit -m "$(printf 'feat: add batch_execute MCP tool and named batch wrappers\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 8: Integration tests (live Ghidra)

**Files:**
- Create: `test_batch.py` (repo root)

**Interfaces:**
- Consumes: live HTTP API at default port 8192; follows the auto-skip pattern of existing `test_*.py`.

- [ ] **Step 1: Write the integration test**

Mirror the connection/auto-skip setup of `test_data_operations.py` (copy its `setUpClass`/skip guard). Then add:

```python
import unittest, requests

BASE = "http://localhost:8192"

def _alive():
    try:
        return requests.get(f"{BASE}/instances", timeout=2).ok
    except Exception:
        return False

@unittest.skipUnless(_alive(), "No live Ghidra instance on :8192")
class BatchTests(unittest.TestCase):

    def test_best_effort_mixed_batch(self):
        # one valid decompile + one rename to a unique name + one bad address
        body = {"atomic": False, "requests": [
            {"method": "GET",   "path": "/functions"},
            {"method": "PATCH", "path": "/functions/0xdeadbeef", "body": {"name": "x"}},  # bad addr -> 4xx
        ]}
        r = requests.post(f"{BASE}/batch", json=body, timeout=60).json()
        self.assertTrue(r["success"])
        results = r["result"]
        self.assertEqual(results[0]["status"], 200)
        self.assertFalse(results[1]["success"])
        self.assertGreaterEqual(results[1]["status"], 400)

    def test_atomic_rollback_reverts_first_success(self):
        # Pick the first real function, rename it, then force a failure in the same atomic batch.
        fns = requests.get(f"{BASE}/functions?limit=1", timeout=30).json()["result"]
        if not fns:
            self.skipTest("no functions in program")
        addr = fns[0]["address"]
        original = fns[0]["name"]
        body = {"atomic": True, "requests": [
            {"method": "PATCH", "path": f"/functions/{addr}", "body": {"name": "batch_atomic_probe"}},
            {"method": "PATCH", "path": "/functions/0xdeadbeef", "body": {"name": "y"}},  # fails -> rollback
        ]}
        r = requests.post(f"{BASE}/batch", json=body, timeout=60).json()
        self.assertFalse(r["result"][0]["success"] and r["result"][1]["success"])
        # Verify the first rename was rolled back:
        after = requests.get(f"{BASE}/functions/{addr}", timeout=30).json()["result"]
        self.assertEqual(after["name"], original)

if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the integration test**

Run (with a Ghidra instance + plugin loaded and a program open): `python -m unittest test_batch -v`
Expected: PASS, or SKIP if no live instance. If `test_atomic_rollback_reverts_first_success` fails, the nested-transaction rollback semantics need revisiting (see spec §4 warning) — debug with `superpowers:systematic-debugging` before proceeding.

- [ ] **Step 3: Commit**

```bash
git add test_batch.py
git commit -m "$(printf 'test: add live batch integration tests (best-effort + atomic rollback)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Task 9: Version bump + documentation

**Files:**
- Modify: `src/main/java/eu/starsong/ghidra/api/ApiConstants.java` (`PLUGIN_VERSION`)
- Modify: `CHANGELOG.md`, `GHIDRA_HTTP_API.md`, `README.md`
- Modify (DO NOT commit): `docs/COMPETITIVE_GAPS.md`

- [ ] **Step 1: Bump `PLUGIN_VERSION`**

In `ApiConstants.java`, increment `PLUGIN_VERSION` to the next patch/minor (match the existing version scheme; leave `API_VERSION` unchanged).

- [ ] **Step 2: Update `CHANGELOG.md`**

Add under a new unreleased entry:

```markdown
### Added
- Batch mode: `POST /batch` executes an array of virtual HTTP sub-requests against
  existing endpoints in one roundtrip, with best-effort (default) or `atomic` transaction
  semantics. Exposed via the `batch_execute` MCP tool plus named wrappers
  (`functions_decompile_batch`, `functions_rename_batch`, `data_create_batch`,
  `data_set_type_batch`, `data_rename_batch`, `structs_add_field_batch`,
  `structs_update_field_batch`).
```

- [ ] **Step 3: Document `POST /batch` in `GHIDRA_HTTP_API.md`**

Add a section describing the request body (`{atomic, requests:[{method, path, body}]}`), the
response (`result` array of `{index, status, success, body}`), best-effort vs atomic, and the
`NO_ROUTE` / `ROLLED_BACK` / `NO_NESTED_BATCH` error codes.

- [ ] **Step 4: Add the new MCP tools to `README.md`** tool/namespace catalog.

- [ ] **Step 5: Update `docs/COMPETITIVE_GAPS.md` (not committed)**

Mark §5.1 Batch Mode Tools as `✅ Done`; update the §0 progress tracker (move batch mode from "next" to done, set "Последнее обновление прогресса" date).

- [ ] **Step 6: Commit (docs + version only; exclude COMPETITIVE_GAPS.md)**

```bash
git add src/main/java/eu/starsong/ghidra/api/ApiConstants.java CHANGELOG.md GHIDRA_HTTP_API.md README.md
git commit -m "$(printf 'docs: document batch mode; bump PLUGIN_VERSION\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

## Self-Review

**1. Spec coverage:**
- §2 architecture (RouteRegistry, Routes, Resource change, SyntheticGhidraContext, BatchResource, BatchService, ErrorMapper) → Tasks 1–6. ✅
- §3 request/response format → Task 5 (BatchService result shape), Task 6 (envelope), Task 8 (asserts shape). ✅
- §4 transactions/errors (best-effort, atomic, ErrorMapper reuse, NO_ROUTE) → Task 3 + Task 5 + Task 8. ✅
- §5 MCP wrappers (generic + 7 named + formatter) → Task 7. ✅
- §6 tests (unit + integration) → Tasks 1,3,4,7 (unit) + Task 8 (integration). ✅
- §7 versioning/docs → Task 9 (PLUGIN_VERSION + BRIDGE_VERSION in Task 7; API_VERSION untouched). ✅
- §8 YAGNI (no CLI, sequential, no nested batch) → no CLI task; nested batch rejected in Task 5. ✅

**2. Placeholder scan:** No "TBD/TODO/handle edge cases". Two explicit "confirm against source" notes (ErrorMapper accessor name; struct field routes) are verification instructions with concrete fallbacks, not placeholders.

**3. Type consistency:** `RouteRegistry.add/match` + `Match(handler, pathParams, queryParams)` consistent across Tasks 1,2,5. `SyntheticGhidraContext` constructor signature consistent between Task 4 (definition) and Task 5 (call). `ErrorMapper.Mapped(status, code, message)` consistent Tasks 3,5. `BatchService.execute(GhidraContext, RouteRegistry, BatchRequestDto)` consistent Tasks 5,6. Bridge `_run_batch`/wrapper names consistent Task 7 ↔ tests.

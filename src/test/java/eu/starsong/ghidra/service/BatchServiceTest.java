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

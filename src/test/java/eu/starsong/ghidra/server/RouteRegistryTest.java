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

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

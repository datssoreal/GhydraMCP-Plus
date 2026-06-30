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

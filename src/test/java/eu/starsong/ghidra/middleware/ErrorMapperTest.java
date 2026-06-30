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

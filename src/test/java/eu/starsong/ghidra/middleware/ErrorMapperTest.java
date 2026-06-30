package eu.starsong.ghidra.middleware;

import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.GhydraServer;
import eu.starsong.ghidra.service.ProjectService;
import com.google.gson.JsonSyntaxException;
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

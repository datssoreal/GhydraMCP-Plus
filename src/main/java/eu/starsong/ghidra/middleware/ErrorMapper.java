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

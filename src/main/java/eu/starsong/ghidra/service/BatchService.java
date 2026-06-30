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
import ghidra.util.Msg;

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
    }

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

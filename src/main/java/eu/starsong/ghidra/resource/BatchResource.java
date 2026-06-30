package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.BatchRequestDto;
import eu.starsong.ghidra.middleware.ErrorMapper;
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
}

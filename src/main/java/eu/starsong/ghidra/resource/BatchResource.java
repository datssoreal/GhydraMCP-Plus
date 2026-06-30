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

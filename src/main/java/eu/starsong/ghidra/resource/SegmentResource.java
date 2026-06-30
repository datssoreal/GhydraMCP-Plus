package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.MemoryBlockDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.hateoas.Response;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.server.Routes;
import eu.starsong.ghidra.service.MemoryService;

import java.util.List;

/**
 * REST resource for /segments endpoints.
 * Provides a segment-focused view of memory blocks.
 */
public class SegmentResource implements Resource {

    private final MemoryService memoryService;

    public SegmentResource() {
        this.memoryService = new MemoryService();
    }

    @Override
    public void register(Routes routes) {
        routes.get("/segments", this::list);
        routes.get("/segments/{name}", this::getByName);
    }

    /**
     * GET /segments - List all segments
     */
    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();

        String nameFilter = ctx.queryParam("name");

        List<MemoryBlockDto> segments = memoryService.listBlocks(program);

        if (nameFilter != null && !nameFilter.isEmpty()) {
            String lower = nameFilter.toLowerCase();
            segments = segments.stream()
                .filter(s -> s.name().toLowerCase().contains(lower))
                .toList();
        }

        var result = Paginator.paginate(segments, pagination, "/segments")
            .withItemLinks(seg -> Links.builder()
                .self("/segments/{}", seg.name())
                .link("memory", "/memory/{}", seg.start())
                .build());

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("program", "/program")
            .link("memory", "/memory")
            .build());
    }

    /**
     * GET /segments/{name} - Get segment by name
     */
    private void getByName(GhidraContext ctx) {
        var program = ctx.requireProgram();
        String name = ctx.pathParam("name");

        MemoryBlockDto segment = memoryService.getBlockByName(program, name);

        ctx.json(Response.ok(ctx.ctx(), ctx.port(), segment)
            .self("/segments/{}", name)
            .link("segments", "/segments")
            .link("memory", "/memory/{}", segment.start())
            .build());
    }
}

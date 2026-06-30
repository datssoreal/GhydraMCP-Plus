package eu.starsong.ghidra.resource;

import eu.starsong.ghidra.dto.ClassDto;
import eu.starsong.ghidra.hateoas.Links;
import eu.starsong.ghidra.hateoas.Paginator;
import eu.starsong.ghidra.server.GhidraContext;
import eu.starsong.ghidra.server.Resource;
import eu.starsong.ghidra.server.Routes;
import eu.starsong.ghidra.service.NamespaceService;

import java.util.List;

public class ClassResource implements Resource {

    private final NamespaceService service;

    public ClassResource() {
        this.service = new NamespaceService();
    }

    public ClassResource(NamespaceService service) {
        this.service = service;
    }

    @Override
    public void register(Routes routes) {
        routes.get("/classes", this::list);
    }

    private void list(GhidraContext ctx) {
        var program = ctx.requireProgram();
        var pagination = ctx.pagination();
        List<ClassDto> classes = service.listClasses(program);

        var result = Paginator.paginate(classes, pagination, "/classes")
            .withItemLinks(c -> Links.builder()
                .self("/classes/{}", c.name())
                .build());

        ctx.json(result.toResponse(ctx.ctx(), ctx.port())
            .link("program", "/program")
            .build());
    }
}

package eu.starsong.ghidra.server;

import io.javalin.Javalin;
import io.javalin.http.Context;

import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Registration surface for resources. Each call registers the route with
 * Javalin AND records (method, pattern, handler) in the RouteRegistry so the
 * /batch pipeline can dispatch virtual sub-requests to the same handler.
 */
public class Routes {

    private final Javalin app;
    private final Function<Context, GhidraContext> contextFactory;
    private final RouteRegistry registry;

    public Routes(Javalin app, Function<Context, GhidraContext> contextFactory, RouteRegistry registry) {
        this.app = app;
        this.contextFactory = contextFactory;
        this.registry = registry;
    }

    public Javalin app() { return app; }
    public Function<Context, GhidraContext> contextFactory() { return contextFactory; }
    public RouteRegistry registry() { return registry; }

    public void get(String path, Consumer<GhidraContext> handler)    { wire("GET", path, handler); }
    public void post(String path, Consumer<GhidraContext> handler)   { wire("POST", path, handler); }
    public void patch(String path, Consumer<GhidraContext> handler)  { wire("PATCH", path, handler); }
    public void put(String path, Consumer<GhidraContext> handler)    { wire("PUT", path, handler); }
    public void delete(String path, Consumer<GhidraContext> handler) { wire("DELETE", path, handler); }

    private void wire(String method, String path, Consumer<GhidraContext> handler) {
        registry.add(method, path, handler);
        switch (method) {
            case "GET"    -> app.get(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "POST"   -> app.post(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "PATCH"  -> app.patch(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "PUT"    -> app.put(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            case "DELETE" -> app.delete(path, ctx -> handler.accept(contextFactory.apply(ctx)));
            default -> throw new IllegalArgumentException("Unsupported method: " + method);
        }
    }
}

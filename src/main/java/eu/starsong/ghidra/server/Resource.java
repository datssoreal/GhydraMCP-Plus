package eu.starsong.ghidra.server;

/**
 * Interface for REST resources that register routes with the server.
 */
@FunctionalInterface
public interface Resource {

    /**
     * Register routes via the {@link Routes} wrapper, which both wires Javalin
     * and records the route in the {@link RouteRegistry} for batch dispatch.
     */
    void register(Routes routes);
}

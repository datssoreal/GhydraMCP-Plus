package eu.starsong.ghidra.server;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.middleware.CorsHandler;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;
import io.javalin.Javalin;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Factory and manager for the Javalin HTTP server.
 * Handles server creation, configuration, and lifecycle.
 */
public class GhydraServer {

    private final PluginTool tool;
    private final int port;
    private final Map<Integer, Object> activeInstances;
    private final boolean isBaseInstance;
    private final List<Resource> resources = new ArrayList<>();
    private final RouteRegistry routeRegistry = new RouteRegistry();

    private Javalin app;

    public GhydraServer(PluginTool tool, int port, Map<Integer, Object> activeInstances, boolean isBaseInstance) {
        this.tool = tool;
        this.port = port;
        this.activeInstances = activeInstances;
        this.isBaseInstance = isBaseInstance;
    }

    /**
     * Register a resource with the server.
     */
    public GhydraServer register(Resource resource) {
        resources.add(resource);
        return this;
    }

    /**
     * Register multiple resources with the server.
     */
    public GhydraServer register(Resource... resources) {
        for (Resource r : resources) {
            this.resources.add(r);
        }
        return this;
    }

    /**
     * Start the server.
     */
    public void start() {
        app = Javalin.create(config -> {
            config.showJavalinBanner = false;

            config.router.contextPath = "/";

            config.jsonMapper(new GsonMapper());
        });

        configureMiddleware();

        registerResources();

        // Bind interface is configurable. Default keeps the historical all-interfaces
        // behaviour so cross-host setups (e.g. bridge in WSL -> Ghidra on Windows) keep
        // working; set -Dghidra.mcp.bind.host=127.0.0.1 (or GHYDRA_BIND_HOST) to lock down.
        String bindHost = System.getProperty("ghidra.mcp.bind.host");
        if (bindHost == null || bindHost.isEmpty()) {
            bindHost = System.getenv("GHYDRA_BIND_HOST");
        }
        if (bindHost != null && !bindHost.isEmpty()) {
            app.start(bindHost, port);
            Msg.info(this, "GhydraMCP HTTP server started on " + bindHost + ":" + port);
        } else {
            app.start(port);
            Msg.info(this, "GhydraMCP HTTP server started on port " + port);
        }
    }

    /**
     * Stop the server.
     */
    public void stop() {
        if (app != null) {
            app.stop();
            Msg.info(this, "GhydraMCP HTTP server stopped on port " + port);
        }
    }

    /**
     * Get the RouteRegistry (used by the /batch pipeline).
     */
    public RouteRegistry routeRegistry() { return routeRegistry; }

    /**
     * Get the Javalin app instance.
     */
    public Javalin app() {
        return app;
    }

    /**
     * Get the server port.
     */
    public int port() {
        return port;
    }

    /**
     * Check if this is the base instance.
     */
    public boolean isBaseInstance() {
        return isBaseInstance;
    }

    // -------------------------------------------------------------------------
    // Private methods
    // -------------------------------------------------------------------------

    private void configureMiddleware() {
        app.before(new CorsHandler());

        // All exception handlers delegate to ErrorMapper so per-route errors and
        // /batch sub-request errors (which bypass middleware) share one mapping.
        app.exception(GhidraContext.NoProgramException.class, this::handleMapped);
        app.exception(eu.starsong.ghidra.service.ProjectService.NoProjectException.class, this::handleMapped);
        app.exception(NotFoundException.class, this::handleMapped);
        app.exception(BadRequestException.class, this::handleMapped);
        // Validation failures conventionally surface as IllegalArgumentException
        // (bad address, malformed param, etc.); ErrorMapper treats them as 400.
        app.exception(IllegalArgumentException.class, this::handleMapped);
        // Malformed request bodies (bodyAsClass) throw from Gson; client error, not 500.
        app.exception(com.google.gson.JsonSyntaxException.class, this::handleMapped);
        app.exception(Exception.class, this::handleMapped);
    }

    private void handleMapped(Exception e, io.javalin.http.Context ctx) {
        eu.starsong.ghidra.middleware.ErrorMapper.Mapped m =
            eu.starsong.ghidra.middleware.ErrorMapper.map(e);
        if (m.status() >= 500) {
            ghidra.util.Msg.error(this, "Unhandled exception in " + ctx.path(), e);
        }
        ctx.status(io.javalin.http.HttpStatus.forStatus(m.status()));
        ctx.json(eu.starsong.ghidra.hateoas.Response.error(ctx, port, m.code(), m.message()).build());
    }

    private void registerResources() {
        Routes routes = new Routes(app, this::createContext, routeRegistry);
        for (Resource resource : resources) {
            resource.register(routes);
        }
        // Auto-register the batch pipeline last so every other route is already
        // present in the registry (BatchResource only needs the registry instance).
        new eu.starsong.ghidra.resource.BatchResource(routeRegistry).register(routes);
    }

    /**
     * Create a GhidraContext from a Javalin Context.
     * This is passed to resources for creating handlers.
     */
    private GhidraContext createContext(io.javalin.http.Context ctx) {
        return new GhidraContext(ctx, tool, port, activeInstances);
    }

    // -------------------------------------------------------------------------
    // Static utility methods
    // -------------------------------------------------------------------------

    /**
     * Find an available port starting from the default port.
     */
    public static int findAvailablePort(Map<Integer, ?> activeInstances) {
        int basePort = ApiConstants.DEFAULT_PORT;
        int maxAttempts = ApiConstants.MAX_PORT_ATTEMPTS;

        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            int candidate = basePort + attempt;
            if (!activeInstances.containsKey(candidate)) {
                try (ServerSocket s = new ServerSocket(candidate)) {
                    return candidate;
                } catch (IOException e) {
                    // Port not available, try next
                }
            }
        }

        throw new RuntimeException("Could not find available port after " + maxAttempts + " attempts");
    }

    // -------------------------------------------------------------------------
    // Exception classes
    // -------------------------------------------------------------------------

    public static class NotFoundException extends RuntimeException {
        private final String errorCode;

        public NotFoundException(String message) {
            this(message, "NOT_FOUND");
        }

        public NotFoundException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return errorCode;
        }
    }

    public static class BadRequestException extends RuntimeException {
        private final String errorCode;

        public BadRequestException(String message) {
            this(message, "BAD_REQUEST");
        }

        public BadRequestException(String message, String errorCode) {
            super(message);
            this.errorCode = errorCode;
        }

        public String errorCode() {
            return errorCode;
        }
    }
}

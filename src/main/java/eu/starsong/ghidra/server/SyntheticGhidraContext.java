package eu.starsong.ghidra.server;

import com.google.gson.Gson;
import ghidra.framework.plugintool.PluginTool;
import io.javalin.http.Context;

import java.lang.reflect.Proxy;
import java.util.Map;

/**
 * A GhidraContext that serves request data from an in-process batch sub-request
 * and captures the handler's response instead of writing it to a real HTTP
 * response. The raw Javalin Context is a no-op proxy that only answers
 * header(...) (returns null), which is all Response.addMeta needs.
 */
public class SyntheticGhidraContext extends GhidraContext {

    private static final Gson GSON = new Gson();

    private final String method;
    private final String path;
    private final Map<String, String> pathParams;
    private final Map<String, String> queryParams;
    private final String bodyJson;

    private int capturedStatus = 200;
    private Object capturedBody;

    public SyntheticGhidraContext(PluginTool tool, int port, Map<Integer, ?> activeInstances,
                                  String method, String path,
                                  Map<String, String> pathParams,
                                  Map<String, String> queryParams,
                                  String bodyJson) {
        super(noopContext(), tool, port, activeInstances);
        this.method = method;
        this.path = path;
        this.pathParams = pathParams;
        this.queryParams = queryParams;
        this.bodyJson = bodyJson == null ? "{}" : bodyJson;
    }

    private static Context noopContext() {
        return (Context) Proxy.newProxyInstance(
            SyntheticGhidraContext.class.getClassLoader(),
            new Class<?>[]{Context.class},
            (proxy, m, args) -> {
                if ("header".equals(m.getName())) {
                    return null;
                }
                Class<?> rt = m.getReturnType();
                if (rt.equals(void.class)) return null;
                if (rt.equals(boolean.class)) return false;
                if (rt.equals(int.class)) return 0;
                return null;
            });
    }

    @Override public String pathParam(String name) { return pathParams.get(name); }
    @Override public String method() { return method; }
    @Override public String path() { return path; }

    @Override public String queryParam(String name) { return queryParams.get(name); }

    @Override public String queryParam(String name, String defaultValue) {
        String v = queryParams.get(name);
        return v != null ? v : defaultValue;
    }

    @Override public int queryParamAsInt(String name, int defaultValue) {
        String v = queryParams.get(name);
        if (v == null || v.isEmpty()) return defaultValue;
        try { return Integer.parseInt(v); } catch (NumberFormatException e) { return defaultValue; }
    }

    @Override public <T> T bodyAsClass(Class<T> clazz) { return GSON.fromJson(bodyJson, clazz); }

    @Override public GhidraContext status(int code) { this.capturedStatus = code; return this; }

    @Override public void json(Object obj) { this.capturedBody = obj; }

    public int capturedStatus() { return capturedStatus; }
    public Object capturedBody() { return capturedBody; }
}

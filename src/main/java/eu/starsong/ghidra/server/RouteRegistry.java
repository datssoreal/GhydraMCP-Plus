package eu.starsong.ghidra.server;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Records every registered route as (method, pattern, handler) and matches an
 * incoming (method, path) against them. Used by the /batch pipeline to dispatch
 * virtual sub-requests to the same handlers Javalin would invoke.
 */
public class RouteRegistry {

    public record Match(Consumer<GhidraContext> handler,
                        Map<String, String> pathParams,
                        Map<String, String> queryParams) {}

    private record Route(String method, String[] segments, Consumer<GhidraContext> handler) {}

    private final List<Route> routes = new ArrayList<>();

    public void add(String method, String pattern, Consumer<GhidraContext> handler) {
        routes.add(new Route(method.toUpperCase(), splitPath(pattern), handler));
    }

    public Match match(String method, String rawPath) {
        String m = method.toUpperCase();
        int q = rawPath.indexOf('?');
        String pathPart = q >= 0 ? rawPath.substring(0, q) : rawPath;
        String queryPart = q >= 0 ? rawPath.substring(q + 1) : "";
        String[] pathSegments = splitPath(pathPart);

        for (Route route : routes) {
            if (!route.method().equals(m)) continue;
            if (route.segments().length != pathSegments.length) continue;
            Map<String, String> params = new LinkedHashMap<>();
            if (segmentsMatch(route.segments(), pathSegments, params)) {
                return new Match(route.handler(), params, parseQuery(queryPart));
            }
        }
        return null;
    }

    private boolean segmentsMatch(String[] pattern, String[] actual, Map<String, String> out) {
        for (int i = 0; i < pattern.length; i++) {
            String p = pattern[i];
            if (p.length() > 1 && p.charAt(0) == '{' && p.charAt(p.length() - 1) == '}') {
                out.put(p.substring(1, p.length() - 1), decode(actual[i]));
            } else if (!p.equals(actual[i])) {
                return false;
            }
        }
        return true;
    }

    private static String[] splitPath(String path) {
        String trimmed = path.startsWith("/") ? path.substring(1) : path;
        if (trimmed.endsWith("/")) trimmed = trimmed.substring(0, trimmed.length() - 1);
        if (trimmed.isEmpty()) return new String[0];
        return trimmed.split("/");
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        if (query.isEmpty()) return out;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            if (eq < 0) {
                out.put(decode(pair), "");
            } else {
                out.put(decode(pair.substring(0, eq)), decode(pair.substring(eq + 1)));
            }
        }
        return out;
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}

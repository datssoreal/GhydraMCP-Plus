## 2026-06-28 - MCP Bridge HTTP Latency
**Learning:** The bridge uses the `requests` library to make local HTTP calls, but without a `requests.Session()`, each API call created a new TCP connection, accumulating huge overhead over multiple calls.
**Action:** Always check if we're hitting APIs repeatedly; if so, create and use a persistent `Session` with an `HTTPAdapter` configured with a connection pool.

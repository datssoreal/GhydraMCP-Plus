## 2026-06-28 - MCP Bridge HTTP Latency
**Learning:** The bridge uses the `requests` library to make local HTTP calls, but without a `requests.Session()`, each API call created a new TCP connection, accumulating huge overhead over multiple calls.
**Action:** Always check if we're hitting APIs repeatedly; if so, create and use a persistent `Session` with an `HTTPAdapter` configured with a connection pool.
## 2026-06-28 - Per-port HTTP connection pooling
**Learning:** Using a single global session for multiple Ghidra instances can cause contention for pool connections. Fast-failing discovery calls shouldn't use retry adapters, as this wastes time polling dead/incorrect endpoints.
**Action:** Use a dedicated `requests.Session` per port with a bounded connection pool size, and separate the discovery mechanism into a distinct `Session` object without retry logic to fail quickly. Ensure that connections are cleaned up when instances are unregistered to avoid resource leakage.

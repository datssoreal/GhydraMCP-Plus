"""Offline tests for the batch bridge tools."""

import bridge_mcp_hydra as b


def test_batch_tools_are_callable():
    for name in ["batch_execute", "functions_decompile_batch", "functions_rename_batch",
                 "data_create_batch", "data_set_type_batch", "data_rename_batch",
                 "structs_add_field_batch", "structs_update_field_batch"]:
        assert callable(getattr(b, name)), name


def test_batch_execute_missing_requests_is_rejected():
    out = b.batch_execute([])
    assert "requests" in out  # MISSING_PARAMETER message rendered by text_output


def test_functions_rename_batch_builds_patch_requests(monkeypatch):
    captured = {}

    def fake_post(port, endpoint, payload):
        captured["endpoint"] = endpoint
        captured["payload"] = payload
        return {"success": True, "result": []}

    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", fake_post)

    b.functions_rename_batch([{"old": "FUN_00401000", "new": "parse"}])

    assert captured["endpoint"] == "batch"
    reqs = captured["payload"]["requests"]
    assert reqs == [{"method": "PATCH",
                     "path": "/functions/by-name/FUN_00401000",
                     "body": {"name": "parse"}}]


def test_functions_decompile_batch_builds_get_requests(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, payload: captured.update(payload) or {"success": True, "result": []})

    b.functions_decompile_batch(["main", "init"])

    paths = [r["path"] for r in captured["requests"]]
    assert paths == ["/functions/by-name/main/decompile", "/functions/by-name/init/decompile"]
    assert all(r["method"] == "GET" for r in captured["requests"])


def test_format_batch_results_renders_table():
    response = {"success": True, "result": [
        {"index": 0, "status": 200, "success": True, "body": {}},
        {"index": 1, "status": 400, "success": False,
         "body": {"error": {"code": "BAD_REQUEST", "message": "bad addr"}}},
    ]}
    out = b.format_batch_results(response)
    assert "0" in out and "200" in out and "ok" in out
    assert "1" in out and "400" in out and "BAD_REQUEST" in out


def test_batch_wrappers_have_formatters_registered():
    # Mutation wrappers summarize as the batch table; decompile prints code.
    for name in ["batch_execute", "functions_rename_batch", "data_create_batch",
                 "data_set_type_batch", "data_rename_batch", "structs_add_field_batch",
                 "structs_update_field_batch"]:
        assert b.FORMATTERS.get(name) is b.format_batch_results, name
    assert b.FORMATTERS.get("functions_decompile_batch") is b.format_batch_decompile


def test_format_batch_decompile_renders_code_and_errors():
    response = {"success": True, "result": [
        {"index": 0, "status": 200, "success": True, "body": {"success": True, "result": {
            "functionName": "main", "functionAddress": "0x401000",
            "decompilation": "int main(void) {\n  return 0;\n}"}}},
        {"index": 1, "status": 404, "success": False,
         "body": {"error": {"code": "FUNCTION_NOT_FOUND", "message": "no such fn"}}},
    ]}
    out = b.format_batch_decompile(response)
    assert "main" in out and "0x401000" in out
    assert "int main(void)" in out and "return 0;" in out
    assert "1" in out and "FUNCTION_NOT_FOUND" in out


def test_rename_batch_missing_key_returns_error():
    # missing "old" -> structured error string, not a raw KeyError
    out = b.functions_rename_batch([{"new": "parse"}])
    assert isinstance(out, str)
    assert "old" in out


def test_batch_wrapper_handles_no_instance(monkeypatch):
    def boom(p=None):
        raise ValueError("No active Ghidra instance on port 8192")
    monkeypatch.setattr(b, "_get_instance_port", boom)
    out = b.functions_rename_batch([{"old": "a", "new": "b"}])
    assert isinstance(out, str)
    assert "instance" in out.lower()


def test_rename_batch_threads_atomic_flag(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post",
                        lambda port, ep, payload: captured.update(payload) or {"success": True, "result": []})
    b.functions_rename_batch([{"old": "a", "new": "b"}], atomic=True)
    assert captured["atomic"] is True


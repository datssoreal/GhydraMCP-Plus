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

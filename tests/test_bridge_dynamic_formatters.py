"""Offline tests proving emulation_*/unicorn_* tools surface real data instead
of collapsing to the generic "Done" mutation-success message.

Root cause: these tools return data-rich dicts (registers, pc, stop reason,
hex bytes), but @text_output's fallback for any function name missing from
FORMATTERS is format_simple_result(response, "Done") -- which discards the
dict entirely. None of the emulation_*/unicorn_* tools had a FORMATTERS
entry, so every call silently returned the literal string "Done".
"""

import bridge_mcp_hydra as b


def _dynamic_tool_names():
    return sorted(
        name for name in dir(b)
        if (name.startswith("emulation_") or name.startswith("unicorn_"))
        and callable(getattr(b, name))
        and hasattr(getattr(b, name), "__wrapped__")  # only @text_output-wrapped tools
    )


def test_emulation_and_unicorn_tools_have_formatters_registered():
    names = _dynamic_tool_names()
    assert names, "sanity: expected to find emulation_*/unicorn_* tools"
    missing = [n for n in names if n not in b.FORMATTERS]
    assert not missing, f"tools falling back to bare 'Done': {missing}"


def test_emulation_reset_shows_pc_and_registers_not_done(monkeypatch):
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: {
        "success": True,
        "result": {"pc": "0x140001000", "steps": 0, "stopReason": None,
                   "registers": {"RIP": "0x140001000", "RSP": "0x1ffffe0"}},
        "timestamp": 1,
    })
    out = b.emulation_reset("0x140001000")
    assert out != "Done"
    assert "0x140001000" in out
    assert "RIP" in out


def test_emulation_read_register_shows_value_not_done(monkeypatch):
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_get", lambda port, ep, params=None: {
        "success": True, "result": {"name": "RIP", "value": "0x140001000"}, "timestamp": 1,
    })
    out = b.emulation_read_register("RIP")
    assert out != "Done"
    assert "0x140001000" in out


def test_unicorn_get_state_shows_registers_not_done(monkeypatch):
    class FakeSession:
        def get_register(self, name):
            return 0x140001000 if name == "RIP" else 0

    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    b._UNICORN_SESSIONS[8192] = FakeSession()
    try:
        out = b.unicorn_get_state(port=8192)
        assert out != "Done"
        assert "RIP" in out
        assert "0x140001000" in out
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)


def test_batch_execute_table_includes_response_body():
    response = {"success": True, "result": [
        {"index": 0, "status": 200, "success": True,
         "body": {"success": True, "result": {"name": "RIP", "value": "0x140001000"}}},
    ]}
    out = b.format_batch_results(response)
    assert "0x140001000" in out


def test_format_dynamic_state_renders_list_of_dicts():
    resp = {"success": True, "result": {
        "mem_writes": [{"address": "0x140076000", "size": 4, "value": "0x41"}],
        "trace": ["0x140075000", "0x140075004"],
        "registers": {},
        "hook_log": [],
    }}
    out = b.format_dynamic_state(resp)
    assert "mem_writes (1):" in out
    assert "0x140076000" in out            # the dict body is rendered, not collapsed
    assert "trace (2):" in out
    assert "0x140075004" in out
    assert "registers: {}" in out          # empty dict branch
    assert "hook_log: []" in out           # empty list branch


def test_format_dynamic_state_handles_non_dict_result():
    out = b.format_dynamic_state({"success": True, "result": "raw-string-payload"})
    assert out == "raw-string-payload"


def test_format_dynamic_state_reports_failure_via_error():
    out = b.format_dynamic_state({"success": False, "error": {"code": "BOOM", "message": "kaboom"}})
    assert "kaboom" in out or "BOOM" in out


def test_batch_results_omits_body_line_when_payload_empty():
    # body carries only stripped keys -> no "body:" line, but still counts as ok
    resp = {"success": True, "result": [
        {"index": 0, "status": 200, "success": True,
         "body": {"success": True, "timestamp": 1, "_links": {}}},
    ]}
    out = b.format_batch_results(resp)
    assert "ok" in out
    assert "body:" not in out


def test_batch_results_tolerates_non_dict_body():
    resp = {"success": True, "result": [
        {"index": 0, "status": 500, "success": False, "body": "not-a-dict"},
    ]}
    out = b.format_batch_results(resp)          # must not raise
    assert "error" in out

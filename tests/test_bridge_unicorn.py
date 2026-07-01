import pytest

from bridge_mcp_hydra import _unicorn_run_result


def _state(stop, last_error=None):
    return {"pc": 0x1000, "steps": 3, "stop_reason": stop, "last_error": last_error,
            "registers": {"RIP": 0x1000}, "trace": [], "mem_writes": []}


def test_done_is_success_without_error_envelope():
    r = _unicorn_run_result(_state("DONE"))
    assert r["success"] is True
    assert r["last_error"] is None
    assert "error" not in r
    assert r["pc"] == "0x1000"


def test_lazy_fetch_failed_is_failure_and_surfaces_message():
    r = _unicorn_run_result(_state("LAZY_FETCH_FAILED", "no image bytes at 0x140076000"))
    assert r["success"] is False
    assert r["stop_reason"] == "LAZY_FETCH_FAILED"
    assert r["error"]["code"] == "LAZY_FETCH_FAILED"
    assert "0x140076000" in r["error"]["message"]
    assert r["last_error"] == "no image bytes at 0x140076000"


def test_count_is_failure_with_cap_message():
    r = _unicorn_run_result(_state("COUNT"))
    assert r["success"] is False
    assert r["error"]["code"] == "COUNT"
    assert "cap" in r["error"]["message"].lower()


def test_lazy_cap_reached_is_failure_with_budget_hint():
    r = _unicorn_run_result(_state("LAZY_CAP_REACHED",
                                   "lazy page cap (4096) reached at 0x140075000; raise max_lazy_pages"))
    assert r["success"] is False
    assert r["error"]["code"] == "LAZY_CAP_REACHED"
    assert "max_lazy_pages" in r["error"]["message"]


def test_unicorn_map_zero_fills_a_region():
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    b._UNICORN_SESSIONS[8192] = UnicornSession()
    b.active_instances[8192] = {"url": "http://localhost:8192"}   # satisfy _get_instance_port
    try:
        # call the undecorated function to inspect the raw dict
        result = b.unicorn_map.__wrapped__("0x140070000", 0x2000, port=8192)
        assert result["success"] is True
        session = b._UNICORN_SESSIONS[8192]
        assert session.read_memory(0x140070000, 8) == b"\x00" * 8   # mapped + zeroed
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_apply_default_stack_maps_and_points_rsp():
    pytest.importorskip("unicorn")
    from ghydra.dynamic.unicorn_engine import UnicornSession
    from bridge_mcp_hydra import _apply_default_stack
    s = UnicornSession()
    base, size = _apply_default_stack(s)
    rsp = s.get_register("RSP")
    assert base <= rsp < base + size
    assert s.get_register("RBP") == rsp
    assert s.read_memory(rsp - 8, 8) == b"\x00" * 8   # stack is mapped + zeroed


def test_unicorn_registry_has_a_lock():
    import bridge_mcp_hydra as b
    from threading import Lock
    assert isinstance(b._unicorn_lock, type(Lock()))


def test_unicorn_run_sends_watch_params_and_formats_watchhit(monkeypatch):
    import bridge_mcp_hydra as b
    import json
    captured = {}

    def mock_run(self, **kwargs):
        captured.update(kwargs)
        return {"pc": 0x140076000, "steps": 5, "stop_reason": "WATCHPOINT", "last_error": None,
                "registers": {"RIP": 0x140076000}, "trace": [], "mem_writes": [],
                "watch_hit": {"address": 0x223018, "size": 4, "value": 0x41, "pc": 0x140076000}}

    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "_get_unicorn_session", lambda p: type("MockSession", (), {
        "get_register": lambda s, r: 0x140075000, "run": mock_run})())

    res = b.unicorn_run.__wrapped__(until="0x140076000", watch_address="0x223018", watch_length=4)
    assert captured["watch_start"] == 0x223018
    assert captured["watch_length"] == 4
    assert res["success"] is True
    assert res["stop_reason"] == "WATCHPOINT"
    assert res["watch_hit"]["address"] == "0x223018"


def test_unicorn_win64_scaffold_maps_and_populates_gs(monkeypatch):
    import bridge_mcp_hydra as b
    import json
    captured = {}
    class MockSession:
        def map_bytes(self, addr, data):
            captured[addr] = data
        def set_register(self, reg, val):
            captured[reg] = val
        def region_is_mapped(self, addr, length):
            return False

    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "_get_unicorn_session", lambda p: MockSession())

    res = b.unicorn_win64_scaffold.__wrapped__(image_base="0x140000000")
    assert res["success"] is True

    peb_base = int(res["peb_address"], 16)
    
    assert peb_base in captured
    assert peb_base + 0x1000 in captured
    assert peb_base + 0x2000 in captured

    peb_bytes = captured[peb_base]
    assert peb_bytes[2] == 1
    assert peb_bytes[3] == 0
    assert int.from_bytes(peb_bytes[0x10:0x18], "little") == 0x140000000
    assert int.from_bytes(peb_bytes[0x18:0x20], "little") == peb_base + 0x2000
    assert int.from_bytes(peb_bytes[0x20:0x28], "little") == peb_base + 0x3000
    
    teb_bytes = captured[peb_base + 0x1000]
    assert int.from_bytes(teb_bytes[0x30:0x38], "little") == peb_base + 0x1000
    assert int.from_bytes(teb_bytes[0x60:0x68], "little") == peb_base
    
    ldr_bytes = captured[peb_base + 0x2000]
    assert ldr_bytes[0x0:0x4] == b"\x58\x00\x00\x00"
    assert ldr_bytes[0x4] == 1
    head_addr = peb_base + 0x2000 + 0x10
    assert int.from_bytes(ldr_bytes[0x10:0x18], "little") == head_addr

    assert captured["GS_BASE"] == peb_base + 0x1000


def test_region_is_mapped_detects_overlap():
    pytest.importorskip("unicorn")
    from ghydra.dynamic.unicorn_engine import UnicornSession
    s = UnicornSession()
    assert s.region_is_mapped(0x7ffd0000, 0x4000) is False
    s.map_bytes(0x7ffd0000, b"\x00" * 0x10)
    assert s.region_is_mapped(0x7ffd0000, 0x4000) is True


def test_win64_scaffold_rejects_when_region_already_mapped():
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    s = UnicornSession()
    s.map_bytes(0x7ffd0000, b"\x00" * 0x10)          # collide with the scaffold's PEB base
    b._UNICORN_SESSIONS[8192] = s
    b.active_instances[8192] = {"url": "http://localhost:8192"}
    try:
        res = b.unicorn_win64_scaffold.__wrapped__(image_base="0x140000000", port=8192)
        assert res["success"] is False
        assert res["error"]["code"] == "REGION_IN_USE"
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_win64_scaffold_maps_process_parameters_page(monkeypatch):
    import bridge_mcp_hydra as b
    captured = {}
    class MockSession:
        def map_bytes(self, addr, data):
            captured[addr] = data
        def set_register(self, reg, val):
            captured[reg] = val
        def region_is_mapped(self, addr, length):
            return False

    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "_get_unicorn_session", lambda p: MockSession())

    res = b.unicorn_win64_scaffold.__wrapped__(image_base="0x140000000")
    peb_base = int(res["peb_address"], 16)
    params_ptr = int.from_bytes(captured[peb_base][0x20:0x28], "little")
    # The ProcessParameters pointer must resolve to a page the scaffold actually mapped.
    assert params_ptr == peb_base + 0x3000
    assert params_ptr in captured                       # page is mapped, not dangling
    assert res["params_address"] == hex(peb_base + 0x3000)


def test_watchpoint_without_watch_hit_does_not_crash():
    state = {"pc": 0x1000, "steps": 3, "stop_reason": "WATCHPOINT", "last_error": None,
             "registers": {"RIP": 0x1000}, "trace": [], "mem_writes": [], "watch_hit": None}
    r = _unicorn_run_result(state)
    assert r["success"] is True
    assert r["stop_reason"] == "WATCHPOINT"
    assert r.get("watch_hit") is None          # omitted/None, but no exception

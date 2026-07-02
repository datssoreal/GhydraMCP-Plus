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
        def mark_scratch(self, base, size):
            captured[("scratch", base)] = size

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


def test_import_error_for_missing_unicorn_blames_unicorn():
    from bridge_mcp_hydra import _unicorn_import_error
    r = _unicorn_import_error(ModuleNotFoundError("No module named 'unicorn'", name="unicorn"))
    assert r["success"] is False
    assert "unicorn not installed" in r["error"]["message"]
    assert "ghydramcp[unicorn]" in r["error"]["message"]


def test_import_error_for_missing_ghydra_names_ghydra_not_unicorn():
    from bridge_mcp_hydra import _unicorn_import_error
    # The whole client package is absent from this interpreter; the message must
    # not misdirect the user to `pip install unicorn`.
    r = _unicorn_import_error(ModuleNotFoundError("No module named 'ghydra'", name="ghydra"))
    assert r["success"] is False
    assert "cannot import 'ghydra'" in r["error"]["message"]
    assert "unicorn not installed" not in r["error"]["message"]
    assert "pip install -e .[unicorn]" in r["error"]["message"]


def test_import_error_uses_submodule_top_level_name():
    from bridge_mcp_hydra import _unicorn_import_error
    # ModuleNotFoundError.name is the top-level module; a failed
    # `ghydra.dynamic.unicorn_engine` import reports name='ghydra'.
    r = _unicorn_import_error(ModuleNotFoundError("boom", name="ghydra.dynamic.unicorn_engine"))
    assert "cannot import 'ghydra'" in r["error"]["message"]


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
        def mark_scratch(self, base, size):
            captured[("scratch", base)] = size

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


def _state_full(stop, **extra):
    base = {"pc": 0x2000, "steps": 5000, "stop_reason": stop, "last_error": None,
            "registers": {"RIP": 0x2000, "RAX": 0x0}, "trace": [], "mem_writes": [],
            "watch_hit": None, "oep": None, "no_progress": None}
    base.update(extra)
    return base


def test_oep_result_is_success_with_payload():
    r = _unicorn_run_result(_state_full("OEP", oep=0x2000))
    assert r["success"] is True
    assert r["oep"] == {"pc": "0x2000"}
    assert r["registers"]["RAX"] == "0x0"


def test_no_progress_result_hex_formats_payload():
    np = {"kind": "polling", "pc": 0x140001045,
          "loop_pcs": [0x140001040, 0x140001044], "reads_from": [0x7ffdf000],
          "register_delta": {"RCX": (0x5, 0x6)}}
    r = _unicorn_run_result(_state_full("NO_PROGRESS", no_progress=np))
    assert r["success"] is True
    assert r["no_progress"]["kind"] == "polling"
    assert r["no_progress"]["pc"] == "0x140001045"
    assert r["no_progress"]["loop_pcs"] == ["0x140001040", "0x140001044"]
    assert r["no_progress"]["reads_from"] == ["0x7ffdf000"]
    assert r["no_progress"]["register_delta"] == {"RCX": ["0x5", "0x6"]}


def test_unicorn_run_rejects_oep_without_tracking(monkeypatch):
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    b._UNICORN_SESSIONS[8192] = UnicornSession(track_dirty=False)
    b.active_instances[8192] = {"url": "http://localhost:8192"}
    try:
        r = b.unicorn_run.__wrapped__("0x0", stop_on=["oep"], port=8192)
        assert r["success"] is False
        assert r["error"]["code"] == "OEP_NEEDS_TRACKING"
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_create_block_helper_posts_expected_payload(monkeypatch):
    import bridge_mcp_hydra as b
    captured = {}

    def fake_post(port, path, body):
        captured["path"] = path
        captured["body"] = body
        return {"success": True, "result": {"name": body["name"]}}

    monkeypatch.setattr(b, "safe_post", fake_post)
    out = b._post_create_block(8192, "unpacked_0", "0x140000000", 4096, "9090")
    assert captured["path"] == "programs/current/memory/blocks"
    assert captured["body"] == {"name": "unpacked_0", "address": "0x140000000",
                                "size": 4096, "hex": "9090", "permissions": "rwx"}
    assert out["success"] is True


def test_disassemble_commit_helper_posts_length(monkeypatch):
    import bridge_mcp_hydra as b
    captured = {}
    monkeypatch.setattr(b, "safe_post",
                        lambda port, path, body: captured.update(path=path, body=body) or {"success": True})
    b._post_disassemble_commit(8192, "0x140000000", 32)
    assert captured["path"] == "programs/current/memory/0x140000000/disassemble"
    assert captured["body"] == {"length": 32}


def _sync_setup(monkeypatch, executed_pages):
    pytest.importorskip("unicorn")
    import bridge_mcp_hydra as b
    from ghydra.dynamic.unicorn_engine import UnicornSession
    s = UnicornSession()
    # map + write two pages: 0x140000000 (in-segment) and 0x30000000 (executed heap)
    s.map_bytes(0x140000000, b"\x90" * 0x1000)
    s.map_bytes(0x30000000, b"\xcc" * 0x1000)
    s.written_pages.update({0x140000000, 0x30000000})
    s.executed_pages.update(executed_pages)
    b._UNICORN_SESSIONS[8192] = s
    b.active_instances[8192] = {"url": "http://localhost:8192"}

    calls = {"patched": [], "created": [], "disasm": []}
    monkeypatch.setattr(b, "safe_get", lambda port, path: {"success": True, "result": [
        {"start": "0x140000000", "end": "0x140010000"}]})
    monkeypatch.setattr(b, "safe_patch",
                        lambda port, path, body: calls["patched"].append((path, body)) or {"success": True})
    monkeypatch.setattr(b, "_post_create_block",
                        lambda *a: calls["created"].append(a) or {"success": True, "result": {"name": "unpacked_0"}})
    monkeypatch.setattr(b, "_post_disassemble_commit",
                        lambda *a: calls["disasm"].append(a) or {"success": True})
    return b, calls


def test_sync_writes_in_segment_and_creates_block_for_executed_heap(monkeypatch):
    b, calls = _sync_setup(monkeypatch, executed_pages={0x30000000})
    try:
        r = b.unicorn_sync_to_program.__wrapped__(port=8192)
        assert r["success"] is True
        # in-segment page -> patched; heap page -> created block
        assert any("0x140000000" in p for p, _ in calls["patched"])
        assert len(calls["created"]) == 1
        starts = {item["start"] for item in r["synced"]}
        assert "0x140000000" in starts and "0x30000000" in starts
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_sync_skips_out_of_segment_unexecuted_heap(monkeypatch):
    b, calls = _sync_setup(monkeypatch, executed_pages=set())   # heap NOT executed
    try:
        r = b.unicorn_sync_to_program.__wrapped__(port=8192)
        assert len(calls["created"]) == 0
        assert any(item["start"] == "0x30000000" for item in r["skipped"])
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)


def test_sync_isolates_a_failing_region_from_the_rest(monkeypatch):
    # heap page (0x30000000) is executed -> would normally get a fresh block via
    # _post_create_block; make that call raise (simulating a transient HTTP failure)
    # and confirm the in-segment page (0x140000000) still syncs successfully in the
    # same call, and the failing region is recorded in "skipped" instead of crashing
    # the whole loop.
    b, calls = _sync_setup(monkeypatch, executed_pages={0x30000000})
    try:
        def raising_create_block(*a):
            calls["created"].append(a)
            raise RuntimeError("connection reset by peer")

        monkeypatch.setattr(b, "_post_create_block", raising_create_block)

        r = b.unicorn_sync_to_program.__wrapped__(port=8192)

        assert r["success"] is True   # tool call itself doesn't crash/propagate
        assert len(calls["created"]) == 1   # the failing call was attempted

        skipped_starts = {item["start"]: item for item in r["skipped"]}
        assert "0x30000000" in skipped_starts
        assert "sync failed" in skipped_starts["0x30000000"]["reason"]
        assert "connection reset by peer" in skipped_starts["0x30000000"]["reason"]

        synced_starts = {item["start"] for item in r["synced"]}
        assert "0x140000000" in synced_starts   # other region still synced
        assert "0x30000000" not in synced_starts
    finally:
        b._UNICORN_SESSIONS.pop(8192, None)
        b.active_instances.pop(8192, None)

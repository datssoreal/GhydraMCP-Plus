# tests/test_bridge_emulation_watch.py
"""Offline tests for emulation_reset/emulation_run wiring (auto_stack, watchpoints)."""

import bridge_mcp_hydra as b


def test_emulation_reset_sends_auto_stack_by_default(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "READY", "steps": 0,
                                     "registers": {}}, "timestamp": 1})

    b.emulation_reset("0x1000")

    assert captured.get("auto_stack") is True


def test_emulation_reset_auto_stack_can_be_disabled(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "READY", "steps": 0,
                                     "registers": {}}, "timestamp": 1})

    b.emulation_reset("0x1000", auto_stack=False)

    assert captured.get("auto_stack") is False


def test_emulation_run_sends_watch_params_when_given(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "WATCHPOINT", "steps": 3,
                                     "registers": {}, "watchHit": {"address": "0x223018"}},
        "timestamp": 1})

    b.emulation_run(watch_address="0x223018", watch_length=4)

    assert captured["watch_address"] == "0x223018"
    assert captured["watch_length"] == 4


def test_emulation_run_omits_watch_params_by_default(monkeypatch):
    captured = {}
    monkeypatch.setattr(b, "_get_instance_port", lambda p=None: 8192)
    monkeypatch.setattr(b, "safe_post", lambda port, ep, body: captured.update(body) or {
        "success": True, "result": {"pc": "0x1000", "stopReason": "MAX_STEPS", "steps": 100,
                                     "registers": {}}, "timestamp": 1})

    b.emulation_run()

    assert "watch_address" not in captured

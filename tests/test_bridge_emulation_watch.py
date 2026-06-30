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

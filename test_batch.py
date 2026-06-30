#!/usr/bin/env python3
"""Live integration tests for the POST /batch pipeline.

Requires a running Ghidra instance with the GhydraMCP plugin loaded and a
program open on the default port (8192). Auto-skips when no instance is
reachable, mirroring the other root-level integration tests.
"""
import unittest, requests

BASE = "http://localhost:8192"


def _alive():
    try:
        return requests.get(f"{BASE}/instances", timeout=2).ok
    except Exception:
        return False


@unittest.skipUnless(_alive(), "No live Ghidra instance on :8192")
class BatchTests(unittest.TestCase):

    def test_best_effort_mixed_batch(self):
        # one valid list + one rename to a bad address (best-effort: failures isolated)
        body = {"atomic": False, "requests": [
            {"method": "GET",   "path": "/functions"},
            {"method": "PATCH", "path": "/functions/0xdeadbeef", "body": {"name": "x"}},  # bad addr -> 4xx
        ]}
        r = requests.post(f"{BASE}/batch", json=body, timeout=60).json()
        self.assertTrue(r["success"])
        results = r["result"]
        self.assertEqual(results[0]["status"], 200)
        self.assertFalse(results[1]["success"])
        self.assertGreaterEqual(results[1]["status"], 400)

    def test_atomic_rollback_reverts_first_success(self):
        # Pick the first real function, rename it, then force a failure in the same atomic batch.
        fns = requests.get(f"{BASE}/functions?limit=1", timeout=30).json()["result"]
        if not fns:
            self.skipTest("no functions in program")
        addr = fns[0]["address"]
        original = fns[0]["name"]
        body = {"atomic": True, "requests": [
            {"method": "PATCH", "path": f"/functions/{addr}", "body": {"name": "batch_atomic_probe"}},
            {"method": "PATCH", "path": "/functions/0xdeadbeef", "body": {"name": "y"}},  # fails -> rollback
        ]}
        r = requests.post(f"{BASE}/batch", json=body, timeout=60).json()
        self.assertFalse(r["result"][0]["success"] and r["result"][1]["success"])
        # Verify the first rename was rolled back:
        after = requests.get(f"{BASE}/functions/{addr}", timeout=30).json()["result"]
        self.assertEqual(after["name"], original)


if __name__ == "__main__":
    unittest.main()

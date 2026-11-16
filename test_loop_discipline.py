"""
Offline unit tests for the P1 loop-discipline additions in agent_core.run_agent.

No Docker, no Ollama, no API key, no network: `requests.post` and the
`execute_tool` dispatcher are both mocked. The scripted "model" returns a fixed
queue of assistant messages so we can assert how the harness reacts.

Run:  python3 -m unittest -v test_loop_discipline
"""
import json
import os
import tempfile
import unittest
from collections import Counter, deque
from pathlib import Path

import agent_core


# ---- minimal tool schemas (subset of the real tools.json) -------------------
TOOLS = [
    {"type": "function", "function": {"name": "run_command",
        "parameters": {"type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"]}}},
    {"type": "function", "function": {"name": "run_python",
        "parameters": {"type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"]}}},
    {"type": "function", "function": {"name": "read_file",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]}}},
    {"type": "function", "function": {"name": "inspect_binary",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"]}}},
    {"type": "function", "function": {"name": "disassemble_binary",
        "parameters": {"type": "object",
            "properties": {"path": {"type": "string"},
                           "start_address": {"type": "string"},
                           "stop_address": {"type": "string"}},
            "required": ["path", "start_address", "stop_address"]}}},
    {"type": "function", "function": {"name": "submit_flag",
        "parameters": {"type": "object",
            "properties": {"flag": {"type": "string"}},
            "required": ["flag"]}}},
    {"type": "function", "function": {"name": "finish",
        "parameters": {"type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"]}}},
]


def tool_call(name, **args):
    return {"function": {"name": name, "arguments": args}}


def assistant(*calls, content=""):
    return {"role": "assistant", "content": content,
            "tool_calls": list(calls) if calls else None}


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class ScriptedModel:
    """Pops the next scripted assistant message on each POST."""
    def __init__(self, script):
        self.queue = deque(script)
        self.calls = 0

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls += 1
        if self.queue:
            msg = self.queue.popleft()
        else:  # safety: end cleanly if the script runs dry
            msg = assistant(tool_call("finish", reason="script exhausted"))
        return FakeResp({"message": msg,
                         "prompt_eval_count": 10, "eval_count": 5})


class RecordingDispatcher:
    """Stands in for controller.ToolDispatcher. Records every execution."""
    def __init__(self, correct_flag="FLAG{correct}"):
        self.executions = Counter()
        self.correct_flag = correct_flag

    def __call__(self, name, args, timeout_s=10):
        self.executions[name] += 1
        if name == "submit_flag":
            return {"verified": args.get("flag") == self.correct_flag}
        if name == "finish":
            return {"finished": True, "reason": args.get("reason", "")}
        if name == "list_files":
            return {"ok": True, "files": [], "stdout": ""}
        if name == "extract_stack_constants":
            return {"blocks": [{"hex_bytes": " c9d9"}], "assignment_count": 2}
        return {"exit_code": 0, "stdout": "ok", "timed_out": False}


class LoopDisciplineTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._orig_log = agent_core.LOG_DIR
        self._orig_requests = agent_core.requests
        agent_core.LOG_DIR = Path(self._tmp.name)

    def tearDown(self):
        agent_core.LOG_DIR = self._orig_log
        agent_core.requests = self._orig_requests
        self._tmp.cleanup()
        for key in ("CTF_REPEAT_LIMIT", "CTF_TRANSITION_AT",
                    "CTF_RECON_HARD_CAP"):
            os.environ.pop(key, None)

    def _run(self, script, *, challenge_id="test-misc", max_steps=15,
             max_seconds=120, correct_flag="FLAG{correct}"):
        model = ScriptedModel(script)
        disp = RecordingDispatcher(correct_flag=correct_flag)

        class _Shim:
            exceptions = self._orig_requests.exceptions
            def post(self, *a, **k):
                return model.post(*a, **k)
        agent_core.requests = _Shim()

        summary = agent_core.run_agent(
            challenge_id=challenge_id,
            description="offline test",
            files=["/challenge/bin"],
            execute_tool=disp,
            api_key="dummy",
            tools=TOOLS,
            max_steps=max_steps,
            max_seconds=max_seconds,
        )
        events = [json.loads(l) for l in
                  Path(summary["trace_file"]).read_text().splitlines() if l]
        return summary, disp, events

    def _types(self, events):
        return Counter(e.get("type") for e in events)

    # ---- Test 1: exact-repeat short-circuit --------------------------------
    def test_identical_calls_are_short_circuited(self):
        script = [assistant(tool_call("inspect_binary", path="/challenge/bin"))
                  for _ in range(5)]
        script.append(assistant(tool_call("finish", reason="done")))
        summary, disp, events = self._run(script)

        # repeat_limit default 2 -> first two execute, next three skipped.
        self.assertEqual(disp.executions["inspect_binary"], 2)
        self.assertEqual(summary["short_circuits"], 3)
        self.assertEqual(self._types(events)["tool_skipped"], 3)
        self.assertEqual(summary["status"], "finished")

    # ---- Test 2: consecutive-recon hard cap (distinct args) ----------------
    def test_recon_hard_cap_blocks_endless_investigation(self):
        # 10 DISTINCT disassemble ranges: repeat detection cannot catch these;
        # only the recon hard cap (default 8) can.
        script = []
        for i in range(10):
            script.append(assistant(tool_call(
                "disassemble_binary", path="/challenge/bin",
                start_address=hex(0x1000 + i * 0x10),
                stop_address=hex(0x1000 + i * 0x10 + 0x8))))
        script.append(assistant(tool_call("finish", reason="done")))
        summary, disp, events = self._run(script, max_steps=20)

        self.assertEqual(disp.executions["disassemble_binary"], 8)
        self.assertEqual(summary["short_circuits"], 2)
        # transition nudge should have fired once at the 5th consecutive recon
        self.assertGreaterEqual(self._types(events)["transition_nudge"], 1)

    # ---- Test 3: clean short solve is completely untouched -----------------
    def test_clean_solve_is_not_interfered_with(self):
        script = [
            assistant(tool_call("read_file", path="/challenge/readme.txt")),
            assistant(tool_call("run_command", command="strings bin")),
            assistant(tool_call("run_python", code="print('FLAG{correct}')")),
            assistant(tool_call("submit_flag", flag="FLAG{correct}")),
        ]
        summary, disp, events = self._run(script)

        self.assertEqual(summary["status"], "verified")
        self.assertTrue(summary["verified"])
        self.assertEqual(summary["short_circuits"], 0)
        self.assertEqual(summary["transition_nudges"], 0)
        self.assertEqual(self._types(events)["tool_skipped"], 0)
        self.assertEqual(self._types(events)["budget_escalation"], 0)

    # ---- Test 4: budget escalation announces thresholds --------------------
    def test_budget_escalation_fires(self):
        # Distinct neutral run_commands: no repeat, no recon cap; the run
        # simply drains the budget so all thresholds are crossed.
        script = [assistant(tool_call("run_command", command=f"echo {i}"))
                  for i in range(12)]
        summary, disp, events = self._run(script, max_steps=8)

        directives = [e["directive"] for e in events
                      if e.get("type") == "budget_escalation"]
        joined = " ".join(directives)
        self.assertIn("half the tool-call budget", joined)
        self.assertIn("move to validation", joined)
        self.assertIn("final action", joined)
        self.assertEqual(summary["status"], "budget_exhausted")

    # ---- Test 5: submit_flag / finish are never short-circuited ------------
    def test_submit_flag_is_never_skipped(self):
        # Three identical wrong submissions must all execute (never skipped),
        # proving a real solve can always land.
        script = [
            assistant(tool_call("submit_flag", flag="FLAG{wrong}")),
            assistant(tool_call("submit_flag", flag="FLAG{wrong}")),
            assistant(tool_call("submit_flag", flag="FLAG{wrong}")),
            assistant(tool_call("submit_flag", flag="FLAG{correct}")),
        ]
        summary, disp, events = self._run(script)
        self.assertEqual(disp.executions["submit_flag"], 4)
        self.assertEqual(summary["status"], "verified")
        self.assertEqual(self._types(events)["tool_skipped"], 0)

    # ---- Test 6: env overrides are honoured --------------------------------
    def test_repeat_limit_env_override(self):
        os.environ["CTF_REPEAT_LIMIT"] = "1"  # block on the 2nd identical call
        script = [assistant(tool_call("inspect_binary", path="/challenge/bin"))
                  for _ in range(3)]
        script.append(assistant(tool_call("finish", reason="done")))
        summary, disp, events = self._run(script)
        self.assertEqual(disp.executions["inspect_binary"], 1)
        self.assertEqual(summary["short_circuits"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

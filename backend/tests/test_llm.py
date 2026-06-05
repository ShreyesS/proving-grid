"""M2: the LLM brain plumbing — verified with a network-free fake client.

No real API calls. We inject a fake Anthropic client that returns canned
tool_use responses, so we can test message threading, action extraction, the
findings artifact, and graceful failure without a key or network.
"""
import asyncio

import pytest

from attacker import run_attack
from llm import LLMBrain, has_api_key, make_brain
from twin import load_twin


# --- fake Anthropic client ------------------------------------------------

class FakeBlock:
    def __init__(self, type, text=None, name=None, input=None, id=None):
        self.type = type
        self.text = text
        self.name = name
        self.input = input
        self.id = id


class FakeResponse:
    def __init__(self, content):
        self.content = content


def _tool_turn(thought, name, args, tid):
    return FakeResponse([
        FakeBlock("text", text=thought),
        FakeBlock("tool_use", name=name, input=args, id=tid),
    ])


# Canned Path A: scan -> exploit -> lateral x2 -> loot -> lateral(cred) -> exfil.
PATH_A_SCRIPT = [
    _tool_turn("Recon the edge.", "scan", {"from_node": "internet"}, "t1"),
    _tool_turn("Initial access.", "exploit", {"target": "cdn_edge"}, "t2"),
    _tool_turn("Pivot in.", "lateral_move", {"from_node": "cdn_edge", "target": "load_balancer"}, "t3"),
    _tool_turn("To the app tier.", "lateral_move", {"from_node": "load_balancer", "target": "app_server"}, "t4"),
    _tool_turn("Grab the cred.", "loot", {"node": "app_server"}, "t5"),
    _tool_turn("Shortcut to DB.", "lateral_move", {"from_node": "app_server", "target": "db_server"}, "t6"),
    _tool_turn("Exfiltrate.", "exfiltrate", {"node": "db_server"}, "t7"),
]


class FakeMessages:
    def __init__(self, script):
        self.script = script
        self.i = 0
        self.seen_last = []  # the last message present on each create() call

    def create(self, **kwargs):
        self.seen_last.append(kwargs["messages"][-1])
        resp = self.script[self.i]
        self.i += 1
        return resp


class FakeClient:
    def __init__(self, script):
        self.messages = FakeMessages(script)


def _run(decide):
    twin = load_twin()
    events = []

    async def emit(msg):
        events.append(msg)

    outcome = asyncio.run(run_attack(twin, decide, emit, step_delay=0))
    return outcome, events, twin


# --- tests ----------------------------------------------------------------

def test_llm_brain_reaches_goal_via_tool_use():
    brain = LLMBrain(client=FakeClient(PATH_A_SCRIPT))
    outcome, events, twin = _run(brain.decide)
    assert outcome == "goal"
    assert twin.is_goal_reached()


def test_llm_brain_threads_tool_results_with_ids():
    client = FakeClient(PATH_A_SCRIPT)
    _run(LLMBrain(client=client).decide)
    seen = client.messages.seen_last
    # First turn: a plain user perception string (no prior tool to report).
    assert isinstance(seen[0]["content"], str)
    # Second turn: a tool_result referencing the first tool_use id.
    block = seen[1]["content"][0]
    assert block["type"] == "tool_result"
    assert block["tool_use_id"] == "t1"


def test_findings_artifact_emitted_at_run_end():
    _outcome, events, _twin = _run(LLMBrain(client=FakeClient(PATH_A_SCRIPT)).decide)
    end = events[-1]
    assert end["type"] == "run_end"
    f = end["payload"]
    assert f["reached_goal"] is True
    # The chained exposures include the entry CVE, the looted cred, and the data.
    assert "EDGE-ORIGIN-SSRF" in f["exposures_chained"]
    assert "db_service_cred" in f["exposures_chained"]
    # The path is the ordered chain ending at the crown jewel.
    assert f["path"][-1]["target"] == "db_server"
    assert f["path"][-1]["technique"] == "exfiltration"


def test_brain_error_does_not_crash_run():
    class BoomClient:
        class messages:
            @staticmethod
            def create(**kwargs):
                raise RuntimeError("api exploded")

    outcome, events, _twin = _run(LLMBrain(client=BoomClient()).decide)
    assert outcome == "error"
    assert any(e["type"] == "reasoning" and "brain error" in e["payload"]["text"]
               for e in events)


def test_make_brain_falls_back_to_scripted_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert has_api_key() is False
    decide = make_brain("auto")
    # Scripted brain's first action is a scan from the internet foothold.
    action = decide({}, load_twin())
    assert action["tool"] == "scan" and action["args"]["from_node"] == "internet"

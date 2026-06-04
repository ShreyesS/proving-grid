"""M1: the bounded attacker loop walks Path A to the goal and streams events."""
import asyncio

from attacker import run_attack, scripted_path_a
from twin import load_twin


def _run(decide, **kw):
    """Drive run_attack, collecting every emitted message."""
    twin = load_twin()
    events: list[dict] = []

    async def emit(msg):
        events.append(msg)

    outcome = asyncio.run(run_attack(twin, decide, emit, step_delay=0, **kw))
    return outcome, events, twin


def test_scripted_run_reaches_goal():
    outcome, events, twin = _run(scripted_path_a())
    assert outcome == "goal"
    assert twin.is_goal_reached()
    assert twin.is_compromised("db_server")
    # Defenderless run: the crown jewel falls, integrity bottoms out.
    assert twin.get_mission_integrity() == 0.0


def test_run_streams_state_and_reasoning_and_end():
    _outcome, events, _twin = _run(scripted_path_a())
    types = [e["type"] for e in events]
    assert types[0] == "state"          # initial snapshot
    assert "reasoning" in types
    assert types[-1] == "run_end"
    # Every reasoning line carries human-readable text for the UI panel.
    reasoning = [e for e in events if e["type"] == "reasoning"]
    assert all(r["payload"]["text"] for r in reasoning)
    assert reasoning[-1]["payload"]["technique"] == "exfiltration"


def test_run_is_bounded_by_max_steps():
    # A brain that never stops and never reaches goal must still terminate.
    def forever(_perception, _twin):
        return {"tool": "scan", "args": {"from_node": "internet"},
                "thought": "loop forever"}

    outcome, events, _twin = _run(forever, max_steps=5)
    assert outcome == "step_cap"
    assert events[-1]["payload"]["steps"] == 5


def test_tool_error_does_not_crash_run():
    # Bad args should degrade into a not-ok reasoning line, not an exception.
    def bad_then_stop(_perception, _twin):
        if not getattr(bad_then_stop, "done", False):
            bad_then_stop.done = True
            return {"tool": "lateral_move", "args": {"from_node": "internet"},
                    "thought": "missing target arg"}
        return None

    outcome, events, _twin = _run(bad_then_stop)
    reasoning = [e for e in events if e["type"] == "reasoning"]
    assert reasoning and reasoning[0]["payload"]["ok"] is False
    assert outcome in ("blocked", "goal")

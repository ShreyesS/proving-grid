"""M2: the LLM brain plumbing — verified with a network-free fake client.

No real API calls. We inject a fake async Anthropic client that streams canned
tool_use responses, so we can test token streaming, message threading, action
extraction, the findings artifact, and graceful failure without a key or network.
"""
import asyncio

from attacker import run_attack
from llm import LLMBrain, has_api_key, make_brain
from twin import load_twin


# --- fake async Anthropic client ------------------------------------------

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


PATH_A_SCRIPT = [
    _tool_turn("Recon the edge.", "scan", {"from_node": "internet"}, "t1"),
    _tool_turn("Initial access.", "exploit", {"target": "cdn_edge"}, "t2"),
    _tool_turn("Exploit the LB.", "exploit", {"target": "load_balancer"}, "t3"),
    _tool_turn("Exploit the firewall.", "exploit", {"target": "firewall"}, "t4"),
    _tool_turn("Trust into the app tier.", "lateral_move", {"from_node": "firewall", "target": "app_server"}, "t5"),
    _tool_turn("Grab the cred.", "loot", {"node": "app_server"}, "t6"),
    _tool_turn("Escalate to cross.", "escalate", {"node": "app_server"}, "t7"),
    _tool_turn("Shortcut to DB.", "lateral_move", {"from_node": "app_server", "target": "db_server"}, "t8"),
    _tool_turn("Root for exfil.", "escalate", {"node": "db_server"}, "t9"),
    _tool_turn("Exfiltrate.", "exfiltrate", {"node": "db_server"}, "t10"),
]


class FakeStream:
    """Mimics the async streaming context manager: text_stream + get_final_message."""
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    @property
    def text_stream(self):
        async def gen():
            for b in self.response.content:
                if b.type == "text":
                    for word in b.text.split():
                        yield word + " "
        return gen()

    async def get_final_message(self):
        return self.response


class FakeAsyncMessages:
    def __init__(self, script):
        self.script = script
        self.i = 0
        self.seen_last = []  # the last message present on each stream() call

    def stream(self, **kwargs):
        self.seen_last.append(kwargs["messages"][-1])
        resp = self.script[self.i]
        self.i += 1
        return FakeStream(resp)


class FakeAsyncClient:
    def __init__(self, script):
        self.messages = FakeAsyncMessages(script)


def _run(decide):
    twin = load_twin()
    events = []

    async def emit(msg):
        events.append(msg)

    outcome = asyncio.run(run_attack(twin, decide, emit, step_delay=0))
    return outcome, events, twin


# --- tests ----------------------------------------------------------------

def test_llm_brain_reaches_goal_via_tool_use():
    brain = LLMBrain(client=FakeAsyncClient(PATH_A_SCRIPT))
    outcome, events, twin = _run(brain.decide)
    assert outcome == "goal"
    assert twin.is_goal_reached()


def test_reasoning_tokens_are_streamed():
    _outcome, events, _twin = _run(LLMBrain(client=FakeAsyncClient(PATH_A_SCRIPT)).decide)
    deltas = [e for e in events if e["type"] == "reasoning_delta"]
    assert deltas, "expected streamed reasoning tokens"
    # Tokens carry the step they belong to and a text chunk.
    assert deltas[0]["payload"]["step"] == 1
    assert deltas[0]["payload"]["chunk"]


def test_llm_brain_threads_tool_results_with_ids():
    client = FakeAsyncClient(PATH_A_SCRIPT)
    _run(LLMBrain(client=client).decide)
    seen = client.messages.seen_last
    assert isinstance(seen[0]["content"], str)               # first turn: perception string
    block = seen[1]["content"][0]
    assert block["type"] == "tool_result"
    assert block["tool_use_id"] == "t1"                      # threaded back correctly


def test_findings_artifact_emitted_at_run_end():
    _outcome, events, _twin = _run(LLMBrain(client=FakeAsyncClient(PATH_A_SCRIPT)).decide)
    end = events[-1]
    assert end["type"] == "run_end"
    f = end["payload"]
    assert f["reached_goal"] is True
    assert "EDGE-ORIGIN-SSRF" in f["exposures_chained"]
    assert "db_service_cred" in f["exposures_chained"]
    assert f["path"][-1]["target"] == "db_server"
    assert f["path"][-1]["technique"] == "exfiltration"


def test_brain_error_does_not_crash_run():
    class BoomClient:
        class messages:
            @staticmethod
            def stream(**kwargs):
                raise RuntimeError("api exploded")

    outcome, events, _twin = _run(LLMBrain(client=BoomClient()).decide)
    assert outcome == "error"
    assert any(e["type"] == "reasoning" and "brain error" in e["payload"]["text"]
               for e in events)


def test_make_brain_falls_back_to_scripted_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert has_api_key() is False
    decide = make_brain("auto")
    action = asyncio.run(decide({}, load_twin(), None))
    assert action["tool"] == "scan" and action["args"]["from_node"] == "internet"

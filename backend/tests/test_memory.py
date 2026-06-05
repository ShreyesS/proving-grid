"""M4: cross-run memory + coverage/eval stats."""
import asyncio

from attacker import run_attack, scripted_path_a
from memory import RunMemory
from twin import load_twin


def _run_into(mem, defended=False):
    twin = load_twin()

    async def emit(_m):  # discard stream
        return None

    asyncio.run(run_attack(twin, scripted_path_a(), emit, step_delay=0,
                           defended=defended, memory=mem))


def test_memory_records_and_dedupes_paths():
    mem = RunMemory()
    _run_into(mem)           # scripted path A
    _run_into(mem)           # identical path again
    assert mem.stats()["total_runs"] == 2
    assert mem.stats()["distinct_paths"] == 1   # same chain -> one distinct path
    # the discovered chain ends at the crown jewel
    assert mem.path_summaries()[0].endswith("db_server") or "db_server" in mem.path_summaries()[0]


def test_memory_stats_track_contained_vs_breached():
    mem = RunMemory()
    _run_into(mem, defended=False)   # breaches (goal)
    _run_into(mem, defended=True)    # contained
    s = mem.stats()
    assert s["breached"] == 1
    assert s["contained"] == 1
    assert s["defended_runs"] == 1


def test_clear_resets():
    mem = RunMemory()
    _run_into(mem)
    mem.clear()
    assert mem.stats()["total_runs"] == 0

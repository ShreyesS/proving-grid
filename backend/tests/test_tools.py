"""M1: modeled attacker tools operate correctly on twin state."""
import pytest

import tools
from twin import load_twin


@pytest.fixture
def twin():
    t = load_twin()
    # Attacker starts on the internet (as the run loop establishes).
    t.set_compromised("internet")
    return t


def test_scan_requires_owned_node(twin):
    assert tools.scan(twin, "cdn_edge")["ok"] is False  # not owned yet
    res = tools.scan(twin, "internet")
    assert res["ok"] and "cdn_edge" in res["observation"]


def test_exploit_initial_access(twin):
    res = tools.exploit(twin, "cdn_edge")
    assert res["ok"] and twin.is_compromised("cdn_edge")
    assert twin.get_privilege("cdn_edge") == "user"


def test_exploit_patched_decoy_fails(twin):
    # staging_decoy is reachable from cdn_edge but fully patched.
    tools.exploit(twin, "cdn_edge")
    res = tools.exploit(twin, "staging_decoy")
    assert res["ok"] is False
    assert "patched" in res["error"]
    assert not twin.is_compromised("staging_decoy")


def test_exploit_unreachable_fails(twin):
    res = tools.exploit(twin, "db_server")  # not adjacent to any owned node
    assert res["ok"] is False and "not reachable" in res["error"]


def test_lateral_move_respects_credential_gate(twin):
    # Walk to app_server first (through the firewall, per the topology).
    tools.exploit(twin, "cdn_edge")
    tools.lateral_move(twin, "cdn_edge", "load_balancer")
    tools.lateral_move(twin, "load_balancer", "firewall")
    tools.lateral_move(twin, "firewall", "app_server")

    # The db_server hop is credential-gated; it fails before looting.
    blocked = tools.lateral_move(twin, "app_server", "db_server")
    assert blocked["ok"] is False and "db_service_cred" in blocked["error"]
    assert not twin.is_compromised("db_server")

    # Loot unlocks the credential gate...
    tools.loot(twin, "app_server")
    assert "db_service_cred" in twin.looted
    # ...but crossing into the corp zone still needs root (access-level gate).
    still_blocked = tools.lateral_move(twin, "app_server", "db_server")
    assert still_blocked["ok"] is False and "root" in still_blocked["error"]
    tools.escalate(twin, "app_server")
    opened = tools.lateral_move(twin, "app_server", "db_server")
    assert opened["ok"] and twin.is_compromised("db_server")


def test_exfiltrate_only_goal_node(twin):
    tools.exploit(twin, "cdn_edge")
    # Exfil requires an owned goal node.
    assert tools.exfiltrate(twin, "cdn_edge")["ok"] is False  # not the goal

    tools.lateral_move(twin, "cdn_edge", "load_balancer")
    tools.lateral_move(twin, "load_balancer", "firewall")
    tools.lateral_move(twin, "firewall", "app_server")
    tools.loot(twin, "app_server")
    tools.escalate(twin, "app_server")          # root needed to cross into corp
    tools.lateral_move(twin, "app_server", "db_server")
    # exfil needs root on the DB host — fails as user, succeeds after escalation.
    assert tools.exfiltrate(twin, "db_server")["ok"] is False
    tools.escalate(twin, "db_server")
    res = tools.exfiltrate(twin, "db_server")
    assert res["ok"] and twin.is_goal_reached()


def test_escalate(twin):
    tools.exploit(twin, "cdn_edge")
    assert tools.escalate(twin, "cdn_edge")["ok"]
    assert twin.get_privilege("cdn_edge") == "root"

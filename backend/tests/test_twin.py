"""M0 smoke tests: topology loads into the twin with the expected shape."""
from twin import Twin


def test_loads_expected_node_count():
    twin = Twin.from_yaml()
    # 8-12 nodes with branching (see topology.yaml).
    assert 8 <= twin.graph.number_of_nodes() <= 12


def test_entrypoint_starts_compromised():
    twin = Twin.from_yaml()
    assert twin.entrypoint == "internet"
    assert twin.node("internet")["state"]["compromised"] is True


def test_goal_node_present_and_unreached():
    twin = Twin.from_yaml()
    assert twin.goal_node == "corp-db"
    assert twin.is_goal_reached() is False


def test_waf_vuln_is_patched_decoy():
    twin = Twin.from_yaml()
    vulns = twin.node("waf")["static"]["modeled_vulns"]
    assert any(v["patched"] for v in vulns), "waf should be a patched decoy"


def test_best_path_exists_alt_path_exists():
    twin = Twin.from_yaml()
    # Path A and Path B both reach the goal in the modeled topology.
    assert twin.path_exists("internet", "corp-db")
    assert twin.path_exists("web-app", "corp-db")     # via jump-host
    assert twin.path_exists("api-gateway", "corp-db")  # via file-server


def test_dead_end_has_no_route_to_goal():
    twin = Twin.from_yaml()
    # dev-workstation is a decoy: loot but no forward edge to corp-db.
    assert not twin.path_exists("dev-workstation", "corp-db")


def test_to_dict_serializes_nodes_and_edges():
    snap = Twin.from_yaml().to_dict()
    assert snap["meta"]["goal_node"] == "corp-db"
    assert len(snap["nodes"]) == 11
    assert all("state" in n for n in snap["nodes"])
    assert any(e.get("requires_cred") == "jumphost-cred" for e in snap["edges"])

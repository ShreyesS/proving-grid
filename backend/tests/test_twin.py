import pytest

from twin import NetworkTwin, load_twin


@pytest.fixture
def twin() -> NetworkTwin:
    return load_twin()


def test_loads_topology_nodes_and_edges(twin: NetworkTwin) -> None:
    assert twin.graph.number_of_nodes() == 13
    assert twin.graph.number_of_edges() == 17


def test_get_neighbors_bidirectional_over_active_edges(twin: NetworkTwin) -> None:
    assert twin.get_neighbors("cdn_edge") == [
        "cloud_vpc",
        "corp_vpn",
        "internet",
        "load_balancer",
        "staging_decoy",
    ]
    assert twin.get_neighbors("internet") == ["cdn_edge"]


def test_get_vulns_from_yaml(twin: NetworkTwin) -> None:
    vulns = twin.get_vulns("db_server")
    assert len(vulns) == 2
    assert vulns[0]["technique"] in ("credential_access", "exfiltration")


def test_compromise_state(twin: NetworkTwin) -> None:
    twin.set_compromised("app_server")
    assert twin.is_compromised("app_server")
    twin.set_compromised("app_server", False)
    assert not twin.is_compromised("app_server")


def test_isolation_cuts_neighbors(twin: NetworkTwin) -> None:
    twin.set_isolated("cdn_edge")
    assert twin.is_isolated("cdn_edge")
    assert twin.get_neighbors("cdn_edge") == []
    assert twin.get_neighbors("load_balancer") == ["cache_server", "firewall"]


def test_mission_integrity(twin: NetworkTwin) -> None:
    assert twin.get_mission_integrity() == 100.0
    twin.set_compromised("db_server")
    assert twin.get_mission_integrity() == 0.0
    twin.set_compromised("db_server", False)
    twin.set_exfiltrated("db_server")
    assert twin.get_mission_integrity() == 0.0


def test_to_dict_snapshot(twin: NetworkTwin) -> None:
    snapshot = twin.to_dict()
    assert snapshot["mission_integrity"] == 100.0
    assert len(snapshot["nodes"]) == 13
    assert len(snapshot["edges"]) == 17
    db = next(n for n in snapshot["nodes"] if n["id"] == "db_server")
    assert db["mission_critical"] is True


def test_unknown_node_raises(twin: NetworkTwin) -> None:
    with pytest.raises(KeyError):
        twin.get_neighbors("missing")


# --- depth: zones, criticality, decoys, credential shortcut -----------------

def test_zone_and_criticality_loaded(twin: NetworkTwin) -> None:
    snap = {n["id"]: n for n in twin.to_dict()["nodes"]}
    assert snap["db_server"]["zone"] == "corp"
    assert snap["db_server"]["criticality"] == 100
    assert snap["load_balancer"]["criticality"] == 85  # costly to isolate
    assert {n["zone"] for n in snap.values()} == {"external", "edge", "dmz", "corp"}


def test_patched_node_is_a_decoy(twin: NetworkTwin) -> None:
    # staging_decoy advertises an RCE but is patched -> not really exploitable.
    vulns = twin.get_vulns("staging_decoy")
    assert vulns and all(v.get("patched") for v in vulns)


def test_credential_unlocks_shortcut_edge(twin: NetworkTwin) -> None:
    loot = twin.graph.nodes["app_server"]["loot"]
    assert any(l["id"] == "db_service_cred" for l in loot)
    edge = twin.graph.edges["app_server", "db_server"]
    assert edge["requires_cred"] == "db_service_cred"


def test_multiple_routes_to_goal(twin: NetworkTwin) -> None:
    # Best path (app), alt (cache), corp path all reach the crown jewel.
    assert twin.has_route("internet", "db_server")
    assert twin.has_route("app_server", "db_server")
    assert twin.has_route("cache_server", "db_server")
    assert twin.has_route("corp_resources", "db_server")


def test_dead_end_has_no_route_to_goal(twin: NetworkTwin) -> None:
    # dev_laptop is reachable but has no edge onward — a genuine dead-end.
    assert twin.has_route("workstation", "dev_laptop")
    assert not twin.has_route("dev_laptop", "db_server")

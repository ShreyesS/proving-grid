import pytest

from twin import NetworkTwin, load_twin


@pytest.fixture
def twin() -> NetworkTwin:
    return load_twin()


def test_loads_topology_nodes_and_edges(twin: NetworkTwin) -> None:
    assert twin.graph.number_of_nodes() == 9
    assert twin.graph.number_of_edges() == 11


def test_get_neighbors_bidirectional_over_active_edges(twin: NetworkTwin) -> None:
    assert twin.get_neighbors("cdn_edge") == ["corp_vpn", "internet", "load_balancer"]
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
    assert twin.get_neighbors("load_balancer") == ["app_server", "cache_server"]


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
    assert len(snapshot["nodes"]) == 9
    assert len(snapshot["edges"]) == 11
    db = next(n for n in snapshot["nodes"] if n["id"] == "db_server")
    assert db["mission_critical"] is True


def test_unknown_node_raises(twin: NetworkTwin) -> None:
    with pytest.raises(KeyError):
        twin.get_neighbors("missing")

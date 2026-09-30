"""Free public contagion calculator (P1.2) — offline, seed-data only."""

import math

import pytest

pytest.importorskip("fastapi")  # optional dep — skip gracefully when not installed
from fastapi.testclient import TestClient

from blastradius.contagion.graph import DeFiContagionGraph
from blastradius.contagion.scoring import simulate_token_collapse
from blastradius.web import calculator


@pytest.fixture
def graph():
    return DeFiContagionGraph.from_json(calculator.default_data_path())


@pytest.fixture
def client(monkeypatch, graph):
    monkeypatch.setattr(calculator, "load_graph", lambda path=None: graph)
    return TestClient(calculator.build_calculator_app())


# ---------------------------------------------------------------------------
# Score card
# ---------------------------------------------------------------------------


def test_score_card_kelpdao_seed_case(client):
    """The founding case: numbers must match the engine + the published post."""
    resp = client.get("/api/v1/contagion/score", params={"token": "rsETH"})
    assert resp.status_code == 200
    body = resp.json()

    # stable public contract (MASTER_PROMPT schema)
    for key in (
        "token",
        "blast_radius_score",
        "reachable_tvl_usd",
        "affected_markets",
        "affected_protocols",
        "affected_chains",
        "bad_debt_uncovered_usd",
        "risk_level",
        "generated_at",
    ):
        assert key in body

    assert body["token"] == "rsETH"
    assert body["reachable_tvl_usd"] == 16_734_000_000
    assert body["bad_debt_uncovered_usd"] == 220_000_000
    assert (body["affected_markets"], body["affected_protocols"], body["affected_chains"]) == (
        5,
        4,
        4,
    )
    assert body["risk_level"] == "CRITICAL"
    assert body["blast_radius_score"] == 87  # 22 * log10(1 + 8_983.39M / 1e6)
    assert body["generated_at"].endswith("Z")


def test_score_card_scenarios_sum_matches_collapse(graph):
    body = calculator.compute_score_card(graph, "rsETH")
    for drop, expected in ((25, 0.75), (50, 0.5), (75, 0.25), (90, 0.1)):
        rows = simulate_token_collapse(graph, "Token:rsETH", price_ratio=expected)
        assert body["bad_debt_scenarios_usd"][f"{drop}%"] == int(
            round(sum(r.uncovered_loss_usd for r in rows))
        )


def test_score_card_token_case_insensitive(client):
    resp = client.get("/api/v1/contagion/score", params={"token": "rseth"})
    assert resp.status_code == 200
    assert resp.json()["token"] == "rsETH"


def test_score_card_unknown_token_404(client):
    resp = client.get("/api/v1/contagion/score", params={"token": "NOPE"})
    assert resp.status_code == 404
    assert "unknown token" in resp.json()["detail"]


def test_score_card_missing_token_422(client):
    assert client.get("/api/v1/contagion/score").status_code == 422


# ---------------------------------------------------------------------------
# ASCII map + page
# ---------------------------------------------------------------------------


def test_map_endpoint_ascii_tree(client):
    resp = client.get("/api/v1/contagion/map", params={"token": "rsETH"})
    assert resp.status_code == 200
    ascii_tree = resp.json()["ascii_map"]
    assert "SEED (this breaks)" in ascii_tree
    assert "Aave V3 Ethereum pool" in ascii_tree
    assert "16,734,000,000" in ascii_tree


def test_calculator_page_served(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "BlastRadius Contagion Calculator" in resp.text


# ---------------------------------------------------------------------------
# Score normalization
# ---------------------------------------------------------------------------


def test_normalized_score_bounds():
    assert calculator.normalized_score(0) == 0
    assert calculator.normalized_score(-5) == 0
    assert calculator.normalized_score(10**15) == 100
    # ~22 points per order of magnitude of decayed exposure
    assert calculator.normalized_score(1e6) == round(22 * math.log10(2))  # 7
    assert calculator.normalized_score(1e12) == 100  # 22 * log10(1e6+1) = 132 -> capped
    assert calculator.normalized_score(1e10) == round(22 * math.log10(10_001))  # 88

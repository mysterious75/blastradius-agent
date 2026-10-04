"""Offline tests for the backstop reader (network isolated via monkeypatch)."""

from blastradius.contagion.loaders import backstop


def _patch_call(monkeypatch, result="0x0de0b6b3a7640000"):
    monkeypatch.setattr(backstop, "_call_first", lambda *a, **k: result)


def test_to_int():
    assert backstop._to_int("0xff") == 255
    assert backstop._to_int("garbage") == 0
    assert backstop._to_int(None) == 0


def test_load_sources_missing(tmp_path):
    assert backstop.load_sources(tmp_path / "nope.json") == {}


def test_load_sources_file():
    cfg = backstop.load_sources()
    assert "stkAAVE-legacy" in [s["id"] for s in cfg.get("sources", [])]


def test_read_total_supply(monkeypatch):
    _patch_call(monkeypatch, "0x" + format(10**18, "x"))
    assert backstop.read_total_supply(["http://x"], "0xT") == 10**18


def test_read_total_assets(monkeypatch):
    _patch_call(monkeypatch, "0x" + format(5 * 10**6, "x"))
    assert backstop.read_total_assets(["http://x"], "0xV") == 5_000_000


def _round_data(answer: int) -> str:
    # latestRoundData() ABI: (uint80 roundId, int256 answer, uint256 startedAt,
    # uint256 updatedAt, uint80 answeredInRound)
    return "0x" + format(1, "064x") + format(answer, "064x") + format(2, "064x") * 3


def test_chainlink_price_math(monkeypatch):
    # $88.34 with 8 decimals
    _patch_call(monkeypatch, _round_data(8834000000))
    assert backstop.read_chainlink_usd(["http://x"], "0xF") == 88.34


def test_chainlink_zero_returns_none(monkeypatch):
    _patch_call(monkeypatch, _round_data(0))
    assert backstop.read_chainlink_usd(["http://x"], "0xF") is None


def test_fetch_backstops_slashable_and_stablecoin(monkeypatch):
    calls = {"n": 0}

    def fake(rpcs, to_addr, data, timeout=20.0):
        calls["n"] += 1
        if data == backstop._SEL_TOTAL_SUPPLY:
            return "0x" + format(10 * 10**18, "x")  # 10 tokens
        return _round_data(100 * 10**8)  # $100 price feed

    monkeypatch.setattr(backstop, "_call_first", fake)
    cfg = {
        "rpcs": {"1": ["http://x"]},
        "chainlink_usd_feeds": {"AAVE": "0xF"},
        "sources": [
            {
                "id": "s1",
                "chain": 1,
                "kind": "erc20-totalSupply",
                "address": "0xT",
                "underlying": "AAVE",
                "decimals": 18,
                "price_usd_feed": "AAVE",
                "slashable_pct": 20,
            }
        ],
    }
    out = backstop.fetch_backstops(cfg)
    assert out == {"s1": 10 * 100 * 0.2}


def test_fetch_backstops_stablecoin_fallback_price(monkeypatch):
    monkeypatch.setattr(backstop, "_call_first", lambda *a, **k: "0x" + format(50 * 10**6, "x"))
    cfg = {
        "rpcs": {"1": ["http://x"]},
        "chainlink_usd_feeds": {},
        "sources": [
            {
                "id": "usdc",
                "chain": 1,
                "kind": "erc4626-totalAssets",
                "address": "0xV",
                "underlying": "USDC",
                "decimals": 6,
            }
        ],
    }
    out = backstop.fetch_backstops(cfg)
    assert out == {"usdc": 50.0}


def test_fetch_backstops_skips_failures(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("down")

    monkeypatch.setattr(backstop, "_call_first", boom)
    cfg = {
        "rpcs": {"1": ["http://x"]},
        "sources": [
            {
                "id": "bad",
                "chain": 1,
                "kind": "erc20-totalSupply",
                "address": "0xT",
                "underlying": "AAVE",
                "decimals": 18,
            }
        ],
    }
    assert backstop.fetch_backstops(cfg) == {}


def test_unknown_kind_skipped():
    cfg = {
        "rpcs": {"1": ["http://x"]},
        "sources": [{"id": "weird", "chain": 1, "kind": "nope", "address": "0xT"}],
    }
    assert backstop.fetch_backstops(cfg) == {}


def test_default_backstop_config_is_valid():
    assert backstop.validate_backstop_sources() == []


def test_non_ethereum_backstop_requires_verified_provenance():
    base = {
        "id": "base-vault",
        "chain": 8453,
        "kind": "erc4626-totalAssets",
        "address": "0xV",
        "underlying": "USDC",
        "decimals": 6,
    }
    cfg = {"rpcs": {"8453": ["http://x"]}, "sources": [dict(base)]}
    assert backstop.validate_backstop_sources(cfg) == [
        "base-vault: non-Ethereum backstop requires verified_by provenance"
    ]

    verified = dict(base, verified_by="Aave governance deployment record")
    assert backstop.validate_backstop_sources({"rpcs": cfg["rpcs"], "sources": [verified]}) == []

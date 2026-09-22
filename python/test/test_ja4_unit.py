import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common import epoch_diff, get_cache  # noqa: E402
from ja4 import first_last_alpn, hops, to_ja4, to_ja4s  # noqa: E402
from ja4h import to_ja4h  # noqa: E402


def test_epoch_diff_spans_seconds():
    t1 = "2020-01-17T20:43:36.000000Z"
    t2 = "2020-01-17T20:43:37.250000Z"
    # 1.25 s of round-trip time -> 625000 microseconds one-way
    assert epoch_diff(t1, t2) == 625000


def test_epoch_diff_sub_second_precision():
    t1 = "2020-01-17T20:43:36.000000Z"
    t2 = "2020-01-17T20:43:36.000500Z"
    assert epoch_diff(t1, t2) == 250


def test_hops_uses_the_regular_initial_ttl_ladder():
    assert hops(64) == 0
    assert hops(60) == 4
    assert hops(128) == 0
    assert hops(120) == 8
    assert hops(200) == 55


def _ja4h_referer_flag(headers):
    x = {
        "hl": "http",
        "stream": "9",
        "method": "GET",
        "headers": ["GET / HTTP/1.1"] + headers,
    }
    result = to_ja4h(x, debug_stream=-1)
    # JA4H layout: method(2) version(2) cookie(1) referer(1) ...
    return result["JA4H"][5]


def test_ja4h_referer_flag_requires_exact_header():
    assert _ja4h_referer_flag(["Referer: https://example.com/"]) == "r"


def test_ja4h_referer_flag_ignores_lookalike_headers():
    assert _ja4h_referer_flag(["X-Referer: https://example.com/"]) == "n"


@pytest.mark.parametrize("alpn, expected", [
    ("h2", "h2"),
    ("http/1.1", "h1"),
    ("x", "xx"),
    ("7", "77"),
    ("", "00"),
    (None, "00"),
    ([], "00"),
    (["", "h2"], "00"),
    (["x", "h2"], "xx"),
    (["h2", "h3"], "h2"),
])
def test_first_last_alpn(alpn, expected):
    assert first_last_alpn(alpn) == expected


@pytest.mark.parametrize("alpn, expected", [
    ("\u00e9", "99"),
    ("\u00e9x", "9x"),
    ("\u00e9xy", "9y"),
    ("x\u00e9", "x9"),
    ("xy\u00e9", "x9"),
    ("x\u00e9y", "xy"),
])
def test_first_last_alpn_retains_rust_style_non_ascii_substitution(alpn, expected):
    assert first_last_alpn(alpn) == expected


@pytest.mark.parametrize("render, fields, prefix", [
    (to_ja4, ("JA4.1", "JA4_o.1", "JA4_r.1", "JA4_ro.1"), "t12i0101"),
    (to_ja4s, ("JA4S", "JA4S_r"), "t1201"),
])
@pytest.mark.parametrize("alpn_fields, expected", [
    ({}, "00"),
    ({"alpn_list": ""}, "00"),
    ({"alpn_list": None}, "00"),
    ({"alpn_list": []}, "00"),
    ({"alpn_list": ["", "h2"]}, "00"),
    ({"alpn_list": "x"}, "xx"),
    ({"alpn_list": ["x", "h2"]}, "xx"),
])
def test_tls_fingerprints_handle_alpn_edge_cases(
    monkeypatch, render, fields, prefix, alpn_fields, expected
):
    x = {
        "hl": "tls",
        "stream": 7,
        "quic": False,
        "version": "0x0303",
        "ciphers": ["0x1301"],
        "extensions": ["0x0016"],
        **alpn_fields,
    }
    monkeypatch.setitem(get_cache(x), x["stream"], {"stream": x["stream"]})
    render(x, debug_stream=-1)
    for field in fields:
        assert x[field].split("_", 1)[0] == prefix + expected

import builtins
import importlib
import types

# Import the module under test
mod = importlib.import_module('Basic_Wallet_Scanner')


def test_b58check_valid_btc():
    ok, ver, info = mod._b58check_verify('1BoatSLRHtKNngkdXEeobR76b53LETtpyT')
    assert ok and info[0] == 'BTC'


def test_detect_eth_and_bech32():
    # Craft a small buffer with ETH and bech32-like addresses
    # Use bech32-charset-only strings for BTC/LTC so our lenient matcher finds them
    data = b"random 0x52908400098527886E0F7030069857D2E4169EE7 bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq ltc1qpppppppppppppppppppppppppppppppp more"
    # Patch open to return our buffer
    class DummyFile:
        def __enter__(self):
            return types.SimpleNamespace(read=lambda: data)
        def __exit__(self, exc_type, exc, tb):
            return False
    orig_open = builtins.open
    builtins.open = lambda *a, **k: DummyFile()
    try:
        res = mod.fallback_scan_addresses('dummy')
    finally:
        builtins.open = orig_open
    coins = {r['coin'] for r in res}
    assert 'ETH' in coins
    assert 'BTC' in coins
    assert 'LTC' in coins

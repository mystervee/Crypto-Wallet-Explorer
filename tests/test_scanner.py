import os
import tempfile
from Basic_Wallet_Scanner import fallback_scan_addresses, _b58check_verify


def test_btc_ltc_doge_ppc_eth_detection(tmp_path):
    data = (
        b"Random text "
        b"1BoatSLRHtKNngkdXEeobR76b53LETtpyT "  # BTC P2PKH
        b"LTW28UySQzC9coNXaaNVJfzRGRKhs6WCMe "  # LTC P2PKH
        b"DQSxhBwk4R9napRWdKpYKwfZZMRn29v1tU "  # DOGE P2PKH
        b"PThNBbM7KFKKvifStnrXXSuCCyTv3htz1s "  # PPC P2PKH
        b"S81NTmg7nTmzu5dFDBH62hT5eBoQ6uNkgU "  # GRC P2PKH
        b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080 "  # BTC bech32
        b"ltc1q7zpg6kek5ux6p7y7m2kqyl9xa4pp5yqv2f7q0y "  # LTC bech32
        b"0x52908400098527886E0F7030069857D2E4169EE7"   # ETH
    )
    f = tmp_path / "sample.dat"
    f.write_bytes(data)

    results = fallback_scan_addresses(str(f))
    coins = {r['coin'] for r in results}
    assert 'BTC' in coins
    assert 'LTC' in coins
    assert 'DOGE' in coins
    assert 'PPC' in coins
    assert 'GRC' in coins
    assert 'ETH' in coins


def test_b58check_verify_valid():
    ok, ver, info = _b58check_verify('1BoatSLRHtKNngkdXEeobR76b53LETtpyT')
    assert ok and ver == 0x00

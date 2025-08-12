# Crypto Wallet Explorer

A simple, cross-platform wallet.dat scanner for Bitcoin-family wallets. It is intended for users to scan wallet files on thier own machine to gain basic information on the contents of the wallet, balance is displayed where possible.  It tries pywallet for structured dumps when available, and safely falls back to read-only address discovery (Base58 + Bech32 + ETH 0x strings).

## features
- Scans folders recursively for `.dat` and skips duplicate backups by content hash
- PyWallet integration with JSON parsing and optional WSL fallback on Windows
- Read-only fallback detection for BTC, LTC, DOGE, PPC, GRC, and ETH
- Balance lookups (best-effort):
   - BTC via bitcoinlib services
   - LTC/DOGE via chain.so
   - PPC via chainz/cryptoid
- Bech32 support for BTC (`bc1…`) and LTC (`ltc1…`)
- CSV export including balance, dedup count, and first wallet path

## quick start
1) Create a virtual environment and install dependencies

Windows (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux/macOS (bash):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

2) Run the scanner

```powershell
python .\Basic_Wallet_Scanner.py --dir \\path\\to\\your\\backups --csv scan_results.csv
```

If `--dir` is omitted, the script will prompt for a folder.

3) Review results
- Console output shows discovered addresses grouped by coin
- A `scan_results.csv` is saved (by default to the current working directory)

## cli flags
- `--dir <folder>`: Folder to scan (recursively) for `.dat`
- `--csv <path>`: Output CSV path (default: `scan_results.csv` in CWD)
- `--no-balances`: Skip all balance lookups
- `--max-per-coin <N>`: Limit per-coin addresses printed to console per wallet (default 25)
- `--no-wsl`: Disable WSL fallback for running pywallet on Windows

Examples:

```powershell
# Minimal, prompt for folder
python .\Basic_Wallet_Scanner.py

# Specify folder and write CSV
python .\Basic_Wallet_Scanner.py --dir D:\Backups\Wallets --csv D:\out\scan.csv

# Faster console scanning; skip balances
python .\Basic_Wallet_Scanner.py --dir D:\Backups\Wallets --no-balances
```

## supported coins
- BTC: Base58 P2PKH/P2SH, Bech32 `bc1…`
- LTC: Base58 P2PKH/P2SH, Bech32 `ltc1…`
- DOGE: Base58 P2PKH/P2SH
- PPC (Peercoin): Base58 P2PKH/P2SH
- GRC (Gridcoin): Base58 P2PKH
- ETH: Hex `0x` addresses (detection only; no balances)

## output csv schema
Columns:
- `wallet`: Source file path where the address was first seen
- `coin`: BTC/LTC/DOGE/PPC/GRC/ETH
- `type`: P2PKH/P2SH/BECH32/HEX
- `address`: The discovered address string
- `balance`: Numeric when looked up (BTC/LTC/DOGE/PPC); empty otherwise
- `count`: Number of times this (coin, address) was encountered across all files
- `first_wallet`: The first wallet file in which this address appeared

## windows + wsl (pywallet fallback)
PyWallet needs Berkeley DB (bsddb). On Windows this is tricky; the script will auto-try WSL if a local run fails with a bsddb error.

Inside WSL (Ubuntu/Debian):

```bash
sudo apt update
sudo apt install -y python3-bsddb3
```

No extra setup is required beyond having WSL installed; the script converts paths and invokes `python3` within WSL for the pywallet step.

## testing
Developer tests live in `tests/` and can be run with pytest:

```powershell
python -m pip install -r requirements-dev.txt
pytest -q
```

## troubleshooting
- PyWallet JSON parse errors: Make sure WSL + `python3-bsddb3` is installed on Windows, or run natively on Linux.
- Public API limits: LTC/DOGE/PPC balances use public endpoints and may rate-limit or return empty data. Rerun later or use `--no-balances`.
- Very old/alt forks: Address version bytes vary. The fallback will label as `UNKNOWN` if it can’t map a version byte.
- No addresses found: Some backups store keys encrypted or in non-standard formats; try the pywallet path on Linux.

## security and privacy
- Read-only: The scanner never writes to wallet files or transacts on any network.
- Offline usage: For maximum privacy, run with `--no-balances` to avoid network calls; you’ll still get address discovery and CSV export.

## contributing
PRs welcome for:
- Additional coin/version mappings and bech32 checksum verification
- More reliable balance providers and optional API key support
- Performance improvements and better CSV/reporting options

## releases
Prebuilt zips are published on the GitHub Releases page when a tag like `v1.0.0` is pushed.

Contents:
- `Basic_Wallet_Scanner.py`
- `pywallet/` (as shipped in this repo)
- `README.md`, `LICENSE`, `requirements.txt` (and `requirements-dev.txt` if present)

Quick run from a release zip:

```powershell
# 1) Extract zip and open a terminal in its folder
# 2) Create venv and install runtime deps
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt

# 3) Run
python .\Basic_Wallet_Scanner.py --dir D:\Backups\Wallets --csv scan_results.csv
```

## disclaimer
This tool is provided “as is,” without warranty of any kind. Use at your own risk.

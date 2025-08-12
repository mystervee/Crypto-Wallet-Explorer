import os
import sys
import subprocess
import json
import hashlib
import re
import time
from typing import Optional
import csv
from bitcoinlib.services.services import Service
import requests

def find_wallet_files(directory):
    """Recursively find candidate wallet files (.dat) and dedupe by content hash."""
    wallet_files = []
    seen_hashes = set()

    for root, _, files in os.walk(directory):
        for file in files:
            if not file.lower().endswith('.dat'):
                continue
            full_path = os.path.join(root, file)
            # De-duplicate identical backups by content hash
            try:
                h = hashlib.sha256()
                with open(full_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(chunk)
                digest = h.hexdigest()
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)
                wallet_files.append(full_path)
            except Exception:
                # If we can't read the file, skip but keep scanning others
                continue

    return wallet_files
    
def check_balance(address):
    try:
        svc = Service()
        balance = svc.getbalance(address)
        print(f"💰 Balance for {address}: {balance} BTC")
    except Exception as e:
        print(f"⚠️ Could not fetch balance: {e}")


def get_balance(address):
    """Return BTC balance for an address, or None on error."""
    try:
        svc = Service()
        return svc.getbalance(address)
    except Exception:
        return None


def _http_get_json(url: str, timeout: int = 12) -> Optional[dict]:
    try:
        r = requests.get(url, headers={"User-Agent": "CryptoWalletExplorer/1.0"}, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        return None
    return None


def _http_get_text(url: str, timeout: int = 12) -> Optional[str]:
    try:
        r = requests.get(url, headers={"User-Agent": "CryptoWalletExplorer/1.0"}, timeout=timeout)
        if r.status_code == 200:
            return r.text
    except Exception:
        return None
    return None


def get_balance_altcoin(coin: str, address: str) -> Optional[float]:
    """Fetch balance for LTC/DOGE/PPC via public APIs. Returns float or None."""
    coin = coin.upper()
    # simple throttle to be nice to APIs
    time.sleep(0.2)
    try:
        if coin in ("LTC", "DOGE"):
            url = f"https://chain.so/api/v2/get_address_balance/{coin}/{address}"
            data = _http_get_json(url)
            if data and data.get("status") == "success":
                d = data.get("data", {})
                conf = d.get("confirmed_balance")
                unconf = d.get("unconfirmed_balance", "0")
                try:
                    return float(conf) + float(unconf)
                except Exception:
                    return None
        elif coin == "PPC":
            # cryptoid simple endpoint returns text float
            url = f"https://chainz.cryptoid.info/ppc/api.dws?q=getbalance&a={address}"
            t = _http_get_text(url)
            if t is None:
                return None
            try:
                return float(t.strip())
            except Exception:
                return None
    except Exception:
        return None
    return None

def display_wallet_data(wallet_path, data):
    print(f"\n🗂️ Wallet: {wallet_path}")
    keys = data.get("keys", [])
    if not keys:
        print("📭 No keys found.")
        return

    for key in keys:
        addr = key.get("addr", "Unknown")
        created = key.get("created_at", "Unknown")
        print(f"🔑 Address: {addr}")
        print(f"📅 Created: {created}")
        check_balance(addr)


# ---------------- Fallback scanning (no bsddb/pywallet) ---------------- #

_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_B58_MAP = {c: i for i, c in enumerate(_B58_ALPHABET)}

# Version byte -> (coin, addr_type)
_VERSION_MAP = {
    0x00: ("BTC", "P2PKH"),
    0x05: ("BTC", "P2SH"),
    0x30: ("LTC", "P2PKH"),
    0x32: ("LTC", "P2SH"),
    0x1E: ("DOGE", "P2PKH"),
    0x16: ("DOGE", "P2SH"),
    0x37: ("PPC", "P2PKH"),
    0x75: ("PPC", "P2SH"),
    0x3E: ("GRC", "P2PKH"),  # Gridcoin mainnet P2PKH (observed from sample)
}


def _b58decode(s: str):
    n = 0
    for char in s:
        if char not in _B58_MAP:
            return None
        n = n * 58 + _B58_MAP[char]
    # Convert to bytes
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    # Add leading zeros
    pad = 0
    for ch in s:
        if ch == '1':
            pad += 1
        else:
            break
    return b'\x00' * pad + full


def _b58check_verify(addr: str):
    data = _b58decode(addr)
    if not data or len(data) < 5:
        return False, None, None
    payload, checksum = data[:-4], data[-4:]
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if check != checksum:
        return False, None, None
    # version byte + pubkey hash/script hash
    if len(payload) not in (21,):  # 1 version + 20 hash
        return False, None, None
    version = payload[0]
    cinfo = _VERSION_MAP.get(version)
    return True, version, cinfo


def fallback_scan_addresses(wallet_path):
    """Scan binary file for likely Base58 addresses and ETH hex addresses.

    Returns a list of dicts: { 'address': str, 'coin': 'BTC'|'LTC'|'DOGE'|'PPC'|'ETH'|'UNKNOWN', 'type': 'P2PKH'|'P2SH'|'HEX'|None }
    """
    try:
        with open(wallet_path, 'rb') as f:
            blob = f.read()
    except Exception:
        return []

    # Extract ASCII substrings that look like base58 addresses
    candidates = set()
    current = []
    for b in blob:
        ch = chr(b)
        if ch in _B58_MAP:
            current.append(ch)
            if len(current) > 50:
                # Unlikely long, split
                current = []
        else:
            if 26 <= len(current) <= 40:
                candidates.add(''.join(current))
            current = []
    if 26 <= len(current) <= 40:
        candidates.add(''.join(current))

    results = []
    seen = set()
    for c in candidates:
        ok, version, cinfo = _b58check_verify(c)
        if ok and c not in seen:
            seen.add(c)
            if cinfo:
                coin, atype = cinfo
            else:
                coin, atype = "UNKNOWN", None
            results.append({"address": c, "coin": coin, "type": atype, "version": version})

    # ETH-style addresses: 0x + 40 hex chars
    try:
        text = blob.decode('latin-1', errors='ignore')
    except Exception:
        text = ''

    for m in re.finditer(r"0x[0-9a-fA-F]{40}", text):
        addr = m.group(0)
        # basic sanity: not all zeros
        if addr.lower() == "0x" + ("0" * 40):
            continue
        if addr not in seen:
            seen.add(addr)
            results.append({"address": addr, "coin": "ETH", "type": "HEX", "version": None})

    # Bech32 BTC/LTC addresses (no checksum verification here)
    bech32_charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7'
    # allow up to 90 chars in data part
    pat_btc = re.compile(rf"(?<![A-Za-z0-9])bc1[{bech32_charset}]{{11,90}}(?![A-Za-z0-9])")
    pat_ltc = re.compile(rf"(?<![A-Za-z0-9])ltc1[{bech32_charset}]{{11,90}}(?![A-Za-z0-9])")
    for m in pat_btc.finditer(text):
        a = m.group(0)
        if a not in seen:
            seen.add(a)
            results.append({"address": a, "coin": "BTC", "type": "BECH32", "version": None})
    for m in pat_ltc.finditer(text):
        a = m.group(0)
        if a not in seen:
            seen.add(a)
            results.append({"address": a, "coin": "LTC", "type": "BECH32", "version": None})

    return results

def _extract_json(text: str):
    """Best-effort JSON extraction from noisy CLI output.

    Finds the first '{' and last '}' and tries to parse the substring.
    Returns dict on success, None on failure.
    """
    if not text:
        return None
    start = text.find('{')
    end = text.rfind('}')
    if start == -1 or end == -1 or end <= start:
        return None
    snippet = text[start:end + 1]
    try:
        return json.loads(snippet)
    except Exception:
        return None


def _venv_python():
    """Return path to current interpreter; prefer venv python if available."""
    return sys.executable or "python"


def run_pywallet(wallet_path, allow_wsl: bool = True):
    # Resolve pywallet path relative to this script; if missing, we'll fallback gracefully
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pywallet_path = os.path.join(script_dir, "pywallet", "pywallet.py")
    datadir = os.path.dirname(wallet_path)
    wallet_file = os.path.basename(wallet_path)

    # Prefer current interpreter; pywallet is historically Python 2.x,
    # but we'll try and report clear diagnostics if incompatible.
    python_exe = _venv_python()

    try:
        result = subprocess.run(
            [python_exe, pywallet_path, "--dumpwallet", f"--datadir={datadir}", f"--wallet={wallet_file}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            encoding="utf-8",
            errors="replace",
        )

        output = (result.stdout or '').strip()

        if result.returncode != 0:
            print(f"❌ PyWallet exited with code {result.returncode} for {wallet_file}\n↳ Output:\n{output[:1000]}")
            # If bsddb missing, try WSL fallback if available
            if allow_wsl and ('needs \"bsddb\"' in output or 'needs \'bsddb\'' in output or 'bsddb' in output.lower()):
                data = _run_pywallet_via_wsl(pywallet_path, datadir, wallet_file)
                if data is not None:
                    return data
            return None

        # Try strict JSON first
        try:
            return json.loads(output)
        except Exception:
            pass

        # Best-effort extraction when output has banners/noise
        data = _extract_json(output)
        if data is not None:
            return data

        # If we got here, show a short preview for debugging
        preview = output[:500].replace('\n', '\n  ')
        print(f"⚠️ PyWallet did not return valid JSON for {wallet_file}. Output preview:\n  {preview}")
        return None
    except Exception as e:
        print(f"⚠️ Failed to run pywallet on {wallet_path}: {e}")
        return None


def _to_wsl_path(win_path: str) -> str:
    """Translate a Windows path like D:\\foo to WSL path /mnt/d/foo."""
    win_path = os.path.abspath(win_path)
    drive, tail = os.path.splitdrive(win_path)
    drive_letter = drive.replace(':', '').lower()
    tail = tail.replace('\\', '/')
    return f"/mnt/{drive_letter}{tail}"


def _run_pywallet_via_wsl(pywallet_path: str, datadir: str, wallet_file: str):
    """Attempt to run pywallet under WSL (Linux) where bsddb3 is easy to install.

    Requires: WSL with python3 and bsddb3 installed (e.g., sudo apt install python3-bsddb3).
    """
    try:
        # Quick probe: is WSL available?
        probe = subprocess.run(["wsl", "--status"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
        if probe.returncode != 0:
            return None
    except Exception:
        return None

    pyw = _to_wsl_path(pywallet_path)
    dd = _to_wsl_path(datadir)
    try:
        res = subprocess.run(
            ["wsl", "python3", pyw, "--dumpwallet", f"--datadir={dd}", f"--wallet={wallet_file}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
            encoding="utf-8",
            errors="replace",
        )
        out = (res.stdout or '').strip()
        if res.returncode != 0:
            print(f"❌ WSL pywallet exited {res.returncode}. Output preview:\n{out[:800]}")
            return None
        try:
            return json.loads(out)
        except Exception:
            return _extract_json(out)
    except Exception:
        return None
        
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scan wallet.dat files for addresses and balances")
    parser.add_argument("--dir", dest="directory", help="Directory to scan for .dat files")
    parser.add_argument("--csv", dest="csv", default=None, help="Output CSV path (default: scan_results.csv in CWD)")
    parser.add_argument("--no-balances", dest="no_balances", action="store_true", help="Do not fetch any balances")
    parser.add_argument("--max-per-coin", dest="max_per_coin", type=int, default=25, help="Max addresses to print per coin per wallet (default 25)")
    parser.add_argument("--no-wsl", dest="no_wsl", action="store_true", help="Disable WSL fallback for pywallet")
    args = parser.parse_args()

    directory = args.directory or input("Enter directory to scan for wallet files: ")
    wallet_files = find_wallet_files(directory)
    print(f"🔍 Found {len(wallet_files)} files")
    all_results = []
    # Global de-duplication across all scanned files
    global_seen = {}  # (coin,address) -> {count:int, first_wallet:str}

    do_balances = not args.no_balances
    max_show = max(0, args.max_per_coin)

    for wallet_path in wallet_files:
        print(f"🧪 Trying PyWallet on: {wallet_path}")
        data = run_pywallet(wallet_path, allow_wsl=not args.no_wsl)
        if data:
            display_wallet_data(wallet_path, data)
            continue

        # Fallback path
        addrs = fallback_scan_addresses(wallet_path)
        if addrs:
            print(f"\n🗂️ Wallet (fallback): {wallet_path}")
            print(f"🔑 Addresses found: {len(addrs)}")
            # Group by coin
            by_coin = {}
            for item in addrs:
                by_coin.setdefault(item['coin'], []).append(item)

            for coin, items in by_coin.items():
                print(f"  ▶ {coin}: {len(items)}")
                for item in items[:max_show]:
                    label = f"{item['address']}"
                    if item.get('type'):
                        label += f" ({item['type']})"
                    print(f"   - {label}")
                    if do_balances:
                        bal = None
                        if coin == 'BTC':
                            bal = get_balance(item['address'])
                            if bal is not None:
                                print(f"💰 Balance for {item['address']}: {bal} BTC")
                            else:
                                print(f"⚠️ Could not fetch balance")
                        elif coin in ('LTC', 'DOGE', 'PPC'):
                            bal = get_balance_altcoin(coin, item['address'])
                            if bal is not None:
                                print(f"💰 Balance for {item['address']}: {bal} {coin}")
                            else:
                                print(f"⚠️ Could not fetch balance")
                if len(items) > max_show:
                    print(f"   … and {len(items) - max_show} more")
            # Collect results for export with global de-duplication
            for item in addrs:
                coin = item.get('coin') or 'UNKNOWN'
                addr = item.get('address') or ''
                atype = item.get('type') or ''
                key = (coin, addr)
                if key not in global_seen:
                    global_seen[key] = {"count": 1, "first_wallet": wallet_path, "type": atype}
                    rec = {
                        'wallet': wallet_path,
                        'coin': coin,
                        'type': atype,
                        'address': addr,
                        'count': 1,
                        'first_wallet': wallet_path,
                    }
                    if do_balances:
                        bal = None
                        if coin == 'BTC':
                            bal = get_balance(addr)
                            rec['balance'] = bal if bal is not None else 0
                        elif coin in ('LTC', 'DOGE', 'PPC'):
                            bal = get_balance_altcoin(coin, addr)
                            rec['balance'] = bal if bal is not None else 0
                        else:
                            rec['balance'] = ''
                    else:
                        rec['balance'] = ''
                    all_results.append(rec)
                else:
                    global_seen[key]['count'] += 1
                    # Update the existing record's count
                    for rec in all_results:
                        if rec['coin'] == coin and rec['address'] == addr:
                            rec['count'] = global_seen[key]['count']
                            break
        else:
            print("📭 No addresses found in fallback scan.")

    # Export CSV summary
    if all_results:
        out_csv = args.csv or os.path.join(os.getcwd(), 'scan_results.csv')
        try:
            with open(out_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['wallet', 'coin', 'type', 'address', 'balance', 'count', 'first_wallet'])
                writer.writeheader()
                writer.writerows(all_results)
            print(f"\n📝 Wrote CSV summary: {out_csv}")
        except Exception as e:
            print(f"⚠️ Could not write CSV summary: {e}")

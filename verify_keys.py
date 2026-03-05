#!/usr/bin/env python3
"""
Verify that the keys in wechat_keys.json can decrypt the corresponding WeChat databases.

Requirements:
    brew install sqlcipher

Usage:
    python3 verify_keys.py
    python3 verify_keys.py --keys path/to/wechat_keys.json
"""

import json
import os
import subprocess
import sys
import glob
import argparse

DB_DIR = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)
PAGE_SZ = 4096
SALT_SZ = 16


def find_db_dir():
    """Auto-detect the db_storage directory under DB_DIR."""
    pattern = os.path.join(DB_DIR, "*", "db_storage")
    candidates = glob.glob(pattern)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        return candidates[0]
    if os.path.isdir(DB_DIR) and os.path.basename(DB_DIR) == "db_storage":
        return DB_DIR
    return None


def find_sqlcipher():
    """Find sqlcipher binary."""
    # Try brew-installed sqlcipher first
    brew_path = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
    if os.path.isfile(brew_path):
        return brew_path
    # Try PATH
    for p in os.environ.get("PATH", "").split(":"):
        candidate = os.path.join(p, "sqlcipher")
        if os.path.isfile(candidate):
            return candidate
    return None


def verify_key(sqlcipher_bin, db_path, key_hex):
    """
    Try to open a SQLCipher database with the given key.
    Returns (success: bool, detail: str)
    """
    if not os.path.isfile(db_path):
        return False, "file not found"

    sz = os.path.getsize(db_path)
    if sz < PAGE_SZ:
        return False, f"file too small ({sz} bytes)"

    # Read salt from db file for display
    with open(db_path, "rb") as f:
        salt = f.read(SALT_SZ).hex()

    # Build sqlcipher commands:
    # WeChat uses SQLCipher defaults (page_size=4096, kdf_iter=256000, etc.)
    # Key format is PRAGMA key = "x'<hex_key>'";
    sql_commands = f"""PRAGMA key = "x'{key_hex}'";
PRAGMA cipher_page_size = 4096;
SELECT count(*) FROM sqlite_master;
"""

    try:
        result = subprocess.run(
            [sqlcipher_bin, db_path],
            input=sql_commands,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.strip()
        stderr = result.stderr.strip()

        # If we can successfully query sqlite_master, the key is correct
        if result.returncode == 0 and output and "Error" not in stderr:
            # Check if we got a numeric result (count of tables)
            lines = output.strip().split("\n")
            last_line = lines[-1].strip()
            if last_line.isdigit():
                table_count = int(last_line)
                return True, f"OK ({table_count} tables, salt={salt})"

        # Common error for wrong key
        if "file is not a database" in stderr or "not a database" in output:
            return False, f"wrong key (salt={salt})"

        return False, f"unknown error: {stderr or output}"

    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="Verify WeChat database keys")
    parser.add_argument(
        "--keys",
        default="wechat_keys.json",
        help="Path to wechat_keys.json (default: wechat_keys.json)",
    )
    args = parser.parse_args()

    # Load keys
    if not os.path.isfile(args.keys):
        print(f"[-] Key file not found: {args.keys}")
        sys.exit(1)

    with open(args.keys, "r") as f:
        data = json.load(f)

    # Find sqlcipher
    sqlcipher_bin = find_sqlcipher()
    if not sqlcipher_bin:
        print("[-] sqlcipher not found. Install it with: brew install sqlcipher")
        sys.exit(1)
    print(f"[*] Using sqlcipher: {sqlcipher_bin}")

    # Find db_storage directory
    db_dir = find_db_dir()
    if not db_dir:
        print(f"[-] Could not find db_storage directory under {DB_DIR}")
        sys.exit(1)
    print(f"[*] DB storage: {db_dir}")

    # Filter out metadata keys
    entries = {k: v for k, v in data.items() if not k.startswith("__")}
    print(f"[*] Verifying {len(entries)} keys...\n")

    passed = 0
    failed = 0

    for db_rel_path, key_hex in sorted(entries.items()):
        db_abs_path = os.path.join(db_dir, db_rel_path)
        success, detail = verify_key(sqlcipher_bin, db_abs_path, key_hex)

        if success:
            print(f"  ✅ {db_rel_path}: {detail}")
            passed += 1
        else:
            print(f"  ❌ {db_rel_path}: {detail}")
            failed += 1

    print(f"\n[*] Results: {passed} passed, {failed} failed, {passed + failed} total")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()

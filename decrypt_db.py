#!/usr/bin/env python3
"""
Decrypt WeChat SQLCipher databases to plaintext SQLite files.

Requirements:
    brew install sqlcipher

Usage:
    python3 decrypt_db.py                  # decrypt all databases
    python3 decrypt_db.py -o ./decrypted   # specify output directory
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


def find_db_dir(keys_data=None):
    # Prefer the db_dir recorded by the scanner
    if keys_data and "__db_dir__" in keys_data:
        d = keys_data["__db_dir__"]
        if os.path.isdir(d):
            return d

    pattern = os.path.join(DB_DIR, "*", "db_storage")
    candidates = glob.glob(pattern)
    if not candidates:
        if os.path.isdir(DB_DIR) and os.path.basename(DB_DIR) == "db_storage":
            return DB_DIR
        return None

    # Detect active WeChat account via lsof
    try:
        import subprocess
        proc = subprocess.Popen(
            ["lsof", "-c", "WeChat", "-F", "n"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc.stdout:
            if "xwechat_files/wxid_" in line:
                part = line.split("xwechat_files/")[1]
                wxid = part.split("/")[0]
                for c in candidates:
                    if wxid in c:
                        proc.kill()
                        proc.wait()
                        return c
        proc.kill()
        proc.wait()
    except Exception:
        pass

    return candidates[0]


def find_sqlcipher():
    brew_path = "/opt/homebrew/opt/sqlcipher/bin/sqlcipher"
    if os.path.isfile(brew_path):
        return brew_path
    for p in os.environ.get("PATH", "").split(":"):
        candidate = os.path.join(p, "sqlcipher")
        if os.path.isfile(candidate):
            return candidate
    return None


def decrypt_database(sqlcipher_bin, src_path, dst_path, key_hex):
    """Decrypt a SQLCipher database to a plaintext SQLite file."""
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    # Remove existing decrypted file if present
    if os.path.exists(dst_path):
        os.remove(dst_path)

    sql_commands = f"""PRAGMA key = "x'{key_hex}'";
PRAGMA cipher_page_size = 4096;
ATTACH DATABASE '{dst_path}' AS plaintext KEY '';
SELECT sqlcipher_export('plaintext');
DETACH DATABASE plaintext;
"""

    try:
        result = subprocess.run(
            [sqlcipher_bin, src_path],
            input=sql_commands,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 or "Error" in result.stderr:
            return False, result.stderr.strip()

        # Verify the decrypted file
        if not os.path.isfile(dst_path) or os.path.getsize(dst_path) == 0:
            return False, "output file is empty"

        return True, "OK"
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(description="Decrypt WeChat databases")
    parser.add_argument(
        "--keys",
        default="wechat_keys.json",
        help="Path to wechat_keys.json (default: wechat_keys.json)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="decrypted",
        help="Output directory for decrypted databases (default: decrypted)",
    )
    args = parser.parse_args()

    if not os.path.isfile(args.keys):
        print(f"[-] Key file not found: {args.keys}")
        sys.exit(1)

    with open(args.keys, "r") as f:
        data = json.load(f)

    sqlcipher_bin = find_sqlcipher()
    if not sqlcipher_bin:
        print("[-] sqlcipher not found. Install it with: brew install sqlcipher")
        sys.exit(1)
    print(f"[*] Using sqlcipher: {sqlcipher_bin}")

    db_dir = find_db_dir(data)
    if not db_dir:
        print(f"[-] Could not find db_storage directory under {DB_DIR}")
        sys.exit(1)
    print(f"[*] DB storage: {db_dir}")

    entries = {k: v for k, v in data.items() if not k.startswith("__")}
    print(f"[*] Decrypting {len(entries)} databases to {args.output}/\n")

    passed = 0
    failed = 0

    for db_rel_path, key_hex in sorted(entries.items()):
        src = os.path.join(db_dir, db_rel_path)
        dst = os.path.join(args.output, db_rel_path)

        if not os.path.isfile(src):
            print(f"  ⏭️  {db_rel_path}: source file not found, skipping")
            continue

        success, detail = decrypt_database(sqlcipher_bin, src, dst, key_hex)
        if success:
            dst_size = os.path.getsize(dst)
            print(f"  ✅ {db_rel_path} -> {dst} ({dst_size / 1024:.0f} KB)")
            passed += 1
        else:
            print(f"  ❌ {db_rel_path}: {detail}")
            failed += 1

    print(f"\n[*] Done: {passed} decrypted, {failed} failed")
    if passed > 0:
        print(f"[*] Decrypted files saved to: {os.path.abspath(args.output)}/")
        print(f"[*] You can now run: python3 export_messages.py")


if __name__ == "__main__":
    main()

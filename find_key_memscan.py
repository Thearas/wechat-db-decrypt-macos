#!/usr/bin/env python3
"""
Extract ALL WeChat database keys by scanning process memory.

Instead of relying on breakpoints (which only fire when a DB is accessed),
this script scans the entire WeChat process memory for cached raw keys
in the format: x'<64hex_enc_key><32hex_salt>'

Inspired by https://github.com/ylytdeng/wechat-decrypt

Requirements:
    - lldb (brew install llvm)
    - SIP disabled (csrutil disable)

Usage:
    PYTHONPATH=$(lldb -P) python3 find_key_memscan.py
"""

import sys
import os
import re
import glob
import json
import struct
import hashlib
import hmac as hmac_mod

import lldb

DB_DIR = os.path.expanduser(
    "~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
OUTPUT_FILE = "wechat_keys.json"

# Regex to match x'<hex>' patterns in memory (64-192 hex chars)
HEX_PATTERN = re.compile(rb"x'([0-9a-fA-F]{64,192})'")


def find_db_dirs(pid=None):
    """Return all db_storage dirs, with the active account's dir first."""
    pattern = os.path.join(DB_DIR, "*", "db_storage")
    candidates = glob.glob(pattern)
    if not candidates:
        return []

    # Try to detect the active account from the process's open files
    active_wxid = None
    if pid:
        try:
            import subprocess
            proc = subprocess.Popen(
                ["lsof", "-c", "WeChat", "-F", "n"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout:
                if "xwechat_files/wxid_" in line:
                    part = line.split("xwechat_files/")[1]
                    active_wxid = part.split("/")[0]
                    break
            proc.kill()
            proc.wait()
        except Exception:
            pass

    if active_wxid:
        active = [c for c in candidates if active_wxid in c]
        rest = [c for c in candidates if active_wxid not in c]
        return active + rest

    return candidates


def collect_db_files(db_dirs):
    """Collect all .db files with their first page and salt from multiple dirs."""
    db_files = []
    salt_to_dbs = {}

    if isinstance(db_dirs, str):
        db_dirs = [db_dirs]

    for db_dir in db_dirs:
        for root, dirs, files in os.walk(db_dir):
            for f in files:
                if not f.endswith(".db"):
                    continue
                if f.endswith("-wal") or f.endswith("-shm"):
                    continue
                path = os.path.join(root, f)
                rel = os.path.relpath(path, db_dir)
                sz = os.path.getsize(path)
                if sz < PAGE_SZ:
                    continue
                with open(path, "rb") as fh:
                    page1 = fh.read(PAGE_SZ)
                salt = page1[:SALT_SZ].hex()
                db_files.append((rel, path, sz, salt, page1))
                salt_to_dbs.setdefault(salt, []).append(rel)

    return db_files, salt_to_dbs


def verify_key_for_db(enc_key_bytes, db_page1):
    """Verify enc_key can decrypt this DB's page 1.

    Tries both SHA512 (SQLCipher 4 default) and SHA1 (SQLCipher 3 legacy)
    for the MAC key PBKDF2 derivation.
    """
    salt = db_page1[:SALT_SZ]
    mac_salt = bytes(b ^ 0x3A for b in salt)

    # HMAC data: encrypted content + IV (bytes 16..4031), stored HMAC: bytes 4032..4095
    hmac_data = db_page1[SALT_SZ : PAGE_SZ - 64]
    stored_hmac = db_page1[PAGE_SZ - 64 : PAGE_SZ]

    for kdf_hash in ("sha512", "sha1"):
        mac_key = hashlib.pbkdf2_hmac(kdf_hash, enc_key_bytes, mac_salt, 2, dklen=KEY_SZ)
        h = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
        h.update(struct.pack("<I", 1))  # page number
        if h.digest() == stored_hmac:
            return True
    return False


def main():
    print("=" * 60)
    print("  WeChat Memory Scanner - Extract ALL Database Keys")
    print("=" * 60)

    # 1. Attach to WeChat first to get PID, then collect DB files for the active account
    print("\n[*] Attaching to WeChat...")
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)
    target = debugger.CreateTarget("")
    error = lldb.SBError()

    process = target.AttachToProcessWithName(
        debugger.GetListener(), "WeChat", False, error
    )
    if not error.Success():
        print(f"[-] Error attaching: {error.GetCString()}")
        print("[!] Make sure WeChat is running and SIP is disabled.")
        sys.exit(1)

    pid = process.GetProcessID()
    print(f"[+] Attached to WeChat (PID: {pid})")

    # 2. Collect DB files from all accounts, active account first
    db_dirs = find_db_dirs(pid)
    if not db_dirs:
        print(f"[-] Could not find db_storage directory under {DB_DIR}")
        process.Detach()
        sys.exit(1)

    print(f"[*] Found {len(db_dirs)} db_storage dir(s):")
    for d in db_dirs:
        print(f"    {d}")

    db_files, salt_to_dbs = collect_db_files(db_dirs)
    print(f"\n[*] Found {len(db_files)} databases, {len(salt_to_dbs)} unique salts")
    for salt_hex, dbs in sorted(salt_to_dbs.items()):
        print(f"    salt {salt_hex}: {', '.join(dbs)}")

    # 3. Enumerate and scan memory regions
    key_map = {}  # salt_hex -> enc_key_hex
    remaining_salts = set(salt_to_dbs.keys())
    all_hex_matches = 0
    total_scanned = 0
    region_count = 0

    region_info = lldb.SBMemoryRegionInfo()
    addr = 0

    # Count total readable memory first
    regions = []
    while True:
        err = process.GetMemoryRegionInfo(addr, region_info)
        if err.Fail():
            break
        base = region_info.GetRegionBase()
        end = region_info.GetRegionEnd()
        if end <= base:
            break
        if region_info.IsReadable() and not region_info.IsExecutable():
            size = end - base
            if 0 < size < 500 * 1024 * 1024:  # skip huge regions
                regions.append((base, size))
        addr = end
        if addr == 0:
            break

    total_bytes = sum(s for _, s in regions)
    print(f"[*] Scanning {len(regions)} memory regions ({total_bytes / 1024 / 1024:.0f} MB)")

    for reg_idx, (base, size) in enumerate(regions):
        # Read memory in chunks to handle large regions
        chunk_size = 8 * 1024 * 1024  # 8MB chunks
        offset = 0

        while offset < size:
            read_size = min(chunk_size, size - offset)
            read_addr = base + offset
            data = process.ReadMemory(read_addr, read_size, error)
            offset += read_size
            total_scanned += read_size

            if not error.Success() or not data:
                continue

            for m in HEX_PATTERN.finditer(data):
                # Normalize to lowercase to avoid case-mismatch with DB salts
                hex_str = m.group(1).decode().lower()
                all_hex_matches += 1
                hex_len = len(hex_str)

                if hex_len == 96:
                    # Standard format: 64 hex key + 32 hex salt
                    enc_key_hex = hex_str[:64]
                    salt_hex = hex_str[64:]
                elif hex_len == 64:
                    # Key only, try against all remaining salts
                    enc_key_hex = hex_str
                    salt_hex = None
                elif hex_len > 96 and hex_len % 2 == 0:
                    # Extended format
                    enc_key_hex = hex_str[:64]
                    salt_hex = hex_str[-32:]
                else:
                    continue

                if salt_hex and salt_hex in remaining_salts:
                    enc_key = bytes.fromhex(enc_key_hex)
                    for rel, path, sz, s, page1 in db_files:
                        if s == salt_hex:
                            if verify_key_for_db(enc_key, page1):
                                key_map[salt_hex] = enc_key_hex
                                remaining_salts.discard(salt_hex)
                                dbs = salt_to_dbs[salt_hex]
                                print(f"\n  [FOUND] salt={salt_hex}")
                                print(f"    key={enc_key_hex}")
                                print(f"    databases: {', '.join(dbs)}")
                            break

                elif salt_hex is None and remaining_salts:
                    # 64-char key without salt, try all remaining DBs
                    enc_key = bytes.fromhex(enc_key_hex)
                    for rel, path, sz, salt_hex_db, page1 in db_files:
                        if salt_hex_db in remaining_salts:
                            if verify_key_for_db(enc_key, page1):
                                key_map[salt_hex_db] = enc_key_hex
                                remaining_salts.discard(salt_hex_db)
                                dbs = salt_to_dbs[salt_hex_db]
                                print(f"\n  [FOUND] salt={salt_hex_db} (key-only match)")
                                print(f"    key={enc_key_hex}")
                                print(f"    databases: {', '.join(dbs)}")
                                break

        # Progress update every 50 regions
        if (reg_idx + 1) % 50 == 0 or reg_idx == len(regions) - 1:
            progress = total_scanned / total_bytes * 100 if total_bytes else 100
            print(
                f"  [{progress:.1f}%] {len(key_map)}/{len(salt_to_dbs)} keys found, "
                f"{all_hex_matches} hex patterns, "
                f"{total_scanned / 1024 / 1024:.0f}/{total_bytes / 1024 / 1024:.0f} MB"
            )

        if not remaining_salts:
            print(f"\n[+] All keys found!")
            break

    # 4. Cross-verify: try known keys against remaining DBs
    missing_salts = set(salt_to_dbs.keys()) - set(key_map.keys())
    if missing_salts and key_map:
        print(f"\n[*] {len(missing_salts)} salts remaining, trying cross-verification...")
        for salt_hex in list(missing_salts):
            for rel, path, sz, s, page1 in db_files:
                if s == salt_hex:
                    for known_salt, known_key_hex in key_map.items():
                        enc_key = bytes.fromhex(known_key_hex)
                        if verify_key_for_db(enc_key, page1):
                            key_map[salt_hex] = known_key_hex
                            dbs = salt_to_dbs[salt_hex]
                            print(f"  [CROSS] salt={salt_hex} uses same key as {known_salt}")
                            print(f"    databases: {', '.join(dbs)}")
                            missing_salts.discard(salt_hex)
                    break

    # 5. Detach
    process.Detach()
    print("\n[*] Detached from WeChat.")

    # 6. Save results
    print(f"\n{'=' * 60}")
    print(f"Results: {len(key_map)}/{len(salt_to_dbs)} keys found")

    result = {}
    # Load existing keys
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r") as f:
                result = json.load(f)
        except Exception:
            pass

    for rel, path, sz, salt_hex, page1 in db_files:
        if salt_hex in key_map:
            result[rel] = key_map[salt_hex]
            print(f"  ✅ {rel} ({sz / 1024 / 1024:.1f} MB)")
        else:
            print(f"  ❌ {rel} (salt={salt_hex})")

    result["__salts__"] = sorted(set(result.get("__salts__", [])) | set(key_map.keys()))

    # Store the active db_dir so decrypt_db.py can find the right source files
    if db_dirs:
        result["__db_dir__"] = db_dirs[0]

    with open(OUTPUT_FILE, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Keys saved to {OUTPUT_FILE}")

    missing = [rel for rel, _, _, s, _ in db_files if s not in key_map]
    if missing:
        print(f"\n[!] Missing keys for: {', '.join(missing)}")


if __name__ == "__main__":
    main()

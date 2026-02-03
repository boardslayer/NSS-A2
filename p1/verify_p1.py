#!/usr/bin/env python3
import argparse
import hashlib
import sys
from pathlib import Path


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def main() -> int:
    p = argparse.ArgumentParser(description="Verify NSS A2 P1 submission files")
    p.add_argument("--key", help="Path to boot.key used for this VM boot (optional if key.txt exists)")
    p.add_argument("--keytxt", default="key.txt", help="Path to key.txt (submission)")
    p.add_argument("--public", default="public.txt", help="Path to public.txt")
    p.add_argument("--private", default="private.txt", help="Path to private.txt")
    p.add_argument("--flag", default="flag.txt", help="Path to flag.txt")
    args = p.parse_args()

    key_path = Path(args.key) if args.key else Path(args.keytxt)
    if not key_path.exists():
        print("[FAIL] No key provided. Use --key or include key.txt in the submission.")
        return 2

    key = read_text(key_path)
    public = read_text(Path(args.public))
    private = read_text(Path(args.private))
    flag = read_text(Path(args.flag))

    exp_public = sha256_hex(f"PUBLIC:P1:{key}")
    exp_private = sha256_hex(f"PRIVATE:P1:{key}")
    exp_flag = sha256_hex(f"P1:{key}")

    ok = True
    if public != exp_public:
        print("[FAIL] public.txt does not match expected value")
        ok = False
    if private != exp_private:
        print("[FAIL] private.txt does not match expected value")
        ok = False
    if flag != exp_flag:
        print("[FAIL] flag.txt does not match expected value")
        ok = False

    if ok:
        print("[OK] P1 submission verified")
        return 0

    print("[INFO] Expected values:")
    print(f"public:  {exp_public}")
    print(f"private: {exp_private}")
    print(f"flag:    {exp_flag}")
    return 1


if __name__ == "__main__":
    sys.exit(main())

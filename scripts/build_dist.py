#!/usr/bin/env python3
"""
Build & Production Packaging Script for WinSecure
"""
import os
import sys
import zipfile
import hashlib

def make_zip():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    zip_path = os.path.join(base_dir, "..", "WinSecure-Production.zip")
    zip_path = os.path.abspath(zip_path)

    print(f"[*] Packaging WinSecure into {zip_path}...")

    # Exclusions
    exclude_dirs = {"__pycache__", ".pytest_cache", ".git", ".idea", "venv", ".venv", "dist", "build", "egg-info"}
    exclude_exts = {".pyc", ".pyo", ".pyd", ".DS_Store"}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.endswith(".egg-info")]
            for file in files:
                ext = os.path.splitext(file)[1]
                if ext in exclude_exts or file.startswith("."):
                    continue
                full_p = os.path.join(root, file)
                rel_p = os.path.join("WinSecure", os.path.relpath(full_p, base_dir))
                zf.write(full_p, rel_p)

    hasher = hashlib.sha256()
    with open(zip_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    sha256 = hasher.hexdigest()

    sha_file = os.path.join(os.path.dirname(zip_path), "SHA256SUMS.txt")
    with open(sha_file, "w") as f:
        f.write(f"{sha256}  WinSecure-Production.zip\n")

    print(f"[+] ZIP created successfully: {zip_path}")
    print(f"[+] SHA256: {sha256}")
    print(f"[+] SHA256SUMS.txt written to: {sha_file}")

if __name__ == "__main__":
    make_zip()

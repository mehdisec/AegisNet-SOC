"""
Helper script to download or setup offline GeoIP databases (e.g. DB-IP / MaxMind GeoLite2).
"""
import os
import urllib.request
import gzip
import shutil
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
os.makedirs(DATA_DIR, exist_ok=True)
TARGET_MMDB = DATA_DIR / "GeoLite2-City.mmdb"

def main():
    print("=" * 60)
    print("AegisNet GeoIP Database Setup Utility")
    print("=" * 60)
    
    if TARGET_MMDB.exists():
        print(f"GeoLite2-City database already present at:\n  {TARGET_MMDB}")
        return

    print("Note: AegisNet already includes a high-speed hybrid GeoIP resolver")
    print("with built-in infrastructure caching and async API resolution.")
    print("If you have a MaxMind License Key or an existing GeoLite2-City.mmdb,")
    print(f"you can place it directly at:\n  {TARGET_MMDB}\n")

if __name__ == "__main__":
    main()

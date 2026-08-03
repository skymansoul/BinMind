from __future__ import annotations

def main():
    import argparse
    p = argparse.ArgumentParser(prog="binmind-binary-analysis")
    p.add_argument("--config", default=None)
    p.add_argument("--verbose", "-v", action="store_true")
    p.parse_args()
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())

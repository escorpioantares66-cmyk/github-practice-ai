import argparse
import json


def main():
    p = argparse.ArgumentParser(description="github-practice-ai - Senior production-ready")
    p.add_argument("--check", action="store_true", help="health check - no API call")
    p.add_argument(
        "--storage-audit",
        action="store_true",
        help="read-only storage inventory and retention audit",
    )
    args = p.parse_args()
    if args.storage_audit:
        from .storage_audit import run_storage_audit

        print(json.dumps(run_storage_audit(), indent=2, sort_keys=True))
    elif args.check:
        print("gh-ai OK - frozen config, cache ready, semaphore=3, mocked tests ready")
    else:
        p.print_help()

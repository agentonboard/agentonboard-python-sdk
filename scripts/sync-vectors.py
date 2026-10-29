#!/usr/bin/env python3
"""
Syncs or checks agent-token-v1.json fixture against the canonical AgentOnboard repo.
"""

import hashlib
import sys
from pathlib import Path

CANONICAL_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "agentonboard"
    / "packages"
    / "sdk"
    / "vectors"
    / "agent-token-v1.json"
)
LOCAL_FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "agent-token-v1.json"
)


def sha256_of(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    if not CANONICAL_PATH.exists():
        print(f"Canonical file not found at {CANONICAL_PATH}; skipping sync check.")
        return 0

    local_hash = sha256_of(LOCAL_FIXTURE_PATH)
    canonical_hash = sha256_of(CANONICAL_PATH)

    if local_hash == canonical_hash:
        print("agent-token-v1.json is in sync with canonical repository.")
        return 0

    if "--check" in sys.argv:
        print(
            f"ERROR: Local fixture {LOCAL_FIXTURE_PATH} differs from {CANONICAL_PATH}!",
            file=sys.stderr,
        )
        return 1

    LOCAL_FIXTURE_PATH.write_bytes(CANONICAL_PATH.read_bytes())
    print("Updated local agent-token-v1.json from canonical source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

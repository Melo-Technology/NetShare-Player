"""Explicit CA-compromise recovery command; never runs without confirmation."""

from __future__ import annotations

import argparse
from pathlib import Path

from .identity import ClusterIdentityStore
from .key_store import default_backend

CONFIRMATION = "RESET-CLUSTER-CA"


def recover(config_dir: Path):
    store = ClusterIdentityStore(config_dir, default_backend(config_dir))
    return store.recover_compromised_ca()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Replace a compromised NetShare cluster CA.",
    )
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--confirm", required=True)
    arguments = parser.parse_args(argv)
    if arguments.confirm != CONFIRMATION:
        parser.error(f"--confirm must be exactly {CONFIRMATION}")
    recover(arguments.config_dir.resolve())
    print("Cluster CA replaced. All secondary servers must be paired again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

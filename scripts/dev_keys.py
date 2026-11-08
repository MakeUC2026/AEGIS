"""Write a local RS256 key pair for dev sign-in (DD-12) into the repo-root .env.

Usage (from backend/): uv run python ../scripts/dev_keys.py
Never commits anything: .env is git-ignored. Re-running replaces the old pair, which signs
everyone out of dev sessions.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "backend"))

from app.auth.testing import make_keys

ENV = pathlib.Path(__file__).resolve().parents[1] / ".env"
DEV_VARS = {
    "AEGIS_AUTH_MODE": "dev",
    "AEGIS_FAKE_SCRIPT": "dev",
    "AEGIS_USE_FAKES": "firewall,read,admin,risky,judge,arena",
    "AEGIS_API_URL": "http://127.0.0.1:8000",
}


def _escape(pem: str) -> str:
    return '"' + pem.strip().replace("\n", "\\n") + '"'


def main() -> None:
    keys = make_keys()
    updates = {
        **DEV_VARS,
        "AEGIS_DEV_JWT_PUBLIC_KEY": _escape(keys.public_pem),
        "AEGIS_DEV_JWT_PRIVATE_KEY": _escape(keys.private_pem),
    }
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    kept = [ln for ln in lines if ln.split("=", 1)[0] not in updates]
    ENV.write_text("\n".join([*kept, *(f"{k}={v}" for k, v in updates.items())]) + "\n")
    ENV.chmod(0o600)
    print(f"wrote dev auth settings to {ENV}")


if __name__ == "__main__":
    main()

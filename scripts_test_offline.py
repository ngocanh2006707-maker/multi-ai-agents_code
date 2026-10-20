"""Run the stub-based test suite without dotenv or third-party pytest plugins."""

import os
import sys
from unittest.mock import patch


def main() -> int:
    sys.dont_write_bytecode = True
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ.setdefault("DEFENSE_MODE", "off")
    os.environ.setdefault("TRACE_OUTPUT_DIR", "artifacts/offline_tests/traces")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    import pytest

    with patch("dotenv.load_dotenv", return_value=False):
        return pytest.main(["-p", "no:cacheprovider", *(sys.argv[1:] or ["tests", "-q"])])


if __name__ == "__main__":
    raise SystemExit(main())

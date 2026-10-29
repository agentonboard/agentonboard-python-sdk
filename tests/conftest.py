import json
from pathlib import Path

import pytest


@pytest.fixture
def fixture_data():
    fixture_path = Path(__file__).parent / "fixtures" / "agent-token-v1.json"
    with open(fixture_path, encoding="utf-8") as f:
        return json.load(f)

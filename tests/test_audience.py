import json
from pathlib import Path

from agentonboard.verify import normalize_audience


def test_audience_normalization_vectors():
    fixture_path = Path(__file__).parent / "fixtures" / "agent-token-v1.json"
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)

    for case in data["audienceNormalization"]:
        input_str = case["input"]
        expected = case["expected"]
        result = normalize_audience(input_str)
        assert result == expected, f"Failed on {case['description']}: got {result!r}, expected {expected!r}"

"""Tests for PII data masking pipeline."""
import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from dataMasker import DataMasker
from maskingRules import MaskingRules

class TestMain:
    def test_basic(self):
        obj = DataMasker()
        assert obj.process({"key": "val"}) is not None
    def test_empty(self):
        obj = DataMasker()
        assert obj.process(None) is None
    def test_stats(self):
        obj = DataMasker()
        obj.process({"x": 1})
        assert obj.get_stats()["processed"] == 1

class TestSupport:
    def test_basic(self):
        obj = MaskingRules()
        assert obj.process({"key": "val"}) is not None

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

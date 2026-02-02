"""
Simple test to verify pytest setup is working.
This test doesn't require database or FastAPI app.
"""

import pytest


def test_pytest_works():
    """Verify pytest is installed and working."""
    assert True


def test_basic_math():
    """Basic test to verify test infrastructure."""
    assert 1 + 1 == 2
    assert 2 * 3 == 6


def test_string_operations():
    """Test string operations."""
    text = "PhishNet Inbox"
    assert "Inbox" in text
    assert text.startswith("PhishNet")
    assert len(text) > 0


@pytest.mark.parametrize("input,expected", [
    (1, 2),
    (2, 4),
    (3, 6),
    (10, 20),
])
def test_double(input, expected):
    """Test parametrized test works."""
    assert input * 2 == expected


class TestBasicClass:
    """Test that class-based tests work."""
    
    def test_method_one(self):
        """First test method."""
        assert "hello".upper() == "HELLO"
    
    def test_method_two(self):
        """Second test method."""
        assert [1, 2, 3] == [1, 2, 3]

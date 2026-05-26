"""Scope-gating tests (criterion 3)."""

from __future__ import annotations

import pytest

from ouija.scope import ScopeError, assert_in_scope, load_scope


def test_scope_file_parses_hosts(scope_file):
    entries = load_scope(scope_file)
    hosts = {h for h, _ in entries}
    assert "127.0.0.1" in hosts
    assert "localhost" in hosts


def test_in_scope_target_passes(scope_file):
    # Should not raise.
    assert_in_scope("http://127.0.0.1:5000/chat", scope_file)
    assert_in_scope("http://localhost/api", scope_file)


def test_out_of_scope_target_raises(scope_file):
    with pytest.raises(ScopeError, match="out of scope"):
        assert_in_scope("https://example.com/chat", scope_file)


def test_missing_scope_file_raises():
    with pytest.raises(ScopeError, match="not found"):
        assert_in_scope("http://127.0.0.1/chat", "/no/such/scope.txt")

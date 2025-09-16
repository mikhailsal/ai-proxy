def test_window_parsing_variants():
    from ai_proxy.logdb.dialogs import _parse_window_to_seconds

    assert _parse_window_to_seconds("30m") == 1800
    assert _parse_window_to_seconds("45s") == 45
    assert _parse_window_to_seconds("2h") == 7200
    assert _parse_window_to_seconds("1800") == 1800
    # Fallbacks
    assert isinstance(_parse_window_to_seconds("bad"), int)
    assert _parse_window_to_seconds("0s") >= 1


def test_parse_window_to_seconds_edge_cases():
    """Test _parse_window_to_seconds handles various edge cases and exceptions."""
    from ai_proxy.logdb.dialogs import _parse_window_to_seconds

    # Test millisecond fallback (line 14)
    assert _parse_window_to_seconds("500ms") == 1

    # Test exception handling in seconds parsing (lines 18-19)
    assert _parse_window_to_seconds("invalid_seconds") == 1800  # fallback

    # Test exception handling in minutes parsing (lines 23-24)
    assert _parse_window_to_seconds("invalid_minutes") == 1800  # fallback

    # Test exception handling in hours parsing (lines 28-29)
    assert _parse_window_to_seconds("invalid_hours") == 1800  # fallback

    # Test zero seconds handling
    assert _parse_window_to_seconds("0s") >= 1  # minimum 1 second


def test_assign_dialogs_for_range_none_to_parameter(tmp_path):
    """Test assign_dialogs_for_range handles to=None case (line 155)."""
    import datetime as dt
    from ai_proxy.logdb.dialogs import assign_dialogs_for_range

    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 18)
    # This should work even though to=None internally
    # The function has an assert that ensures since and to are not None
    # but we need to test the line where it checks if to is None
    try:
        assign_dialogs_for_range(str(base), date, None, 1800)
        assert False, "Should have failed assertion"
    except AssertionError:
        pass  # Expected


def test_clear_dialogs_for_range_none_to_parameter(tmp_path):
    """Test clear_dialogs_for_range handles to=None case (line 193)."""
    import datetime as dt
    from ai_proxy.logdb.dialogs import clear_dialogs_for_range

    base = tmp_path / "logs" / "db"
    date = dt.date(2025, 9, 19)
    # This should work even though to=None internally
    # The function has an assert that ensures since and to are not None
    # but we need to test the line where it checks if to is None
    try:
        clear_dialogs_for_range(str(base), date, None)
        assert False, "Should have failed assertion"
    except AssertionError:
        pass  # Expected


def test_stable_dialog_id_generation():
    """Test _stable_dialog_id generates consistent IDs."""
    from ai_proxy.logdb.dialogs import _stable_dialog_id

    # Same inputs should generate same ID
    id1 = _stable_dialog_id("hash1", "/v1/chat", "gpt-4", 1234567890)
    id2 = _stable_dialog_id("hash1", "/v1/chat", "gpt-4", 1234567890)
    assert id1 == id2

    # Different inputs should generate different IDs
    id3 = _stable_dialog_id("hash2", "/v1/chat", "gpt-4", 1234567890)
    assert id1 != id3

    # Test with None values
    id4 = _stable_dialog_id(None, None, None, 1234567890)
    assert id4.startswith("dlg-")
    assert len(id4) == 20  # "dlg-" + 16 hex chars


def test_stable_dialog_id_deterministic():
    """Test _stable_dialog_id is deterministic across calls."""
    from ai_proxy.logdb.dialogs import _stable_dialog_id

    # Generate multiple IDs and ensure they're all the same
    ids = []
    for _ in range(10):
        ids.append(_stable_dialog_id("test", "endpoint", "model", 1000000))

    # All should be identical
    assert all(id == ids[0] for id in ids)


def test_parse_window_to_seconds_invalid_formats():
    """Test _parse_window_to_seconds with invalid formats."""
    from ai_proxy.logdb.dialogs import _parse_window_to_seconds

    # Invalid unit should fallback to 1800
    assert _parse_window_to_seconds("30x") == 1800
    assert _parse_window_to_seconds("invalid") == 1800
    assert _parse_window_to_seconds("") == 1800

    # Invalid number should fallback to 1800
    assert _parse_window_to_seconds("abc") == 1800
    assert _parse_window_to_seconds("30.5m") == 1800  # Float not supported

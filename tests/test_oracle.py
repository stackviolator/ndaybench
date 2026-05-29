"""Unit tests for the Level-C string-match oracle."""

from ndaybench.oracle import grade


def test_pass_exact_match() -> None:
    flag = "ndaybench{abc123}"
    result = grade(flag, f"some prefix {flag} some suffix\n")
    assert result["pass_"] is True
    assert flag in result["evidence"]


def test_fail_when_absent() -> None:
    result = grade("ndaybench{abc123}", "no flag here")
    assert result["pass_"] is False
    assert "not found" in result["evidence"]


def test_pass_with_whitespace_around_expected() -> None:
    # `grade` strips the expected_flag, so leading/trailing whitespace is ignored.
    result = grade("  ndaybench{abc123}  ", "ndaybench{abc123}")
    assert result["pass_"] is True


def test_fail_when_only_partial_match() -> None:
    result = grade("ndaybench{abc123}", "ndaybench{abc12}")  # one char short
    assert result["pass_"] is False


def test_pass_when_flag_appears_multiple_times() -> None:
    flag = "ndaybench{aaa}"
    result = grade(flag, f"{flag} and again {flag}")
    assert result["pass_"] is True

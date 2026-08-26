# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: MPL-2.0

import signal
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Adjust import to your package
from fileaudit.python_check import validate_python, PythonValidationError


def _write_simple_py(tmpdir: Path) -> Path:
    path = tmpdir / "simple.py"
    path.write_text("x = 1\n", encoding="utf-8")
    return path


def _make_alarm_fire_immediately(timeout_exc_factory):
    """
    Return a side_effect for signal.alarm that raises *immediately*
    when a positive timeout is requested. This simulates the alarm
    firing without any real sleep.
    """
    def fake_alarm(seconds):
        if seconds > 0:
            # Simulate SIGALRM delivery by raising the same exception
            # the real handler would raise.
            raise timeout_exc_factory()
        return 0  # cancelling alarm (seconds == 0)
    return fake_alarm


# ---------------------------------------------------------------------------
# Fast tests (< 0.2 s total)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    not hasattr(signal, "SIGALRM") or not hasattr(signal, "alarm"),
    reason="parse_timeout relies on SIGALRM (Unix only)",
)
def test_parse_timeout_triggers(tmp_path):
    """parse_timeout must cause validation to fail when the alarm fires."""
    py_file = _write_simple_py(tmp_path)

    # Use a generic TimeoutError; replace with the exact exception your
    # implementation raises from the SIGALRM handler if different.
    TimeoutExc = TimeoutError

    with patch("signal.alarm", side_effect=_make_alarm_fire_immediately(TimeoutExc)):
        result = validate_python(py_file, parse_timeout=1)
        assert result is False


@pytest.mark.skipif(
    not hasattr(signal, "SIGALRM") or not hasattr(signal, "alarm"),
    reason="parse_timeout relies on SIGALRM (Unix only)",
)
def test_parse_timeout_does_not_fire_for_fast_parse(tmp_path):
    """Normal file succeeds when timeout is large enough (no mock needed)."""
    py_file = _write_simple_py(tmp_path)
    assert validate_python(py_file, parse_timeout=5) is True


@pytest.mark.skipif(
    not hasattr(signal, "SIGALRM") or not hasattr(signal, "alarm"),
    reason="parse_timeout relies on SIGALRM (Unix only)",
)
def test_parse_timeout_in_decorator_mode(tmp_path):
    """Decorator mode raises PythonValidationError on timeout."""
    py_file = _write_simple_py(tmp_path)

    @validate_python(parse_timeout=1)
    def process(path):
        return "ok"

    with patch("signal.alarm", side_effect=_make_alarm_fire_immediately(TimeoutError)):
        with pytest.raises(PythonValidationError):
            process(py_file)


def test_parse_timeout_ignored_when_no_sigalrm(tmp_path, monkeypatch):
    """Without SIGALRM the option is a no-op; valid files still pass."""
    if hasattr(signal, "SIGALRM"):
        monkeypatch.delattr(signal, "SIGALRM", raising=False)

    py_file = _write_simple_py(tmp_path)
    assert validate_python(py_file, parse_timeout=1) is True


@pytest.mark.skipif(
    not hasattr(signal, "SIGALRM") or not hasattr(signal, "alarm"),
    reason="parse_timeout relies on SIGALRM (Unix only)",
)
def test_parse_timeout_zero_disables_alarm(tmp_path):
    """parse_timeout=0 must not arm the alarm; validation succeeds."""
    py_file = _write_simple_py(tmp_path)

    # Even if alarm is patched, a call with 0 should just cancel and succeed.
    with patch("signal.alarm", side_effect=_make_alarm_fire_immediately(TimeoutError)) as mock_alarm:
        result = validate_python(py_file, parse_timeout=0)
        assert result is True
        # Optional: verify that a positive alarm was never requested
        for call in mock_alarm.call_args_list:
            assert call.args[0] == 0 or call.args[0] is None
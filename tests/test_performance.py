"""Performance test — decision time must be under 10ms.

blastradius is in the hot path of every agent command. If it's slow,
people disable it.
"""

from __future__ import annotations

import time

import pytest

from blastradius.check import check_command


class TestPerformance:
    """Decision time must be under 10ms on every path."""

    def _bench(self, command: str, iterations: int = 100) -> float:
        """Return the minimum decision time in milliseconds."""
        # Warm up
        check_command(command)
        times = []
        for _ in range(iterations):
            t = time.perf_counter()
            check_command(command)
            times.append((time.perf_counter() - t) * 1000)
        return min(times)

    def test_floor_path_under_10ms(self):
        ms = self._bench("rm -rf /")
        assert ms < 10.0, f"floor path took {ms:.2f}ms (must be <10ms)"

    def test_empty_variable_under_10ms(self):
        ms = self._bench('rm -rf "$UNSET_VAR/foo"')
        assert ms < 10.0, f"empty variable took {ms:.2f}ms (must be <10ms)"

    def test_allowed_path_under_10ms(self):
        ms = self._bench("rm -rf /tmp/blastradius-test/foo")
        assert ms < 10.0, f"allowed path took {ms:.2f}ms (must be <10ms)"

    def test_non_destructive_under_10ms(self):
        ms = self._bench("ls -la")
        assert ms < 10.0, f"non-destructive took {ms:.2f}ms (must be <10ms)"

    def test_tilde_under_10ms(self):
        ms = self._bench("rm -rf ~/foo")
        assert ms < 10.0, f"tilde check took {ms:.2f}ms (must be <10ms)"

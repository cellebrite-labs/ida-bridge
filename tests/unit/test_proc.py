"""Unit tests for process lifecycle primitives."""

import os
import subprocess
import sys
import time

import pytest

from ida_bridge.proc import is_pid_alive, terminate_pid, wait_for_exit


class TestIsPidAlive:
    @pytest.mark.skipif(sys.platform == "win32", reason="zombies are POSIX-only")
    def test_returns_false_for_zombie_child(self) -> None:
        """is_pid_alive must detect zombie (exited but un-reaped) children."""
        child = subprocess.Popen([sys.executable, "-c", ""])
        # Let child exit; don't call child.wait() so it remains a zombie.
        time.sleep(0.2)

        try:
            os.kill(child.pid, 0)
        except ProcessLookupError:
            pytest.skip("child already reaped")

        assert not is_pid_alive(child.pid)

    def test_returns_false_for_nonexistent_pid(self) -> None:
        assert not is_pid_alive(2_000_000_000)

    def test_returns_true_for_own_process(self) -> None:
        assert is_pid_alive(os.getpid())


class TestWaitForExit:
    def test_returns_true_when_process_exits(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(0.1)"])
        assert wait_for_exit(child.pid, timeout_s=5.0)
        child.wait()

    def test_returns_false_on_timeout(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            assert not wait_for_exit(child.pid, timeout_s=0.2)
        finally:
            child.kill()
            child.wait()


class TestTerminatePid:
    def test_already_dead(self) -> None:
        assert terminate_pid(2_000_000_000) == "already_dead"

    def test_sigterm(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            # Windows has no SIGTERM: terminate_pid is a hard TerminateProcess
            # and reports "sigkill". POSIX gets a graceful SIGTERM.
            expected = "sigkill" if sys.platform == "win32" else "sigterm"
            assert terminate_pid(child.pid, timeout_s=5.0) == expected
            assert not is_pid_alive(child.pid)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()

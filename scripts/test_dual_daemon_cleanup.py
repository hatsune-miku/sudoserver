"""Regression tests for the Unix dual-daemon smoke test's teardown."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, call, patch

spec = importlib.util.spec_from_file_location(
    "dual_daemon", Path(__file__).with_name("test-dual-daemon.py")
)
daemon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(daemon)


class CleanupTests(unittest.TestCase):
    def process(self, pid=1234):
        return Mock(pid=pid, poll=Mock(return_value=None))

    def test_user_signal_uses_process_group_api(self):
        with patch.object(daemon.os, "killpg", create=True) as killpg:
            daemon.signal_group(self.process(), False, signal.SIGTERM)
        killpg.assert_called_once_with(1234, signal.SIGTERM)

    def test_exited_group_is_harmless(self):
        with patch.object(daemon.os, "killpg", create=True, side_effect=ProcessLookupError):
            daemon.signal_group(self.process(), False, signal.SIGTERM)

    def test_elevated_signal_uses_checked_bounded_helper(self):
        with patch.object(daemon.subprocess, "run") as run:
            daemon.signal_group(self.process(), True, signal.SIGTERM)
        args = run.call_args.args[0]
        self.assertEqual(args[:5], ["sudo", "-n", "--", sys.executable, "-c"])
        self.assertEqual(args[6:], ["1234", str(int(signal.SIGTERM))])
        self.assertEqual(run.call_args.kwargs, {"check": True, "timeout": 5})
        with patch.object(os, "killpg", create=True) as killpg:
            with patch.object(sys, "argv", ["-c", *args[6:]]):
                exec(args[5])
        killpg.assert_called_once_with(1234, int(signal.SIGTERM))

    def test_graceful_cleanup_in_reverse_order(self):
        root, user = self.process(1234), self.process(5678)
        with patch.object(daemon, "signal_group") as send:
            daemon.stop_processes([(root, True), (user, False)])
        self.assertEqual(send.call_args_list, [
            call(user, False, signal.SIGTERM), call(root, True, signal.SIGTERM),
        ])
        user.wait.assert_called_once_with(timeout=10)
        root.wait.assert_called_once_with(timeout=10)

    @patch.object(daemon.signal, "SIGKILL", 9, create=True)
    def test_timeout_escalates_to_kill(self):
        process = self.process()
        process.wait.side_effect = [subprocess.TimeoutExpired("daemon", 10), 0]
        with patch.object(daemon, "signal_group") as send:
            daemon.stop_processes([(process, False)])
        self.assertEqual(send.call_args_list, [
            call(process, False, signal.SIGTERM), call(process, False, signal.SIGKILL),
        ])
        self.assertEqual(process.wait.call_args_list, [call(timeout=10), call(timeout=5)])

    @patch.object(daemon.signal, "SIGKILL", 9, create=True)
    def test_failure_does_not_skip_other_daemon(self):
        root, user = self.process(1234), self.process(5678)
        with patch.object(daemon, "signal_group", side_effect=[PermissionError(), PermissionError(), None]) as send:
            with self.assertRaisesRegex(RuntimeError, "daemon 5678"):
                daemon.stop_processes([(root, True), (user, False)])
        self.assertEqual(send.call_args_list[-1], call(root, True, signal.SIGTERM))
        root.wait.assert_called_once_with(timeout=10)

    def test_already_exited_process_is_skipped(self):
        process = self.process()
        process.poll.return_value = 0
        with patch.object(daemon, "signal_group") as send:
            daemon.stop_processes([(process, False)])
        send.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Real Unix process groups")
    def test_real_process_group_signals(self):
        for ignore_term in (False, True):
            with self.subTest(ignore_term=ignore_term):
                code = "import signal, time\n"
                if ignore_term:
                    code += "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                code += "print('ready', flush=True)\ntime.sleep(60)\n"
                with subprocess.Popen([sys.executable, "-c", code], start_new_session=True,
                                      stdout=subprocess.PIPE, text=True) as process:
                    try:
                        self.assertEqual(process.stdout.readline().strip(), "ready")
                        daemon.signal_group(process, False, signal.SIGTERM)
                        if ignore_term:
                            with self.assertRaises(subprocess.TimeoutExpired):
                                process.wait(timeout=0.1)
                            daemon.signal_group(process, False, signal.SIGKILL)
                        process.wait(timeout=5)
                        self.assertEqual(process.returncode, -(signal.SIGKILL if ignore_term else signal.SIGTERM))
                    finally:
                        if process.poll() is None:
                            os.killpg(process.pid, signal.SIGKILL)
                            process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

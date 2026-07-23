import os
import re
import subprocess
import sys
import threading
import unittest
from http.server import HTTPServer

from src.web_server import MX2SandboxHTTPHandler


class TestMX2ControlCLI(unittest.TestCase):
    """Integration test suite for the mx2ctl command line utility."""

    @classmethod
    def setUpClass(cls) -> None:
        # Start HTTPServer on loopback with port 0 (OS chooses a random free port)
        cls.server = HTTPServer(("127.0.0.1", 0), MX2SandboxHTTPHandler)
        cls.host, cls.port = cls.server.server_address
        cls.base_url = f"http://{cls.host}:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def _run_cli(self, args: list[str]) -> tuple[int, str, str]:
        """Runs the mx2ctl CLI as a subprocess and strips ANSI escape codes."""
        cmd = [sys.executable, "mx2ctl.py"] + args
        # Pass target port via environment variable
        env = {**os.environ, "MX2_URL": self.base_url}
        res = subprocess.run(cmd, capture_output=True, text=True, env=env)

        # Strip ANSI escape sequences (colors) from output
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_stdout = ansi_escape.sub('', res.stdout)
        clean_stderr = ansi_escape.sub('', res.stderr)

        return res.returncode, clean_stdout, clean_stderr

    def test_cli_no_args_prints_help(self) -> None:
        """Tests that running mx2ctl with no arguments prints the help message."""
        code, stdout, stderr = self._run_cli([])
        self.assertEqual(code, 0)
        self.assertIn("usage: mx2ctl", stdout)
        self.assertIn("subcommands", stdout)

    def test_cli_help_flag(self) -> None:
        """Tests that running mx2ctl --help prints the help message."""
        code, stdout, stderr = self._run_cli(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("usage: mx2ctl", stdout)

    def test_cli_resolve_did(self) -> None:
        """Tests cryptographically resolving a direct DID identifier."""
        code, stdout, stderr = self._run_cli(["resolve", "did:mx2:mockKey123"])
        self.assertEqual(code, 0)
        self.assertIn("Resolving identifier: did:mx2:mockKey123", stdout)
        self.assertIn("Resolved direct DID public key: mockKey123", stdout)

    def test_cli_resolve_domain(self) -> None:
        """Tests cryptographically resolving a domain TXT record key."""
        code, stdout, stderr = self._run_cli(["resolve", "example.com"])
        self.assertEqual(code, 0)
        self.assertIn("Resolving identifier: example.com", stdout)
        self.assertIn("Found SRV: Port 443 -> mx2.example.com", stdout)
        self.assertIn("Found TXT: v=MX2", stdout)

    def test_cli_daemon_dependent_commands(self) -> None:
        """Tests commands that query the daemon."""

        # Test Status
        code, stdout, stderr = self._run_cli(["status"])
        self.assertEqual(code, 0)
        self.assertIn("MX2 GATEWAY DAEMON STATUS", stdout)
        self.assertIn("Daemon State : RUNNING", stdout)

        # Test Test Translation
        code, stdout, stderr = self._run_cli(["test", "--subject", "CLI Test Email"])
        self.assertEqual(code, 0)
        self.assertIn("Daemon Response Received!", stdout)
        self.assertIn("Status       : JUNK", stdout)


if __name__ == "__main__":
    unittest.main()

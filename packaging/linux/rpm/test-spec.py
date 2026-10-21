"""Fast packaging contract checks; the Fedora install test is still required."""

from pathlib import Path
import unittest


SPEC = Path(__file__).with_name("synthaea-agent.spec.template")


class RpmLifecycleTests(unittest.TestCase):
    def test_config_is_shipped_without_replacing_operator_edits(self):
        spec = SPEC.read_text()
        self.assertIn("crates/config/data/default-agent.toml", spec)
        self.assertIn("%config(noreplace) /etc/synthaea/agent.toml", spec)

    def test_erase_uses_safe_cleanup_and_preserves_logs(self):
        spec = SPEC.read_text()
        preun = spec.split("%preun\n", 1)[1].split("%postun\n", 1)[0]
        self.assertIn('if [ "$1" -eq 0 ]; then', preun)
        self.assertIn("runuser -u synthaea", preun)
        self.assertIn("cleanup-deception", preun)
        self.assertNotIn("rm -rf /var/lib/synthaea /var/log/synthaea", spec)
        self.assertNotIn("userdel synthaea", spec)


if __name__ == "__main__":
    unittest.main()

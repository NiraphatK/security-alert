"""Offline health-notice checks: python3 -B test_workflow.py (requires jq)."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).with_name(".github") / "workflows" / "watch.yml"
STUB = r'''
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if Path(sys.argv[0]).name == "gh":
    assert args[:2] == ["run", "list"], args
    assert args[args.index("-w") + 1] == "watch.yml", args
    assert args[args.index("-s") + 1] == "completed", args
    limit = int(args[args.index("-L") + 1])
    assert 1 <= limit <= 100, args
    query = args[args.index("-q" if "-q" in args else "--jq") + 1]
    history = json.loads(Path(os.environ["HISTORY"]).read_text())[:limit]
    result = subprocess.run([os.environ["JQ"], "-r", query], input=json.dumps(history),
                            text=True, capture_output=True, check=True)
    sys.stdout.write(result.stdout)
else:
    assert Path(sys.argv[0]).name == "curl", sys.argv
    assert "https://discord.invalid/offline" in args, args
    payload = json.loads(args[args.index("-d") + 1])
    with Path(os.environ["NOTICES"]).open("a") as output:
        output.write(json.dumps(payload) + "\n")
'''


class HealthNotices(unittest.TestCase):
    def notice(self, step, history):
        section = WORKFLOW.read_text().split(f"      - name: Tell Discord the watcher {step}\n", 1)[1]
        script = re.search(r"        run: \|\n((?:          .*\n|\n)+)", section).group(1)
        jq = shutil.which("jq")
        self.assertIsNotNone(jq, "Install jq to run the workflow checks")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for command in ("gh", "curl"):
                executable = root / command
                executable.write_text(f"#!{sys.executable}\n" + STUB)
                executable.chmod(0o700)
            (root / "history.json").write_text(json.dumps([{"conclusion": c} for c in history]))
            env = {"PATH": directory, "HISTORY": str(root / "history.json"), "JQ": jq,
                   "NOTICES": str(root / "notices.jsonl"), "DISCORD_WEBHOOK": "https://discord.invalid/offline",
                   "RUN": "https://github.invalid/actions/runs/1"}
            result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                     textwrap.dedent(script)], cwd=root, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            notices = root / "notices.jsonl"
            return [json.loads(line) for line in notices.read_text().splitlines()] if notices.exists() else []

    def test_failure_ignores_cancelled_and_skipped(self):
        self.assertEqual(self.notice("broke", ["cancelled", "skipped", "failure", "success"]), [])

    def test_recovery_ignores_cancelled_and_skipped(self):
        notices = self.notice("recovered", ["skipped", "cancelled", "failure", "success"])
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["embeds"][0]["color"], 3187820)

    def test_last_success_starts_failure_and_suppresses_duplicate_recovery(self):
        history = ["cancelled", "skipped", "success", "failure"]
        self.assertEqual(len(self.notice("broke", history)), 1)
        self.assertEqual(self.notice("recovered", history), [])

    def test_duplicate_failure_is_suppressed(self):
        self.assertEqual(self.notice("broke", ["failure"]), [])

    def test_empty_or_inconclusive_history(self):
        for history in ([], ["cancelled", "skipped"]):
            with self.subTest(history=history):
                self.assertEqual(len(self.notice("broke", history)), 1)
                self.assertEqual(self.notice("recovered", history), [])


if __name__ == "__main__":
    unittest.main()

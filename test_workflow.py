"""Offline workflow checks: python3 -B test_workflow.py (health notices require jq)."""
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


def step_script(name):
    section = WORKFLOW.read_text().split(f"      - name: {name}\n", 1)[1]
    return textwrap.dedent(re.search(r"        run: \|\n((?:          .*\n|\n)+)", section).group(1))


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
        script = step_script(f"Tell Discord the watcher {step}")
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
                                     script], cwd=root, env=env, text=True, capture_output=True)
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


SAVE_STUB = r'''
import json
import os
from pathlib import Path
import sys

command, args = Path(sys.argv[0]).name, sys.argv[1:]
log = Path(os.environ["SAVE_CALLS"])
calls = json.loads(log.read_text())
calls.append([command, *args])
log.write_text(json.dumps(calls))
fixture = json.loads(Path(os.environ["SAVE_FIXTURE"]).read_text())
if command == "date":
    assert args == ["-u", "+%FT%TZ"], args
    print("2026-10-30T14:20:45Z")
elif command == "sleep":
    assert args in (["5"], ["10"]), args
elif command == "git":
    if args == ["add", "state.json"]:
        pass
    elif args == ["diff", "--cached", "--quiet"]:
        sys.exit(1 if fixture["changed"] else 0)
    elif args[:1] == ["-c"]:
        assert args[4:6] == ["commit", "-qm"], args
    elif args == ["pull", "-q", "--rebase"]:
        attempts = sum(c == ["git", "pull", "-q", "--rebase"] for c in calls)
        sys.exit(1 if attempts == fixture["pull_failure"] else 0)
    elif args == ["push", "-q"]:
        attempts = sum(c == ["git", "push", "-q"] for c in calls)
        if attempts <= fixture["push_failures"]:
            print("remote: fatal error in commit_refs", file=sys.stderr)
            sys.exit(1)
    else:
        raise AssertionError(args)
else:
    raise AssertionError(command)
'''


class SaveState(unittest.TestCase):
    def save(self, push_failures=0, pull_failure=False, changed=True, has_state=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for command in ("git", "sleep", "date"):
                executable = root / command
                executable.write_text(f"#!{sys.executable}\n" + SAVE_STUB)
                executable.chmod(0o700)
            state = '{"seen":{"news:delivered":"2026-10-30T14:20:00Z"}}\n'
            if has_state:
                (root / "state.json").write_text(state)
            (root / "calls.json").write_text("[]")
            (root / "fixture.json").write_text(json.dumps({"changed": changed, "pull_failure": pull_failure,
                                                          "push_failures": push_failures}))
            env = {"PATH": directory, "SAVE_CALLS": str(root / "calls.json"),
                   "SAVE_FIXTURE": str(root / "fixture.json")}
            result = subprocess.run(["/bin/bash", "--noprofile", "--norc", "-eo", "pipefail", "-c",
                                     step_script("Save state")], cwd=root, env=env, text=True, capture_output=True)
            if has_state:
                self.assertEqual((root / "state.json").read_text(), state)
            return result, json.loads((root / "calls.json").read_text())

    def test_transient_push_failure_retries_state_only(self):
        for failures, expected, sleeps in [
            (0, ["pull", "push"], []),
            (1, ["pull", "push", "pull", "push"], [["sleep", "5"]]),
            (2, ["pull", "push", "pull", "push", "pull", "push"], [["sleep", "5"], ["sleep", "10"]]),
        ]:
            with self.subTest(failures=failures):
                result, calls = self.save(push_failures=failures)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([c[1] for c in calls if c[:2] in (["git", "pull"], ["git", "push"])], expected)
                self.assertEqual(sum(c[:2] == ["git", "-c"] for c in calls), 1)
                self.assertEqual([c for c in calls if c[0] == "sleep"], sleeps)

    def test_exhausted_push_retries_still_fail(self):
        result, calls = self.save(push_failures=3)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(c == ["git", "push", "-q"] for c in calls), 3)
        self.assertEqual(sum(c[:2] == ["git", "-c"] for c in calls), 1)
        self.assertEqual([c for c in calls if c[0] == "sleep"], [["sleep", "5"], ["sleep", "10"]])

    def test_pull_or_rebase_failure_stops_before_push(self):
        for failure_on, push_failures, expected_pushes, sleeps in [(1, 0, 0, []), (2, 1, 1, [["sleep", "5"]])]:
            with self.subTest(failure_on=failure_on):
                result, calls = self.save(pull_failure=failure_on, push_failures=push_failures)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sum(c == ["git", "pull", "-q", "--rebase"] for c in calls), failure_on)
                self.assertEqual(sum(c == ["git", "push", "-q"] for c in calls), expected_pushes)
                self.assertEqual([c for c in calls if c[0] == "sleep"], sleeps)

    def test_unchanged_or_missing_state_does_not_commit_or_push(self):
        for fixture in ({"changed": False}, {"has_state": False}):
            with self.subTest(fixture=fixture):
                result, calls = self.save(**fixture)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(c[0] != "git" or c[1] not in {"add", "diff"} for c in calls))


if __name__ == "__main__":
    unittest.main()

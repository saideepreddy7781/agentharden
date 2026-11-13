"""The interactive scan: copy the prompt automatically, then copy again / rescan / open on one key."""
import argparse
import contextlib
import io
import os
import unittest
from unittest import mock

from agentharden import cli


def args(**kw):
    base = {"no_copy": False, "quiet": False, "json": False, "print_prompt": False, "fail_on": None, "strict": False,
            "copy": False}
    return argparse.Namespace(**{**base, **kw})


class Tty(io.StringIO):
    def isatty(self):
        return True


class InteractiveDetectionTest(unittest.TestCase):
    def check(self, expected, ci=False, tty=True, **kw):
        stream = Tty() if tty else io.StringIO()
        env = {k: v for k, v in os.environ.items() if k != "CI"}
        if ci:
            env["CI"] = "true"
        with mock.patch.dict(os.environ, env, clear=True), mock.patch("sys.stdin", stream), \
                mock.patch("sys.stdout", stream):
            self.assertEqual(cli._interactive(args(**kw)), expected, kw)

    def test_person_at_a_terminal(self):
        self.check(True)

    def test_never_in_ci_pipes_hooks_or_output_modes(self):
        self.check(False, ci=True)
        self.check(False, tty=False)
        for flag in ("no_copy", "quiet", "json", "print_prompt", "strict"):
            self.check(False, **{flag: True})
        self.check(False, fail_on="high")  # the pre-commit hook and CI gates

    def test_pre_commit_hook_opts_out_explicitly(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, ".pre-commit-hooks.yaml"), encoding="utf-8") as fh:
            self.assertIn("--no-copy", fh.read())


class MenuTest(unittest.TestCase):
    def run_menu(self, keys, scans=(), copy_ok=True):
        copies = []
        keys, scans = iter(keys), iter(scans)
        buf = io.StringIO()
        with mock.patch.object(cli, "read_key", lambda: next(keys)), \
                mock.patch.object(cli, "copy_to_clipboard", lambda t: copies.append(t) or copy_ok), \
                mock.patch.object(cli, "_scan_once", lambda a: next(scans)), \
                mock.patch.object(cli, "open_file", lambda p: True), contextlib.redirect_stdout(buf):
            rc = cli._menu(args(), 1, "prompt v1", "/r/.agentharden/FIX_PROMPT.md", 0)
        return rc, copies, buf.getvalue()

    def test_copies_at_once_then_again_on_c(self):
        rc, copies, out = self.run_menu(["c", "q"])
        self.assertEqual(copies, ["prompt v1", "prompt v1"])
        self.assertEqual(out.count("Prompt copied"), 2)
        self.assertEqual(rc, 1)

    def test_rescan_reports_the_level_and_copies_the_new_prompt(self):
        rc, copies, out = self.run_menu(["r", "q"], scans=[(0, "prompt v2", "/r/p.md", 2)])
        self.assertEqual(copies, ["prompt v1", "prompt v2"])
        self.assertIn("L0 Exposed → L2 Baseline (up)", out)
        self.assertEqual(rc, 0)

    def test_any_other_key_ctrl_c_or_enter_quits(self):
        for key in ("q", "\n", "\x1b", "x"):
            _, copies, _ = self.run_menu([key])
            self.assertEqual(len(copies), 1)
        with mock.patch.object(cli, "read_key", side_effect=KeyboardInterrupt), \
                mock.patch.object(cli, "copy_to_clipboard", lambda t: True), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli._menu(args(), 0, "p", "/r/p.md", 2), 0)

    def test_no_clipboard_says_so_and_names_the_file(self):
        _, _, out = self.run_menu(["q"], copy_ok=False)
        self.assertIn("Could not reach the clipboard", out)
        self.assertNotIn("Prompt copied", out)


class CopyTest(unittest.TestCase):
    def test_a_failing_clipboard_tool_is_not_reported_as_copied(self):
        with mock.patch("shutil.which", lambda name: "/usr/bin/" + name), \
                mock.patch("subprocess.run", return_value=mock.Mock(returncode=1)):
            self.assertFalse(cli.copy_to_clipboard("x"))

    def test_first_working_tool_wins(self):
        calls = []

        def run(cmd, **kw):
            calls.append(cmd[0])
            return mock.Mock(returncode=0 if cmd[0] == "xclip" else 1)

        with mock.patch("shutil.which", lambda name: None if name == "pbcopy" else "/usr/bin/" + name), \
                mock.patch("subprocess.run", side_effect=run):
            self.assertTrue(cli.copy_to_clipboard("x"))
        self.assertEqual(calls, ["wl-copy", "xclip"])


if __name__ == "__main__":
    unittest.main()

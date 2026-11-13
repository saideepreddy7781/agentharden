"""Privacy of everything agentharden writes: no secret value or personal email in the prompt, the terminal summary,
report.json or SARIF, whichever field of the repository it came from."""
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from agentharden import cli, prompt, scanner, secrets

# Assembled at runtime so this file never holds a string in a real key format.
STRIPE = "sk_" + "live_" + "51HqLyjWDarjtT1zdp7dcXYZ"
GITHUB = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
EMAIL = "priya.sharma" + "@" + "acme-corp.com"


class MaskEmailsTest(unittest.TestCase):
    def test_masks_personal_addresses_and_keeps_the_domain(self):
        self.assertEqual(secrets.mask_emails(f"owner = '{EMAIL}'"), "owner = 'p***@acme-corp.com'")

    def test_leaves_reserved_domains_code_and_package_scopes_alone(self):
        for text in ("admin@example.com", "x@test.example.org", "a@localhost", "@app.get('/x')", "@types/node",
                     "matrix = a @ b", "npm i @scope/pkg@1.2.3"):
            self.assertEqual(secrets.mask_emails(text), text)

    def test_scrub_is_idempotent(self):
        once = secrets.scrub(f"{EMAIL} token={STRIPE}")
        self.assertEqual(secrets.scrub(once), once)
        self.assertNotIn(STRIPE, once)
        self.assertNotIn("priya.sharma", once)


class NoLeakTest(unittest.TestCase):
    """Plant values where agentharden copies text from, then check every output."""

    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp())
        (cls.root / "app").mkdir()
        (cls.root / "app" / "main.py").write_text(
            "from flask import Flask, request\nimport requests, subprocess\napp = Flask(__name__)\n\n"
            f'@app.get("/hook/{STRIPE}")\ndef hook():\n    return "ok"\n\n'
            '@app.route("/run")\ndef run():\n'
            f'    cmd = request.args["c"] + " --token={GITHUB} --mail={EMAIL}"\n'
            "    return subprocess.run(cmd, shell=True)\n")
        (cls.root / "app" / f"export_{STRIPE}.py").write_text("import os\nos.system(input())\n")
        subprocess.run(["git", "init", "-q", str(cls.root)], check=True, capture_output=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["scan", str(cls.root), "--no-external", "--sarif", "--no-copy"])
        cls.outputs = {"terminal": buf.getvalue()}
        for name in ("FIX_PROMPT.md", "report.json", "results.sarif"):
            cls.outputs[name] = (cls.root / ".agentharden" / name).read_text(encoding="utf-8")

    def test_planted_values_were_really_exercised(self):
        text = self.outputs["FIX_PROMPT.md"]
        self.assertIn("/hook/", text)          # the route list
        self.assertIn("chars redacted].py:2", text)  # a file name in a location, masked
        self.assertIn("--token=", text)        # a code line

    def test_no_secret_or_email_in_any_output(self):
        for name, text in self.outputs.items():
            for value in (STRIPE, GITHUB, "priya.sharma"):
                self.assertNotIn(value, text, f"{value[:6]}… leaked into {name}")

    def test_reports_stay_valid_json(self):
        json.loads(self.outputs["report.json"])
        json.loads(self.outputs["results.sarif"])

    def test_terminal_tells_the_user_what_the_prompt_holds(self):
        line = next(ln for ln in self.outputs["terminal"].splitlines() if "Privacy" in ln)
        self.assertIn("masked", line)
        self.assertIn("nothing is sent anywhere", line)


class OfflineTest(unittest.TestCase):
    def test_a_scan_opens_no_network_connection(self):
        import socket
        from unittest import mock

        def refuse(*a, **kw):
            raise AssertionError("agentharden scan tried to open a network connection")

        root = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-app"
        with mock.patch.object(socket.socket, "connect", refuse), \
                mock.patch.object(socket.socket, "connect_ex", refuse), \
                mock.patch.object(socket, "create_connection", refuse), \
                mock.patch.object(socket, "getaddrinfo", refuse):
            result = scanner.run(str(root), external=False)
            text, _, _ = prompt.build(result, audit=True)
        self.assertTrue(result.findings)
        self.assertIn("## Security audit", text)


class NoCodeTest(unittest.TestCase):
    def test_no_code_prompt_has_locations_but_no_code_lines(self):
        root = Path(tempfile.mkdtemp())
        (root / "app.py").write_text("import subprocess\n\n\ndef run(c):\n    return subprocess.run(c, shell=True)\n")
        result = scanner.run(str(root), external=False)
        with_code, _, _ = prompt.build(result)
        no_code, _, _ = prompt.build(result, quote_code=False)
        self.assertIn("shell=True", with_code)
        self.assertNotIn("subprocess.run(c, shell=True)", no_code)
        self.assertIn("location: app.py:5", no_code)
        self.assertIn("This prompt quotes no code", no_code)
        self.assertIn("no code quoted", prompt.privacy_summary(no_code))


if __name__ == "__main__":
    unittest.main()

import json
import io
import unittest
from contextlib import redirect_stderr
from contextlib import redirect_stdout

from email_triage.cli import build_parser, email_input_from_json


class CliTest(unittest.TestCase):
    def test_parser_has_required_commands(self):
        parser = build_parser()
        args = parser.parse_args(["models"])

        self.assertEqual(args.command, "models")

    def test_parser_prints_version(self):
        parser = build_parser()
        output = io.StringIO()

        with redirect_stdout(output), self.assertRaises(SystemExit) as raised:
            parser.parse_args(["--version"])

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("email-triage 0.3.2", output.getvalue())

    def test_parser_has_serve_command(self):
        parser = build_parser()
        args = parser.parse_args(["serve", "--port", "8012"])

        self.assertEqual(args.command, "serve")
        self.assertEqual(args.model_path, "small")
        self.assertEqual(args.port, 8012)

    def test_parser_has_download_command(self):
        parser = build_parser()
        args = parser.parse_args(["download", "--model", "small"])

        self.assertEqual(args.command, "download")
        self.assertEqual(args.model, "small")

    def test_parser_has_prompt_injection_gate_args(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "triage",
                "--prompt-injection-gate",
                "heuristic",
                "--subject",
                "Hello",
                "--body",
                "Need support",
            ]
        )

        self.assertEqual(args.prompt_injection_gate, "heuristic")

    def test_parser_rejects_removed_classifier_gate(self):
        parser = build_parser()

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "triage",
                    "--prompt-injection-gate",
                    "classifier",
                    "--subject",
                    "Hello",
                    "--body",
                    "Need support",
                ]
            )

    def test_parser_rejects_backend_option(self):
        parser = build_parser()

        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "triage",
                    "--backend",
                    "openai",
                    "--subject",
                    "Hello",
                    "--body",
                    "Need support",
                ]
            )

    def test_email_input_from_json_accepts_content_alias(self):
        email_input = email_input_from_json({"subject": "Hello", "content": "Need support"})

        self.assertEqual(email_input.subject, "Hello")
        self.assertEqual(email_input.body, "Need support")

    def test_models_command_shape(self):
        parser = build_parser()
        args = parser.parse_args(["models"])
        output = io.StringIO()
        with redirect_stdout(output):
            args.func(args)
        rows = json.loads(output.getvalue())

        self.assertEqual(rows[0]["preset"], "small")
        self.assertEqual(rows[0]["repo"], "tunedtensor/email-triage-v1-gguf")
        self.assertEqual(rows[0]["filename"], "email-triage-v1-Q5_K_M.gguf")
        self.assertEqual(rows[0]["api_model"], "email-triage-v1")


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from email_triage.serve import run_llama_server


class ServeTest(unittest.TestCase):
    def test_run_llama_server_disables_prompt_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_path = Path(tmp) / "model.gguf"
            model_path.write_text("fake", encoding="utf-8")

            with patch("email_triage.serve.find_llama_server", return_value="/bin/echo"):
                with patch("email_triage.serve.subprocess.run") as run:
                    run.return_value.returncode = 0

                    exit_code = run_llama_server(model_path=model_path)

        self.assertEqual(exit_code, 0)
        command = run.call_args.args[0]
        self.assertIn("--cache-ram", command)
        self.assertEqual(command[command.index("--cache-ram") + 1], "0")


if __name__ == "__main__":
    unittest.main()

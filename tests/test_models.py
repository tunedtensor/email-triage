import tempfile
import unittest
from pathlib import Path

from email_triage.models import (
    MODEL_PRESETS,
    ModelDownloadError,
    local_model_path,
    resolve_gguf_model_path,
    resolve_model_id,
)


class ModelsTest(unittest.TestCase):
    def test_small_resolves_to_local_api_model_name(self):
        self.assertEqual(resolve_model_id("small"), "email-triage")

    def test_local_model_path_uses_gguf_repo_and_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            path = local_model_path(MODEL_PRESETS["small"], Path(directory))

        self.assertIn("tunedtensor--email-triage-gguf", str(path))
        self.assertEqual(path.name, "email-triage-Q5_K_M.gguf")

    def test_resolve_gguf_model_path_accepts_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "model.gguf"
            path.write_bytes(b"gguf")

            self.assertEqual(resolve_gguf_model_path(str(path)), path)

    def test_resolve_gguf_model_path_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.gguf"

            with self.assertRaisesRegex(ModelDownloadError, "does not exist"):
                resolve_gguf_model_path(str(path))


if __name__ == "__main__":
    unittest.main()

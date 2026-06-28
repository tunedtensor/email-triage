import unittest
from unittest.mock import patch

import email_triage


class ApiTest(unittest.TestCase):
    def test_package_triage_function(self):
        class FakeBackend:
            def generate(self, prompt, *, max_new_tokens, temperature):
                return (
                    '{"triage":"reply","priority":"normal",'
                    '"should_process":true,"confidence":0.82,'
                    '"summary":"Sender asks for help with billing.",'
                    '"reason":"Direct support request requires a response."}'
                )

        with patch("email_triage.api.create_backend", return_value=FakeBackend()):
            decision = email_triage.triage(
                "Can you help me with billing?",
                subject="Need help",
                api_base="http://127.0.0.1:8011/v1",
                prompt_injection_gate="heuristic",
            )

        self.assertEqual(decision["triage"], "reply")
        self.assertNotIn("risk", decision)
        self.assertIn("summary", decision)
        self.assertIs(decision["should_process"], True)


if __name__ == "__main__":
    unittest.main()

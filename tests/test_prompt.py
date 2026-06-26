import unittest

from email_triage.prompt import prepare_body


class PromptTest(unittest.TestCase):
    def test_prepare_body_compacts_long_email_and_keeps_edges(self):
        body = "<p>" + ("a" * 5000) + "</p>" + ("b" * 3000)

        prepared = prepare_body(body)

        self.assertLess(len(prepared), len(body))
        self.assertIn("[...middle omitted for email triage context...]", prepared)
        self.assertTrue(prepared.startswith("a" * 20))
        self.assertTrue(prepared.endswith("b" * 20))

    def test_prepare_body_normalizes_html_and_whitespace(self):
        prepared = prepare_body("<div>Hello</div>\r\n\r\n\r\n   world")

        self.assertEqual(prepared, "Hello\n\nworld")


if __name__ == "__main__":
    unittest.main()

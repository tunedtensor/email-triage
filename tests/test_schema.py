import unittest

from email_triage.schema import TriageValidationError, parse_decision


class SchemaTest(unittest.TestCase):
    def test_parse_decision_extracts_json_from_wrapped_output(self):
        parsed = parse_decision(
            'prefix {"triage":"reply","priority":"normal",'
            '"should_process":true,"confidence":0.83,'
            '"summary":"Sender asks for a scheduling reply.",'
            '"reason":"Direct request requires a response."} suffix'
        )

        self.assertEqual(
            parsed,
            {
                "triage": "reply",
                "priority": "normal",
                "should_process": True,
                "confidence": 0.83,
                "summary": "Sender asks for a scheduling reply.",
                "reason": "Direct request requires a response.",
            },
        )

    def test_parse_decision_rejects_invalid_priority(self):
        with self.assertRaisesRegex(TriageValidationError, "priority must be one of"):
            parse_decision(
                '{"triage":"reply","priority":"unknown",'
                '"should_process":true,"confidence":0.83,'
                '"summary":"Sender asks for a scheduling reply.",'
                '"reason":"Direct request requires a response."}'
            )

    def test_parse_decision_canonicalizes_common_model_drift(self):
        parsed = parse_decision(
            '{"triage":"respond","priority":"medium",'
            '"should_process":"yes","confidence":0.67,'
            '"summary":"Sender needs an answer.",'
            '"reason":"Direct response needed."}'
        )

        self.assertEqual(parsed["triage"], "reply")
        self.assertEqual(parsed["priority"], "normal")
        self.assertIs(parsed["should_process"], True)

    def test_parse_decision_aligns_should_process_from_triage(self):
        parsed = parse_decision(
            '{"triage":"ignore","priority":1,'
            '"should_process":true,"confidence":0.95,'
            '"summary":"Spam message.",'
            '"reason":"Junk should not enter workflow."}'
        )

        self.assertEqual(parsed["triage"], "ignore")
        self.assertEqual(parsed["priority"], "low")
        self.assertIs(parsed["should_process"], False)

    def test_parse_decision_repairs_missing_triage_from_legacy_risk(self):
        parsed = parse_decision(
            '{"priority":1,"risk":"prompt_injection","should_process":false,'
            '"confidence":0.95,"summary":"Prompt injection attempt.",'
            '"reason":"Prompt injection attempt."}'
        )

        self.assertEqual(parsed["triage"], "ignore")
        self.assertNotIn("risk", parsed)
        self.assertIs(parsed["should_process"], False)

    def test_parse_decision_defaults_missing_summary_from_reason(self):
        parsed = parse_decision(
            '{"triage":"review","priority":"standard",'
            '"should_process":true,"confidence":0.82,'
            '"reason":"Normal digest requires review."}'
        )

        self.assertEqual(parsed["priority"], "normal")
        self.assertEqual(parsed["summary"], "Normal digest requires review.")

    def test_parse_decision_repairs_common_json_string_boundary_typo(self):
        parsed = parse_decision(
            '{"confidence":0.91,"priority":1,"summary":"Promotional tutorial,""should_process":false,'
            '"triage":"promotional","reason":"Promotional tutorial."}'
        )

        self.assertEqual(parsed["triage"], "archive")
        self.assertEqual(parsed["priority"], "low")
        self.assertIs(parsed["should_process"], False)


if __name__ == "__main__":
    unittest.main()

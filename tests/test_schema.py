import unittest

from email_triage.schema import TriageValidationError, parse_decision


class SchemaTest(unittest.TestCase):
    def test_parse_decision_extracts_json_from_wrapped_output(self):
        parsed = parse_decision(
            'prefix {"triage":"reply","priority":"normal","risk":"none",'
            '"should_process":true,"confidence":0.83,"reason":"Legitimate request."} suffix'
        )

        self.assertEqual(
            parsed,
            {
                "triage": "reply",
                "priority": "normal",
                "risk": "none",
                "should_process": True,
                "confidence": 0.83,
                "reason": "Legitimate request.",
            },
        )

    def test_parse_decision_rejects_invalid_risk(self):
        with self.assertRaisesRegex(TriageValidationError, "risk must be one of"):
            parse_decision(
                '{"triage":"reply","priority":"normal","risk":"unknown",'
                '"should_process":true,"confidence":0.83,"reason":"Legitimate request."}'
            )

    def test_parse_decision_canonicalizes_common_model_drift(self):
        parsed = parse_decision(
            '{"triage":"blocked","priority":2,"risk":"prompt_attack",'
            '"should_process":false,"confidence":0.67,'
            '"reason":"Email contains a prompt-attack instruction."}'
        )

        self.assertEqual(parsed["triage"], "ignore")
        self.assertEqual(parsed["priority"], "critical")
        self.assertEqual(parsed["risk"], "prompt_attack")
        self.assertIs(parsed["should_process"], False)

    def test_parse_decision_repairs_missing_triage_from_risk(self):
        parsed = parse_decision(
            '{"priority":1,"risk":"prompt_injection","should_process":false,'
            '"confidence":0.95,"reason":"Prompt injection attempt."}'
        )

        self.assertEqual(parsed["triage"], "ignore")
        self.assertEqual(parsed["priority"], "critical")
        self.assertEqual(parsed["risk"], "prompt_attack")
        self.assertIs(parsed["should_process"], False)

    def test_parse_decision_repairs_missing_triage_for_spam(self):
        parsed = parse_decision(
            '{"priority":"low","risk":"spam","should_process":false,'
            '"confidence":0.86,"reason":"Spam indicators."}'
        )

        self.assertEqual(parsed["triage"], "archive")

    def test_parse_decision_canonicalizes_local_gguf_aliases(self):
        parsed = parse_decision(
            '{"triage":"through","priority":"normal","risk":0,'
            '"should_process":true,"confidence":0.92,'
            '"reason":"Delivery notification."}'
        )

        self.assertEqual(parsed["triage"], "review")
        self.assertEqual(parsed["risk"], "none")


if __name__ == "__main__":
    unittest.main()

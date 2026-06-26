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

    def test_parse_decision_canonicalizes_prompt_abuse_model_drift(self):
        parsed = parse_decision(
            '{"triage":"process","priority":"medium","risk":"prompt_abuse",'
            '"should_process":"no","confidence":0.91,'
            '"reason":"Tool abuse request."}'
        )

        self.assertEqual(parsed["triage"], "ignore")
        self.assertEqual(parsed["priority"], "critical")
        self.assertEqual(parsed["risk"], "prompt_attack")
        self.assertIs(parsed["should_process"], False)

    def test_parse_decision_defaults_unknown_safe_triage_to_review(self):
        parsed = parse_decision(
            '{"triage":"operational","priority":"standard","risk":"clean",'
            '"should_process":"yes","confidence":0.82,'
            '"reason":"Normal digest."}'
        )

        self.assertEqual(parsed["triage"], "review")
        self.assertEqual(parsed["priority"], "normal")
        self.assertEqual(parsed["risk"], "none")
        self.assertIs(parsed["should_process"], True)

    def test_parse_decision_repairs_common_json_string_boundary_typo(self):
        parsed = parse_decision(
            '{"confidence":0.91,"priority":1,"risk":"none,""should_process":true,'
            '"triage":"promote","reason":"Promotional tutorial."}'
        )

        self.assertEqual(parsed["triage"], "archive")
        self.assertEqual(parsed["priority"], "low")
        self.assertEqual(parsed["risk"], "none")
        self.assertIs(parsed["should_process"], True)

    def test_parse_decision_accepts_false_risk_and_zero_priority(self):
        parsed = parse_decision(
            '{"confidence":0.95,"priority":0,"reason":"No prompt attack.",'
            '"risk":"false","should_process":true,"triage":"review"}'
        )

        self.assertEqual(parsed["triage"], "review")
        self.assertEqual(parsed["priority"], "low")
        self.assertEqual(parsed["risk"], "none")
        self.assertIs(parsed["should_process"], True)


if __name__ == "__main__":
    unittest.main()

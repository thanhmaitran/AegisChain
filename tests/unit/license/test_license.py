import unittest

from aegischain.domain.models import LicenseStatus as S
from aegischain.engines.license.evaluator import LicensePolicy, evaluate_license
from aegischain.engines.license.expression import ExpressionError, parse_expression, to_string


class ExpressionTests(unittest.TestCase):
    def test_round_trip_and_case_insensitivity(self) -> None:
        self.assertEqual(to_string(parse_expression("mit or apache-2.0")), "MIT OR Apache-2.0")

    def test_precedence_and_parentheses(self) -> None:
        # AND binds tighter than OR
        self.assertEqual(
            to_string(parse_expression("MIT OR ISC AND BSD-3-Clause")),
            "MIT OR (ISC AND BSD-3-Clause)",
        )
        self.assertEqual(
            to_string(parse_expression("(MIT OR ISC) AND BSD-3-Clause")),
            "(MIT OR ISC) AND BSD-3-Clause",
        )

    def test_with_exception(self) -> None:
        self.assertEqual(
            to_string(parse_expression("GPL-2.0-only WITH Classpath-exception-2.0")),
            "GPL-2.0-only WITH Classpath-exception-2.0",
        )

    def test_deprecated_ids_are_normalised(self) -> None:
        self.assertEqual(to_string(parse_expression("GPL-3.0+")), "GPL-3.0-or-later")

    def test_invalid_expressions(self) -> None:
        for bad in [
            "",
            "MIT AND",
            "AND MIT",
            "(MIT",
            "MIT)",
            "MIT OR OR ISC",
            "Nope-1.0",
            "MIT WITH",
            "MIT WITH Unknown-exc",
            "(MIT OR ISC) WITH Classpath-exception-2.0",
            "MIT $ ISC",
        ]:
            with self.assertRaises(ExpressionError, msg=bad):
                parse_expression(bad)


class EvaluatorTests(unittest.TestCase):
    policy = LicensePolicy(denied=("GPL-3.0-*", "AGPL-*"))

    def status(self, text, policy=None):
        return evaluate_license("pkg:x/y", text, policy or self.policy).status

    def test_missing_license_is_unknown_never_assumed(self) -> None:
        self.assertEqual(self.status(None), S.UNKNOWN)
        self.assertEqual(self.status("  "), S.UNKNOWN)

    def test_and_or_semantics(self) -> None:
        self.assertEqual(self.status("MIT"), S.ALLOWED)
        self.assertEqual(self.status("MIT OR GPL-3.0-only"), S.ALLOWED)  # licensee may choose MIT
        self.assertEqual(self.status("MIT AND GPL-3.0-only"), S.DENIED)  # obligations of both apply
        self.assertEqual(self.status("GPL-3.0-only OR AGPL-3.0-only"), S.DENIED)
        self.assertEqual(self.status("GPL-3.0-only OR LicenseRef-x"), S.UNKNOWN)

    def test_allow_list(self) -> None:
        p = LicensePolicy(allowed=("MIT", "Apache-2.0"))
        self.assertEqual(self.status("MIT", p), S.ALLOWED)
        self.assertEqual(self.status("ISC", p), S.DENIED)
        self.assertEqual(self.status("ISC OR MIT", p), S.ALLOWED)

    def test_invalid_and_custom(self) -> None:
        self.assertEqual(self.status("Proprietary"), S.INVALID)
        self.assertEqual(self.status("LicenseRef-Acme"), S.UNKNOWN)

    def test_alias_normalisation_is_reported(self) -> None:
        f = evaluate_license("p", "MIT License", self.policy)
        self.assertEqual((f.status, f.normalized), (S.ALLOWED, "MIT"))
        self.assertIn("normalised", f.reason)

    def test_ambiguous_names_are_not_guessed(self) -> None:
        self.assertEqual(self.status("BSD"), S.INVALID)
        self.assertEqual(self.status("GPL"), S.INVALID)


if __name__ == "__main__":
    unittest.main()

import json
import unittest

from aegischain.application.pipeline import AnalysisPipeline, AnalysisRequest
from aegischain.domain.models import AnalysisReport
from aegischain.engines.vulnerability.provider import StaticVulnerabilityProvider
from aegischain.utils.deserialization import from_jsonable
from aegischain.utils.serialization import to_jsonable

from tests.helpers import CLOCK, EXAMPLE_NODE, EXAMPLE_PY
from tests.unit.vulnerability.test_vulnerability import pyyaml_record


class RoundTrip(unittest.TestCase):
    def test_full_report_round_trips_exactly(self) -> None:
        provider = StaticVulnerabilityProvider({"pkg:pypi/pyyaml@5.3": [pyyaml_record()]}, CLOCK)
        for ex in (EXAMPLE_PY, EXAMPLE_NODE):
            report = AnalysisPipeline(provider, clock=CLOCK).run(AnalysisRequest(ex)).report
            wire = json.loads(json.dumps(to_jsonable(report)))
            self.assertEqual(from_jsonable(AnalysisReport, wire), report)


if __name__ == "__main__":
    unittest.main()

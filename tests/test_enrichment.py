from agents.enrichment_agent import EnrichmentAgent
from api.models import NormalizedEvent


def test_indicator_extraction():
    event = NormalizedEvent(
        event_id="00000000-0000-0000-0000-000000000001",
        src_ip="8.8.8.8",
        dst_ip="1.1.1.1",
        raw_payload={"domain": "example.com", "sha256": "a" * 64},
    )
    indicators = EnrichmentAgent()._extract_indicators(event)
    values = {(x["type"], x["value"]) for x in indicators}
    assert ("ip", "8.8.8.8") in values
    assert ("ip", "1.1.1.1") in values
    assert ("domain", "example.com") in values
    assert ("hash", "a" * 64) in values

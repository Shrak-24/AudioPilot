from datetime import datetime, timezone
from types import SimpleNamespace

from backend.rules import classify


def incident(**overrides):
    values = dict(detection_time=datetime(2026, 1, 1, tzinfo=timezone.utc), severity="p2",
                  incident_type="phishing", systems=[], financial_exposure=0, customers_impacted=0)
    values.update(overrides)
    return SimpleNamespace(**values)


def test_tier_one_incident_is_reportable_and_has_server_deadlines():
    decision = classify(incident(incident_type="ransomware", severity="p1"))
    assert decision.reportable is True
    assert "TIER_1_INCIDENT_TYPE" in decision.rules_fired
    assert (decision.deadlines["full_report"] - decision.deadlines["initial"]).total_seconds() == 4 * 3600


def test_non_triggering_incident_is_not_reportable():
    decision = classify(incident())
    assert decision.reportable is False
    assert decision.rules_fired == []


def test_thresholds_are_inclusive_of_system_rules():
    decision = classify(incident(systems=["cbs"], customers_impacted=101))
    assert set(decision.rules_fired) == {"CUSTOMERS_GT_100", "CBS_AFFECTED"}

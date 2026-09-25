from datetime import timedelta, timezone
from dataclasses import dataclass

TIER_1 = {"ransomware", "ddos", "data-breach", "swift-fraud", "web-defacement"}

@dataclass(frozen=True)
class Decision:
    reportable: bool
    confidence: float
    reasons: list[str]
    rules_fired: list[str]
    deadlines: dict

def classify(data) -> Decision:
    reasons, rules = [], []
    if data.severity == "p1":
        rules.append("P1_CRITICAL"); reasons.append("P1 critical severity requires immediate regulatory assessment.")
    if data.incident_type in TIER_1:
        rules.append("TIER_1_INCIDENT_TYPE"); reasons.append(f"{data.incident_type} is a Tier-1 RBI CSITE incident category.")
    if data.financial_exposure > 100000:
        rules.append("FINANCIAL_EXPOSURE_GT_100K"); reasons.append("Estimated financial exposure exceeds ₹1,00,000.")
    if data.customers_impacted > 100:
        rules.append("CUSTOMERS_GT_100"); reasons.append("Customer impact exceeds the 100-customer trigger.")
    if "swift" in data.systems:
        rules.append("SWIFT_AFFECTED"); reasons.append("SWIFT / messaging infrastructure is affected.")
    if "cbs" in data.systems:
        rules.append("CBS_AFFECTED"); reasons.append("Core Banking System is affected.")
    if not rules:
        reasons.append("No configured mandatory reporting rule matched; retain the incident under the internal CCMP.")
    dt = data.detection_time.astimezone(timezone.utc)
    return Decision(bool(rules), min(99.0, 78.0 + len(rules) * 4.0) if rules else 88.0, reasons, rules, {
        "initial": dt + timedelta(hours=2), "full_report": dt + timedelta(hours=6),
        "certin": dt + timedelta(hours=6), "post_incident": dt + timedelta(days=21)})

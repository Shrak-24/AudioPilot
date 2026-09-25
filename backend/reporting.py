import json
import httpx
from .config import get_settings

PROMPT_VERSION = "rbi-csite-9-section-v1"

async def generate_report(incident, decision) -> tuple[dict, str, str]:
    settings = get_settings()
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY is required to generate a regulatory report")
    source = {"incident_id": incident.id, "alert_id": incident.alert_id,
        "detection_time": incident.detection_time.isoformat(), "source": incident.source,
        "type": incident.incident_type, "severity": incident.severity, "systems": incident.systems,
        "description": incident.description, "financial_exposure": float(incident.financial_exposure),
        "customers_impacted": incident.customers_impacted, "officer": incident.officer,
        "classification": {"reportable": decision.reportable, "reasons": decision.reasons}}
    system = "You draft an RBI CSITE cyber incident report. Return ONLY valid JSON with string keys 1 through 9. Never invent facts; use null or 'Under investigation' when unknown."
    user = "Create all nine prescribed report sections from this source record:\n" + json.dumps(source, default=str)
    async with httpx.AsyncClient(timeout=90) as client:
        response = await client.post("https://api.openai.com/v1/chat/completions", headers={
            "Authorization": f"Bearer {settings.openai_api_key}", "Content-Type": "application/json"},
            json={"model": settings.openai_model, "temperature": 0, "response_format": {"type": "json_object"},
                  "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]})
        response.raise_for_status()
        sections = json.loads(response.json()["choices"][0]["message"]["content"])
    missing = set(map(str, range(1, 10))) - set(sections)
    if missing:
        raise ValueError(f"LLM response missing report sections: {sorted(missing)}")
    return sections, "openai", settings.openai_model

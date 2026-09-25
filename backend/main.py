import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from .audit import append, verify_chain
from .config import get_settings
from .db import get_db, init_db
from .models import Classification, Evidence, Incident, Report, Task
from .reporting import PROMPT_VERSION, generate_report
from .rules import classify
from .schemas import EvidenceVerify, IncidentCreate, TaskStatus

app = FastAPI(title="AuditPilot API", version="1.0.0")
settings = get_settings()
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    init_db(); Path(settings.evidence_dir).mkdir(parents=True, exist_ok=True)

def incident_json(i: Incident):
    c = i.classification
    return {"id": i.id, "incident_id": f"IR-CNRB-{i.id[:8].upper()}", "alert_id": i.alert_id,
        "detection_time": i.detection_time, "source": i.source, "incident_type": i.incident_type,
        "severity": i.severity, "systems": i.systems, "description": i.description,
        "financial_exposure": float(i.financial_exposure), "customers_impacted": i.customers_impacted,
        "officer": i.officer, "classification": None if not c else {"reportable": c.reportable,
        "confidence": float(c.confidence), "reasons": c.reasons, "rules_fired": c.rules_fired},
        "deadlines": None if not c else {"initial": c.initial_deadline, "full_report": c.full_report_deadline,
        "certin": c.certin_deadline, "post_incident": c.post_incident_deadline}}

@app.get("/health")
def health(): return {"status": "ok"}

@app.post("/api/incidents", status_code=201)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)):
    i = Incident(alert_id=payload.alert_id, detection_time=payload.detection_time, source=payload.source,
        incident_type=payload.incident_type, severity=payload.severity, systems=payload.systems,
        description=payload.description, financial_exposure=payload.financial_exposure,
        customers_impacted=payload.customers_impacted, officer=payload.officer.model_dump())
    db.add(i); db.flush()
    append(db, incident_id=i.id, stage="SOC Intake", actor_type="human", actor="SOC Analyst",
           action=f"Alert {i.alert_id} ingested", status="Complete", payload=payload.model_dump(mode="json"))
    db.commit(); db.refresh(i); return incident_json(i)

@app.post("/api/incidents/{incident_id}/classify")
def classify_incident(incident_id: str, db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i: raise HTTPException(404, "Incident not found")
    d = classify(i)
    if i.classification: db.delete(i.classification)
    i.classification = Classification(reportable=d.reportable, confidence=d.confidence, reasons=d.reasons,
        rules_fired=d.rules_fired, initial_deadline=d.deadlines["initial"], full_report_deadline=d.deadlines["full_report"],
        certin_deadline=d.deadlines["certin"], post_incident_deadline=d.deadlines["post_incident"])
    append(db, incident_id=i.id, stage="Classification", actor_type="agent", actor="Classification Rule Engine",
        action=f"Classified as {'REPORTABLE' if d.reportable else 'NOT REPORTABLE'}", status="Complete",
        payload={"rules_fired": d.rules_fired, "confidence": d.confidence})
    db.commit(); return incident_json(i)

@app.post("/api/incidents/{incident_id}/report")
async def create_report(incident_id: str, db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i or not i.classification: raise HTTPException(409, "Classify the incident before generating a report")
    if i.report: return {"id": i.report.id, "sections": i.report.sections, "provider": i.report.provider, "model": i.report.model}
    try: sections, provider, model = await generate_report(i, i.classification)
    except Exception as exc: raise HTTPException(502, str(exc)) from exc
    r = Report(incident_id=i.id, sections=sections, provider=provider, model=model, prompt_version=PROMPT_VERSION)
    db.add(r); append(db, incident_id=i.id, stage="Report Generation", actor_type="agent", actor="OpenAI Report Agent",
        action="Generated nine-section RBI CSITE report", status="Complete", payload={"provider": provider, "model": model})
    db.commit(); return {"id": r.id, "sections": r.sections, "provider": r.provider, "model": r.model}

TASKS = [
    ("MAP-001", "Network Isolation of Affected Systems", "Isolate affected systems and block known command-and-control traffic.", "soc", "SOC Team", "critical", .5),
    ("MAP-002", "Forensic Evidence Preservation", "Capture memory and disk images and maintain chain of custody.", "ir", "IR Team", "critical", 1),
    ("MAP-003", "CISO, Board & Compliance Notification", "Notify accountable executives and record timestamps.", "compliance", "Compliance", "critical", 2),
    ("MAP-004", "Compromised Account Remediation", "Suspend compromised accounts, rotate credentials and revoke tokens.", "ops", "Ops Team", "critical", 2),
    ("MAP-005", "Submit RBI Initial Notification", "File the initial RBI notification and retain acknowledgement.", "ciso", "CISO Office", "critical", 2),
    ("MAP-006", "Submit CERT-In Incident Report", "Submit the CERT-In report and retain portal acknowledgement.", "ciso", "CISO Office", "critical", 6),
    ("MAP-007", "Submit Full RBI CSITE Report", "Submit all nine report sections through the approved RBI channel.", "ciso", "CISO Office", "critical", 6),
    ("MAP-008", "Customer Advisory & Helpdesk Activation", "Coordinate customer communications and service-status updates.", "customer", "Customer Service", "high", 4),
    ("MAP-009", "Forensic Vendor Engagement", "Engage the approved forensic provider and begin deep-dive analysis.", "ir", "IR Team", "high", 8),
    ("MAP-010", "Post-Incident Analysis Report", "Prepare the post-incident analysis and corrective action plan.", "compliance", "Compliance", "medium", 21 * 24),
]

def task_json(t):
    return {"id": t.id, "title": t.title, "description": t.description, "team_id": t.team_id,
        "assignee": t.assignee, "priority": t.priority, "due_at": t.due_at, "status": t.status,
        "verified": bool(t.verified_at), "evidence": [{"id": e.id, "filename": e.filename,
        "content_type": e.content_type, "sha256": e.sha256, "verified": bool(e.verified_at)} for e in t.evidence]}

@app.post("/api/incidents/{incident_id}/tasks")
def create_tasks(incident_id: str, db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i or not i.classification: raise HTTPException(409, "Classify the incident before creating tasks")
    if i.tasks: return {"tasks": [task_json(t) for t in i.tasks]}
    base = i.detection_time.astimezone(timezone.utc)
    for ident, title, desc, team, assignee, priority, hours in TASKS:
        db.add(Task(id=ident, incident_id=i.id, title=title, description=desc, team_id=team, assignee=assignee,
            priority=priority, due_at=base + timedelta(hours=hours)))
    append(db, incident_id=i.id, stage="Workbench", actor_type="agent", actor="MAP Engine",
        action="Generated mitigation action plan", status="Complete", payload={"task_count": len(TASKS)})
    db.commit(); return {"tasks": [task_json(t) for t in i.tasks]}

@app.get("/api/incidents/{incident_id}/tasks")
def list_tasks(incident_id: str, db: Session = Depends(get_db)):
    rows = db.scalars(select(Task).where(Task.incident_id == incident_id).options(joinedload(Task.evidence))).unique()
    return {"tasks": [task_json(t) for t in rows]}

@app.post("/api/tasks/{task_id}/evidence")
def upload_evidence(task_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t: raise HTTPException(404, "Task not found")
    content = file.file.read(); digest = hashlib.sha256(content).hexdigest()
    key = f"{task_id}/{digest}-{Path(file.filename or 'evidence').name}"; path = Path(settings.evidence_dir) / key
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
    e = Evidence(task_id=t.id, filename=file.filename or "evidence", content_type=file.content_type or "application/octet-stream",
        sha256=digest, storage_key=key); db.add(e)
    append(db, incident_id=t.incident_id, stage="Workbench", actor_type="human", actor="Analyst",
        action=f"Evidence uploaded to {t.id}: {e.filename}", status="Complete", payload={"sha256": digest})
    db.commit(); return {"evidence": {"id": e.id, "filename": e.filename, "sha256": e.sha256, "verified": False}}

@app.post("/api/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str, payload: EvidenceVerify, db: Session = Depends(get_db)):
    e = db.get(Evidence, evidence_id)
    if not e: raise HTTPException(404, "Evidence not found")
    e.verified_at = datetime.now(timezone.utc) if payload.verified else None
    append(db, incident_id=e.task.incident_id, stage="Workbench", actor_type="human", actor="Analyst",
        action=f"Evidence {evidence_id} {'verified' if payload.verified else 'unverified'}", status="Complete")
    db.commit(); return {"verified": bool(e.verified_at)}

@app.patch("/api/tasks/{task_id}")
def update_task(task_id: str, payload: TaskStatus, db: Session = Depends(get_db)):
    t = db.get(Task, task_id)
    if not t or payload.status not in {"open", "inprogress", "closed"}: raise HTTPException(400, "Invalid task or status")
    if payload.status == "closed":
        if not t.evidence or any(e.verified_at is None for e in t.evidence):
            raise HTTPException(409, "Task closure requires at least one uploaded and verified evidence item")
        t.verified_at = datetime.now(timezone.utc)
    t.status = payload.status
    append(db, incident_id=t.incident_id, stage="Workbench", actor_type="human", actor="Analyst",
        action=f"Task {t.id} moved to {t.status}", status="Complete", payload={"evidence_verified": bool(t.verified_at)})
    db.commit(); return task_json(t)

@app.get("/api/incidents/{incident_id}/deadlines")
def deadlines(incident_id: str, db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i or not i.classification: raise HTTPException(404, "Incident classification not found")
    now = datetime.now(timezone.utc); c = i.classification
    return {"server_now": now, "deadlines": {name: {"at": value, "remaining_seconds": max(0, int((value-now).total_seconds()))}
        for name, value in {"initial": c.initial_deadline, "full_report": c.full_report_deadline,
        "certin": c.certin_deadline, "post_incident": c.post_incident_deadline}.items()}}

@app.get("/api/incidents/{incident_id}/audit")
def audit(incident_id: str, db: Session = Depends(get_db)):
    from .models import AuditLog
    rows = list(db.scalars(select(AuditLog).where(AuditLog.incident_id == incident_id).order_by(AuditLog.id)))
    return {"immutable": verify_chain(db), "events": [{"id": r.id, "timestamp": r.created_at, "stage": r.stage,
        "actor_type": r.actor_type, "actor": r.actor, "action": r.action, "status": r.status, "entry_hash": r.entry_hash} for r in rows]}

app.mount("/", StaticFiles(directory=".", html=True), name="frontend")

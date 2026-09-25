import hashlib
import json
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import AuditLog

def append(db: Session, *, incident_id: str | None, stage: str, actor_type: str,
           actor: str, action: str, status: str, payload: dict | None = None) -> AuditLog:
    previous = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()))
    previous_hash = previous.entry_hash if previous else None
    body = {"incident_id": incident_id, "stage": stage, "actor_type": actor_type, "actor": actor,
            "action": action, "status": status, "payload": payload or {}, "previous_hash": previous_hash}
    entry_hash = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    row = AuditLog(**body, entry_hash=entry_hash)
    db.add(row); db.flush(); return row

def verify_chain(db: Session) -> bool:
    previous = None
    for row in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        if row.previous_hash != previous: return False
        body = {"incident_id": row.incident_id, "stage": row.stage, "actor_type": row.actor_type,
                "actor": row.actor, "action": row.action, "status": row.status,
                "payload": row.payload or {}, "previous_hash": row.previous_hash}
        if hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest() != row.entry_hash: return False
        previous = row.entry_hash
    return True

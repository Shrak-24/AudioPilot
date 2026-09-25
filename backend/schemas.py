from datetime import datetime
from pydantic import BaseModel, Field

class Officer(BaseModel):
    name: str = ""
    designation: str = ""
    department: str = ""
    email: str = ""
    phone: str = ""

class IncidentCreate(BaseModel):
    alert_id: str = Field(min_length=1, max_length=128)
    detection_time: datetime
    source: str
    incident_type: str
    severity: str
    systems: list[str] = []
    description: str = Field(min_length=1)
    financial_exposure: float = Field(default=0, ge=0)
    customers_impacted: int = Field(default=0, ge=0)
    officer: Officer = Officer()

class EvidenceVerify(BaseModel):
    verified: bool

class TaskStatus(BaseModel):
    status: str

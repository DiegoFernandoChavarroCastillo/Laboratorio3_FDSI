from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

# Inicializamos la aplicación sin configuraciones de seguridad (Req. Lab 3)
app = FastAPI(
    title="MuvAutomation CrowdStrike API (LAB)",
    description="API vulnerable y sin autenticación para el Lab 3 de Red/Blue Team"
)

# Base de datos ficticia en memoria usando tu estructura
ALERTS = [
    {
        "id": "ALRT-LAB-0001",
        "severity": "high",
        "tactic": "Credential Access",
        "technique": "T1003",
        "hostname": "WEB-LAB-01",
        "agent_id": "aaaaaaaa-0000-0000-0000-000000000001",
        "internal_ip": "10.10.10.11",
        "analyst_email": "analyst1@lab.invalid",
        "status": "new",
    },
    {
        "id": "ALRT-LAB-0002",
        "severity": "medium",
        "tactic": "Discovery",
        "technique": "T1046",
        "hostname": "API-LAB-01",
        "agent_id": "aaaaaaaa-0000-0000-0000-000000000002",
        "internal_ip": "10.10.10.12",
        "analyst_email": "analyst2@lab.invalid",
        "status": "new",
    },
    {
        "id": "ALRT-LAB-0003",
        "severity": "low",
        "tactic": "Execution",
        "technique": "T1059",
        "hostname": "DB-LAB-01",
        "agent_id": "aaaaaaaa-0000-0000-0000-000000000003",
        "internal_ip": "10.10.10.13",
        "analyst_email": "analyst1@lab.invalid",
        "status": "new",
    }
]

ACTIONS = []

# Modelos de datos para recibir peticiones estructuradas
class Alert(BaseModel):
    id: str
    severity: str
    tactic: str
    technique: str
    hostname: str
    agent_id: str
    internal_ip: str
    analyst_email: str
    status: str

class Action(BaseModel):
    alert_id: str
    action_type: str
    description: str

# Endpoints de la API

@app.get("/api/alerts", response_model=List[Alert])
def get_alerts():
    """Consulta todas las alertas activas."""
    return ALERTS

@app.post("/api/alerts", response_model=Alert)
def create_alert(alert: Alert):
    """Simula la recepción de una nueva alerta desde Falcon."""
    ALERTS.append(alert.model_dump())
    return alert

@app.get("/api/actions", response_model=List[Action])
def get_actions():
    """Consulta el registro de acciones realizadas."""
    return ACTIONS

@app.post("/api/actions", response_model=Action)
def record_action(action: Action):
    """Registra una acción de escalamiento, enriquecimiento o remediación."""
    ACTIONS.append(action.model_dump())
    return action
"""
MuvAutomation CrowdStrike Incident Hub — rama Mejoras
Laboratorio 3 FDSI | E07

Mitigaciones aplicadas sobre el modelo STRIDE:
  M1 (H1) - AlertPublic + validacion estricta de entrada
  M2 (H3) - Atribucion en el registro de acciones
  M3 (H3) - Correlacion por request_id entre Nginx y FastAPI
  M4 (H2) - Superficie de documentacion cerrada

Limite declarado: sigue sin TLS y sin autenticacion verificada.
El campo `actor` es autodeclarado, no autenticado (pendiente Lab 4).
"""

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# M4 (H2): se desactiva la documentacion interactiva.
# Swagger publicaba el contrato completo del API sin autenticacion, lo que
# entrega a un atacante el mapa de endpoints, metodos y esquemas sin esfuerzo.
# ---------------------------------------------------------------------------
app = FastAPI(
    title="MuvAutomation CrowdStrike Incident Hub (LAB - Mejoras)",
    description="Prototipo con mitigaciones STRIDE aplicadas sobre la linea base del Lab 3",
    version="0.2.0-mejoras",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# ---------------------------------------------------------------------------
# M3 (H3): logging estructurado con request_id
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("incident-hub")


# ---------------------------------------------------------------------------
# Enumeraciones: restringen los valores aceptados en lugar de admitir
# cualquier cadena. Mitiga Tampering por valores fuera de dominio.
# ---------------------------------------------------------------------------
class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, Enum):
    new = "new"
    in_progress = "in_progress"
    closed = "closed"


class ActionType(str, Enum):
    triage = "triage"
    enrich = "enrich"
    escalate = "escalate"
    contain = "contain"
    close = "close"


# ---------------------------------------------------------------------------
# Datos ficticios en memoria. Sin informacion real.
# ---------------------------------------------------------------------------
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
    },
]

ACTIONS = []


# ---------------------------------------------------------------------------
# M1 (H1 / H4): modelos de entrada y salida separados
# ---------------------------------------------------------------------------
class Alert(BaseModel):
    """Modelo interno completo. Es lo que acepta el POST (ingesta desde Falcon)."""

    # extra="forbid" rechaza campos no declarados en lugar de ignorarlos.
    # Mitiga asignacion masiva (mass assignment) en el flujo F7 del DFD.
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=4, max_length=32, pattern=r"^ALRT-[A-Z0-9]+-\d{4}$")
    severity: Severity
    tactic: str = Field(min_length=1, max_length=64)
    technique: str = Field(min_length=2, max_length=16, pattern=r"^T\d{4}(\.\d{3})?$")
    hostname: str = Field(min_length=1, max_length=64)
    agent_id: str = Field(min_length=8, max_length=64)
    internal_ip: str = Field(min_length=7, max_length=45)
    analyst_email: str = Field(min_length=5, max_length=128)
    status: AlertStatus


class AlertPublic(BaseModel):
    """Proyeccion publica. Excluye agent_id, internal_ip y analyst_email.

    Corresponde al flujo F8 del DFD (respuesta de la API hacia el cliente).
    """

    id: str
    severity: Severity
    tactic: str
    technique: str
    hostname: str
    status: AlertStatus


# ---------------------------------------------------------------------------
# M2 (H3): atribucion en el registro de acciones
# ---------------------------------------------------------------------------
class ActionIn(BaseModel):
    """Lo que el cliente envia."""

    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=4, max_length=32)
    action_type: ActionType
    description: str = Field(min_length=1, max_length=500)
    # Autodeclarado: el servidor lo registra pero NO lo verifica.
    # La verificacion requiere autenticacion (Laboratorio 4).
    actor: str = Field(min_length=1, max_length=64)


class ActionRecord(BaseModel):
    """Lo que el servidor almacena y devuelve.

    Los campos action_id, source_ip, request_id y ts_utc los asigna el
    servidor: el cliente no puede falsificarlos. El campo actor sigue
    siendo autodeclarado, por lo que la mitigacion de H3 es PARCIAL.
    """

    action_id: str
    alert_id: str
    action_type: ActionType
    description: str
    actor: str
    actor_verified: bool  # siempre False hasta el Lab 4
    source_ip: str
    request_id: str
    ts_utc: str


# ---------------------------------------------------------------------------
# M3 (H3): middleware de correlacion
# Toma el X-Request-ID que inyecta Nginx y lo propaga al log de aplicacion,
# de modo que un mismo identificador une access.log, el log del backend
# y el registro de acciones.
# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", f"local-{uuid.uuid4().hex[:12]}")
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    logger.info(
        "rid=%s src=%s method=%s path=%s status=%s",
        request_id,
        request.headers.get("X-Real-IP", request.client.host if request.client else "-"),
        request.method,
        request.url.path,
        response.status_code,
    )
    return response


def _source_ip(request: Request) -> str:
    """IP de origen tomada de la cabecera que inyecta Nginx."""
    return request.headers.get(
        "X-Real-IP", request.client.host if request.client else "unknown"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.2.0-mejoras"}


@app.get("/api/alerts", response_model=List[AlertPublic])
def get_alerts(severity: Optional[Severity] = None):
    """Consulta las alertas activas con proyeccion publica reducida."""
    if severity:
        return [a for a in ALERTS if a["severity"] == severity.value]
    return ALERTS


@app.get("/api/alerts/{alert_id}", response_model=AlertPublic)
def get_alert(alert_id: str):
    for a in ALERTS:
        if a["id"] == alert_id:
            return a
    raise HTTPException(status_code=404, detail="alert not found")


@app.post("/api/alerts", response_model=AlertPublic, status_code=201)
def create_alert(alert: Alert, request: Request):
    """Simula la ingesta de una alerta desde Falcon.

    Acepta el objeto completo pero responde con la proyeccion publica.
    """
    if any(a["id"] == alert.id for a in ALERTS):
        raise HTTPException(status_code=409, detail="alert id already exists")

    ALERTS.append(alert.model_dump())
    logger.info(
        "rid=%s event=alert_created alert_id=%s src=%s",
        getattr(request.state, "request_id", "-"),
        alert.id,
        _source_ip(request),
    )
    return alert.model_dump()


@app.get("/api/actions", response_model=List[ActionRecord])
def get_actions():
    """Consulta el registro de acciones con su metadata de atribucion."""
    return ACTIONS


@app.post("/api/actions", response_model=ActionRecord, status_code=201)
def record_action(action: ActionIn, request: Request):
    """Registra una accion sobre una alerta, con atribucion parcial.

    El servidor asigna action_id, source_ip, request_id y ts_utc.
    El campo actor lo declara el cliente y NO se verifica (Lab 4).
    """
    if not any(a["id"] == action.alert_id for a in ALERTS):
        raise HTTPException(status_code=404, detail="alert_id does not exist")

    record = {
        "action_id": str(uuid.uuid4()),
        "alert_id": action.alert_id,
        "action_type": action.action_type,
        "description": action.description,
        "actor": action.actor,
        "actor_verified": False,
        "source_ip": _source_ip(request),
        "request_id": getattr(request.state, "request_id", "-"),
        "ts_utc": datetime.now(timezone.utc).isoformat(),
    }
    ACTIONS.append(record)

    logger.info(
        "rid=%s event=action_recorded action_id=%s alert_id=%s type=%s "
        "actor=%s verified=False src=%s",
        record["request_id"],
        record["action_id"],
        record["alert_id"],
        record["action_type"],
        record["actor"],
        record["source_ip"],
    )
    return record
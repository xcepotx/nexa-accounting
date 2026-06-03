import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "Nexa Accounting API")
APP_ENV = os.getenv("APP_ENV", "production")
INTERNAL_API_KEY = os.getenv("INTERNAL_API_KEY", "")
EVENT_STORE_PATH = Path(os.getenv("EVENT_STORE_PATH", "/tmp/nexa_accounting_events.jsonl"))

app = FastAPI(title=APP_NAME, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://nexapos.contentfactory.click",
        "https://acc.contentfactory.click",
        "http://acc.contentfactory.click",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PosEvent(BaseModel):
    tenant_id: str = Field(..., min_length=1)
    source: str = "nexapos"
    event_type: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    occurred_at: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def require_internal_key(x_internal_api_key: str = Header(default="")) -> None:
    if not INTERNAL_API_KEY:
        raise HTTPException(status_code=500, detail="Internal API key is not configured")
    if x_internal_api_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid internal API key")

@app.get("/health")
@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "nexa-accounting-api",
        "app": APP_NAME,
        "env": APP_ENV,
        "time": now_iso(),
    }

@app.post("/api/v1/integrations/pos/events")
def receive_pos_event(event: PosEvent, _: None = Depends(require_internal_key)):
    EVENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "received_at": now_iso(),
        "status": "received",
        "event": event.model_dump(),
        "note": "B2 skeleton only. Journal posting engine will be wired in the next batches.",
    }
    with EVENT_STORE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return {
        "ok": True,
        "status": "received",
        "event_type": event.event_type,
        "event_id": event.event_id,
        "message": "POS event accepted by Nexa Accounting skeleton",
    }

@app.get("/api/v1/integrations/pos/events/recent")
def recent_events(_: None = Depends(require_internal_key)):
    if not EVENT_STORE_PATH.exists():
        return {"ok": True, "events": []}
    rows = []
    for line in EVENT_STORE_PATH.read_text(encoding="utf-8").splitlines()[-20:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            pass
    return {"ok": True, "events": rows}

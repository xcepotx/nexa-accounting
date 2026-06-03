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

def _public_event_summary(record: Dict[str, Any]) -> Dict[str, Any]:
    event = record.get("event") or {}
    payload = event.get("payload") or {}

    payload_keys = []
    if isinstance(payload, dict):
        payload_keys = sorted(str(k) for k in payload.keys())[:20]

    return {
        "received_at": record.get("received_at"),
        "status": record.get("status"),
        "tenant_id": event.get("tenant_id"),
        "source": event.get("source"),
        "event_type": event.get("event_type"),
        "event_id": event.get("event_id"),
        "occurred_at": event.get("occurred_at"),
        "has_payload": bool(payload),
        "payload_keys": payload_keys,
    }


@app.get("/api/v1/events/recent-public")
def recent_events_public() -> Dict[str, Any]:
    if not EVENT_STORE_PATH.exists():
        return {"ok": True, "events": [], "count": 0}

    rows = []
    for line in EVENT_STORE_PATH.read_text(encoding="utf-8").splitlines()[-25:]:
        try:
            rows.append(_public_event_summary(json.loads(line)))
        except Exception:
            continue

    rows = list(reversed(rows))
    return {
        "ok": True,
        "count": len(rows),
        "events": rows,
        "note": "Public dashboard endpoint returns metadata only; payload values are not exposed.",
    }

def _money(value: Any) -> float:
    try:
        return round(float(value or 0), 2)
    except Exception:
        return 0.0


def _event_records(limit: int = 100) -> list[Dict[str, Any]]:
    if not EVENT_STORE_PATH.exists():
        return []

    rows = []
    for line in EVENT_STORE_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            continue

    return list(reversed(rows))


def _journal_line(account_code: str, account_name: str, debit: float = 0, credit: float = 0, memo: str = "") -> Dict[str, Any]:
    return {
        "account_code": account_code,
        "account_name": account_name,
        "debit": _money(debit),
        "credit": _money(credit),
        "memo": memo,
    }


def _build_sale_completed_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    sale = payload.get("sale") or {}

    sale_id = sale.get("id") or event.get("event_id")
    invoice = sale.get("invoice_number") or sale_id
    total = _money(sale.get("total"))
    subtotal = _money(sale.get("subtotal"))
    discount = _money(sale.get("discount")) + _money(sale.get("voucher_discount"))
    cogs = _money(sale.get("cogs"))
    net_sales = _money(total)

    lines = [
        _journal_line("1000", "Cash / Payment Clearing", debit=total, memo=f"Receive payment for {invoice}"),
        _journal_line("4000", "Sales Revenue", credit=net_sales, memo=f"Recognize sale {invoice}"),
    ]

    if discount > 0:
        lines.append(_journal_line("4100", "Sales Discount", debit=discount, memo=f"Discount for {invoice}"))

    if cogs > 0:
        lines.extend([
            _journal_line("5000", "Cost of Goods Sold", debit=cogs, memo=f"COGS for {invoice}"),
            _journal_line("1200", "Inventory", credit=cogs, memo=f"Inventory out for {invoice}"),
        ])

    return {
        "event_type": "sale_completed",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": invoice,
        "status": "preview",
        "amount": total,
        "summary": f"Preview journal for completed sale {invoice}",
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }



def _find_original_sale_completed_event(records: list[Dict[str, Any]], sale_id: str) -> Optional[Dict[str, Any]]:
    if not sale_id:
        return None

    for record in records or []:
        event = record.get("event") or {}
        if event.get("event_type") != "sale_completed":
            continue

        payload = event.get("payload") or {}
        sale = payload.get("sale") or {}

        if str(event.get("event_id")) == str(sale_id) or str(sale.get("id")) == str(sale_id):
            return sale

    return None

def _build_sale_voided_preview(event: Dict[str, Any], records: Optional[list[Dict[str, Any]]] = None) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    void_result = payload.get("void_result") or {}
    sale = void_result.get("sale") or void_result.get("voided_sale") or {}

    sale_id = payload.get("sale_id") or event.get("event_id")
    invoice = sale.get("invoice_number") or void_result.get("invoice_number") or sale_id
    total = _money(sale.get("total") or void_result.get("total") or void_result.get("refund_amount"))
    cogs = _money(sale.get("cogs") or void_result.get("cogs"))

    paired_sale = None
    if records and (not total or not cogs):
        paired_sale = _find_original_sale_completed_event(records, sale_id)
        if paired_sale:
            if not invoice or invoice == sale_id:
                invoice = paired_sale.get("invoice_number") or invoice
            if not total:
                total = _money(paired_sale.get("total"))
            if not cogs:
                cogs = _money(paired_sale.get("cogs"))

    lines = [
        _journal_line("4000", "Sales Revenue", debit=total, memo=f"Reverse sale {invoice}"),
        _journal_line("1000", "Cash / Payment Clearing", credit=total, memo=f"Refund/void payment for {invoice}"),
    ]

    if cogs > 0:
        lines.extend([
            _journal_line("1200", "Inventory", debit=cogs, memo=f"Inventory restored for void {invoice}"),
            _journal_line("5000", "Cost of Goods Sold", credit=cogs, memo=f"Reverse COGS for {invoice}"),
        ])

    return {
        "event_type": "sale_voided",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": invoice,
        "status": "preview",
        "amount": total,
        "summary": f"Preview reversal journal for voided sale {invoice}",
        "paired_sale_completed_found": bool(paired_sale),
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }


def _build_po_received_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    po = payload.get("purchase_order") or {}
    receive_id = payload.get("receive_id") or event.get("event_id")
    po_number = po.get("po_number") or payload.get("po_id") or "PO"

    amount = 0.0
    for rec in po.get("receive_history") or []:
        if not receive_id or rec.get("id") == receive_id:
            amount = _money(rec.get("total_received_value") or rec.get("amount"))
            break

    if not amount:
        amount = _money(payload.get("amount") or po.get("total_received_value") or po.get("total"))

    lines = [
        _journal_line("1200", "Inventory", debit=amount, memo=f"Receive inventory {po_number}/{receive_id}"),
        _journal_line("2000", "Accounts Payable", credit=amount, memo=f"AP for received PO {po_number}/{receive_id}"),
    ]

    return {
        "event_type": "purchase_order_received",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": f"{po_number}/{receive_id}",
        "status": "preview",
        "amount": amount,
        "summary": f"Preview journal for PO receive {po_number}",
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }


def _build_journal_preview(record: Dict[str, Any], records: Optional[list[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    event = record.get("event") or {}
    event_type = event.get("event_type")

    event_with_received = {
        **event,
        "received_at": record.get("received_at"),
    }

    if event_type == "sale_completed":
        return _build_sale_completed_preview(event_with_received)

    if event_type == "sale_voided":
        return _build_sale_voided_preview(event_with_received, records=records)

    if event_type == "purchase_order_received":
        return _build_po_received_preview(event_with_received)

    return None


@app.get("/api/v1/journal-preview/queue")
def journal_preview_queue(limit: int = 50) -> Dict[str, Any]:
    records = _event_records(limit=max(1, min(limit, 200)))
    previews = []

    for record in records:
        preview = _build_journal_preview(record, records=records)
        if preview:
            previews.append(preview)

    return {
        "ok": True,
        "count": len(previews),
        "items": previews,
        "note": "B9 preview queue only. No permanent ledger posting is performed yet.",
    }


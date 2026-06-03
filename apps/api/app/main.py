import hashlib
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
EVENT_DEAD_LETTER_STORE_PATH = Path(os.getenv("EVENT_DEAD_LETTER_STORE_PATH", "/data/accounting/app/nexa-accounting/data/dead_letter_events.jsonl"))
JOURNAL_DRAFT_STORE_PATH = Path(os.getenv("JOURNAL_DRAFT_STORE_PATH", "/data/accounting/app/nexa-accounting/data/journal_drafts.jsonl"))
SIM_LEDGER_ENTRY_STORE_PATH = Path(os.getenv("SIM_LEDGER_ENTRY_STORE_PATH", "/data/accounting/app/nexa-accounting/data/sim_ledger_entries.jsonl"))
SIM_LEDGER_LINE_STORE_PATH = Path(os.getenv("SIM_LEDGER_LINE_STORE_PATH", "/data/accounting/app/nexa-accounting/data/sim_ledger_lines.jsonl"))

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


SUPPORTED_POS_EVENT_TYPES = {
    "sale_completed",
    "sale_voided",
    "purchase_order_received",
    "cash_movement_created",
    "stock_adjusted",
    "expense_created",
    "payment_settlement_created",
    "supplier_payment_recorded",
}


def _event_key_from_event_dict(event: Dict[str, Any]) -> str:
    return f"{event.get('source') or 'unknown'}:{event.get('event_type') or 'unknown'}:{event.get('event_id') or 'unknown'}"


def _event_key_from_record(record: Dict[str, Any]) -> str:
    if record.get("event_key"):
        return str(record.get("event_key"))
    return _event_key_from_event_dict(record.get("event") or {})


def _read_event_records_chronological(limit: int = 10000) -> list[Dict[str, Any]]:
    if not EVENT_STORE_PATH.exists():
        return []

    rows = []
    for line in EVENT_STORE_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            row = json.loads(line)
            if "event_key" not in row:
                row["event_key"] = _event_key_from_record(row)
            rows.append(row)
        except Exception:
            continue

    return rows


def _append_event_record(record: Dict[str, Any]) -> None:
    EVENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_STORE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=_json_default) + "\n")


def _append_dead_letter_record(record: Dict[str, Any]) -> None:
    EVENT_DEAD_LETTER_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_DEAD_LETTER_STORE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=_json_default) + "\n")


def _find_event_record(event_key: str) -> Optional[Dict[str, Any]]:
    for record in reversed(_read_event_records_chronological(limit=20000)):
        if _event_key_from_record(record) == event_key:
            return record
    return None


def _find_dead_letter_record(event_key: str) -> Optional[Dict[str, Any]]:
    if not EVENT_DEAD_LETTER_STORE_PATH.exists():
        return None

    for line in reversed(EVENT_DEAD_LETTER_STORE_PATH.read_text(encoding="utf-8").splitlines()[-20000:]):
        try:
            record = json.loads(line)
        except Exception:
            continue
        if _event_key_from_record(record) == event_key:
            return record
    return None

@app.post("/api/v1/integrations/pos/events")
def receive_pos_event(event: PosEvent, _: None = Depends(require_internal_key)):
    event_data = event.model_dump()
    event_key = _event_key_from_event_dict(event_data)
    received_at = now_iso()

    if event.event_type not in SUPPORTED_POS_EVENT_TYPES:
        record = {
            "received_at": received_at,
            "status": "dead_letter",
            "event_key": event_key,
            "event": event_data,
            "reason": "unsupported_event_type",
            "message": f"Unsupported POS event type: {event.event_type}",
            "note": "Stored in dead-letter. Event was accepted but will not be processed until supported.",
        }
        _append_dead_letter_record(record)
        return {
            "ok": True,
            "status": "dead_letter",
            "duplicate": False,
            "event_key": event_key,
            "event_type": event.event_type,
            "event_id": event.event_id,
            "message": "POS event accepted into dead-letter queue",
        }

    existing = _find_event_record(event_key)
    if existing:
        return {
            "ok": True,
            "status": "duplicate",
            "duplicate": True,
            "event_key": event_key,
            "event_type": event.event_type,
            "event_id": event.event_id,
            "first_received_at": existing.get("received_at"),
            "message": "Duplicate POS event ignored idempotently",
        }

    record = {
        "received_at": received_at,
        "status": "received",
        "event_key": event_key,
        "event": event_data,
        "note": "B17 hardened receiver. Event stored idempotently for preview/draft/ledger pipeline.",
    }
    _append_event_record(record)
    return {
        "ok": True,
        "status": "received",
        "duplicate": False,
        "event_key": event_key,
        "event_type": event.event_type,
        "event_id": event.event_id,
        "message": "POS event accepted by Nexa Accounting",
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
        "event_key": record.get("event_key") or _event_key_from_record(record),
        "reason": record.get("reason"),
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

def _json_default(value: Any) -> str:
    try:
        if hasattr(value, "isoformat"):
            return value.isoformat()
    except Exception:
        pass
    return str(value)


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



def _build_cash_movement_created_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    movement = payload.get("cash_movement") or payload
    movement_id = movement.get("id") or event.get("event_id")
    movement_type = str(movement.get("type") or "").lower()
    amount = _money(movement.get("amount"))

    if movement_type == "in":
        lines = [
            _journal_line("1000", "Cash / Payment Clearing", debit=amount, memo=f"Cash in {movement_id}"),
            _journal_line("6200", "Cash Over / Short", credit=amount, memo=f"Cash movement offset {movement_id}"),
        ]
        summary = f"Preview journal for cash in {movement_id}"
    else:
        lines = [
            _journal_line("6200", "Cash Over / Short", debit=amount, memo=f"Cash movement offset {movement_id}"),
            _journal_line("1000", "Cash / Payment Clearing", credit=amount, memo=f"Cash out {movement_id}"),
        ]
        summary = f"Preview journal for cash out {movement_id}"

    return {
        "event_type": "cash_movement_created",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": movement_id,
        "status": "preview",
        "amount": amount,
        "summary": summary,
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }


def _build_stock_adjusted_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    movement = payload.get("stock_movement") or payload
    movement_id = movement.get("id") or event.get("event_id")
    product_name = movement.get("product_name") or payload.get("product_name") or "Inventory item"

    qty_change = _money(movement.get("qty_change") or payload.get("qty_change"))
    unit_cost = _money(payload.get("unit_cost") or movement.get("unit_cost") or movement.get("cost"))
    amount = _money(payload.get("value") or abs(qty_change * unit_cost))

    if qty_change >= 0:
        lines = [
            _journal_line("1200", "Inventory", debit=amount, memo=f"Stock increase {product_name} / {movement_id}"),
            _journal_line("6300", "Inventory Adjustment", credit=amount, memo=f"Inventory adjustment offset {movement_id}"),
        ]
    else:
        lines = [
            _journal_line("6300", "Inventory Adjustment", debit=amount, memo=f"Stock decrease {product_name} / {movement_id}"),
            _journal_line("1200", "Inventory", credit=amount, memo=f"Inventory decrease {movement_id}"),
        ]

    return {
        "event_type": "stock_adjusted",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": movement_id,
        "status": "preview",
        "amount": amount,
        "summary": f"Preview journal for stock adjustment {product_name}",
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }



def _build_expense_created_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    expense = payload.get("expense") or payload
    expense_id = expense.get("id") or event.get("event_id")
    expense_number = expense.get("expense_number") or expense_id
    amount = _money(expense.get("amount"))

    expense_code = str(expense.get("expense_account_code") or "6000")
    expense_name = str(expense.get("expense_account_name") or "Operating Expense")
    payment_code = str(expense.get("payment_account_code") or "1000")
    payment_name = str(expense.get("payment_account_name") or "Cash / Payment Clearing")

    lines = [
        _journal_line(expense_code, expense_name, debit=amount, memo=f"Expense {expense_number}"),
        _journal_line(payment_code, payment_name, credit=amount, memo=f"Expense payment {expense_number}"),
    ]

    return {
        "event_type": "expense_created",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": expense_number,
        "status": "preview",
        "amount": amount,
        "summary": f"Preview journal for expense {expense_number}",
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }


def _build_payment_settlement_created_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    settlement = payload.get("settlement") or payload
    settlement_id = settlement.get("id") or event.get("event_id")
    settlement_number = settlement.get("settlement_number") or settlement_id

    gross = _money(settlement.get("gross_amount"))
    fee = _money(settlement.get("fee_amount"))
    net = _money(settlement.get("net_amount") or (gross - fee))

    clearing_code = str(settlement.get("clearing_account_code") or "1000")
    clearing_name = str(settlement.get("clearing_account_name") or "Payment Clearing")
    bank_code = str(settlement.get("bank_account_code") or "1010")
    bank_name = str(settlement.get("bank_account_name") or "Bank")
    fee_code = str(settlement.get("fee_expense_account_code") or "6100")
    fee_name = str(settlement.get("fee_expense_account_name") or "Payment Fee Expense")

    lines = [
        _journal_line(bank_code, bank_name, debit=net, memo=f"Settlement net received {settlement_number}"),
    ]

    if fee > 0:
        lines.append(_journal_line(fee_code, fee_name, debit=fee, memo=f"Settlement fee {settlement_number}"))

    lines.append(_journal_line(clearing_code, clearing_name, credit=gross, memo=f"Clear payment settlement {settlement_number}"))

    return {
        "event_type": "payment_settlement_created",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": settlement_number,
        "status": "preview",
        "amount": gross,
        "summary": f"Preview journal for payment settlement {settlement_number}",
        "lines": lines,
        "balanced": _money(sum(x["debit"] for x in lines)) == _money(sum(x["credit"] for x in lines)),
    }


def _build_supplier_payment_recorded_preview(event: Dict[str, Any]) -> Dict[str, Any]:
    payload = event.get("payload") or {}
    payment = payload.get("supplier_payment") or payload
    payment_id = payment.get("id") or event.get("event_id")
    payment_number = payment.get("payment_number") or payment_id
    amount = _money(payment.get("amount"))

    ap_code = str(payment.get("ap_account_code") or "2000")
    ap_name = str(payment.get("ap_account_name") or "Accounts Payable")
    payment_code = str(payment.get("payment_account_code") or "1000")
    payment_name = str(payment.get("payment_account_name") or "Cash / Payment Clearing")

    lines = [
        _journal_line(ap_code, ap_name, debit=amount, memo=f"Supplier payment {payment_number}"),
        _journal_line(payment_code, payment_name, credit=amount, memo=f"Pay supplier {payment_number}"),
    ]

    return {
        "event_type": "supplier_payment_recorded",
        "event_id": event.get("event_id"),
        "source": "nexapos",
        "tenant_id": event.get("tenant_id"),
        "received_at": event.get("received_at"),
        "source_number": payment_number,
        "status": "preview",
        "amount": amount,
        "summary": f"Preview journal for supplier payment {payment_number}",
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

    if event_type == "cash_movement_created":
        return _build_cash_movement_created_preview(event_with_received)

    if event_type == "stock_adjusted":
        return _build_stock_adjusted_preview(event_with_received)

    if event_type == "expense_created":
        return _build_expense_created_preview(event_with_received)

    if event_type == "payment_settlement_created":
        return _build_payment_settlement_created_preview(event_with_received)

    if event_type == "supplier_payment_recorded":
        return _build_supplier_payment_recorded_preview(event_with_received)

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

def _journal_draft_key(item: Dict[str, Any]) -> str:
    return f"{item.get('source') or 'unknown'}:{item.get('event_type') or 'unknown'}:{item.get('event_id') or 'unknown'}"


def _read_journal_drafts(limit: int = 500) -> list[Dict[str, Any]]:
    if not JOURNAL_DRAFT_STORE_PATH.exists():
        return []

    rows = []
    for line in JOURNAL_DRAFT_STORE_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            continue

    return list(reversed(rows))


def _append_journal_draft(draft: Dict[str, Any]) -> None:
    JOURNAL_DRAFT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with JOURNAL_DRAFT_STORE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(draft, ensure_ascii=False, default=_json_default) + "\n")


def _public_journal_draft_summary(draft: Dict[str, Any]) -> Dict[str, Any]:
    lines = draft.get("lines") or []
    return {
        "id": draft.get("id"),
        "draft_key": draft.get("draft_key"),
        "status": draft.get("status"),
        "source": draft.get("source"),
        "event_type": draft.get("event_type"),
        "event_id": draft.get("event_id"),
        "tenant_id": draft.get("tenant_id"),
        "source_number": draft.get("source_number"),
        "summary": draft.get("summary"),
        "amount": draft.get("amount"),
        "balanced": draft.get("balanced"),
        "line_count": len(lines),
        "created_at": draft.get("created_at"),
        "updated_at": draft.get("updated_at"),
        "posted_simulated_at": draft.get("posted_simulated_at"),
        "posted_simulated_by": draft.get("posted_simulated_by"),
        "posting_note": draft.get("posting_note"),
    }


@app.get("/api/v1/journal-drafts")
def list_journal_drafts(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    drafts = _read_journal_drafts()
    return {
        "ok": True,
        "count": len(drafts),
        "items": drafts,
    }


@app.get("/api/v1/journal-drafts/public")
def list_journal_drafts_public() -> Dict[str, Any]:
    drafts = _read_journal_drafts()
    return {
        "ok": True,
        "count": len(drafts),
        "items": [_public_journal_draft_summary(d) for d in drafts],
        "note": "Public dashboard endpoint returns draft metadata only.",
    }


@app.post("/api/v1/journal-drafts/generate-from-previews")
def generate_journal_drafts_from_previews(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    records = _event_records(limit=200)
    existing = _read_journal_drafts(limit=10000)
    existing_keys = {d.get("draft_key") for d in existing if d.get("draft_key")}

    created = []
    skipped = []

    for record in records:
        preview = _build_journal_preview(record, records=records)
        if not preview:
            continue

        draft_key = _journal_draft_key(preview)

        if draft_key in existing_keys:
            skipped.append({
                "draft_key": draft_key,
                "reason": "already_exists",
                "event_type": preview.get("event_type"),
                "event_id": preview.get("event_id"),
            })
            continue

        now = now_iso()
        draft = {
            "id": f"jd_{hashlib.sha1(draft_key.encode('utf-8')).hexdigest()[:16]}",
            "draft_key": draft_key,
            "status": "draft",
            "source": preview.get("source"),
            "event_type": preview.get("event_type"),
            "event_id": preview.get("event_id"),
            "tenant_id": preview.get("tenant_id"),
            "received_at": preview.get("received_at"),
            "source_number": preview.get("source_number"),
            "summary": preview.get("summary"),
            "amount": preview.get("amount"),
            "balanced": preview.get("balanced"),
            "lines": preview.get("lines") or [],
            "preview_meta": {
                "paired_sale_completed_found": preview.get("paired_sale_completed_found"),
            },
            "created_at": now,
            "updated_at": now,
        }

        _append_journal_draft(draft)
        existing_keys.add(draft_key)
        created.append(_public_journal_draft_summary(draft))

    return {
        "ok": True,
        "created_count": len(created),
        "skipped_count": len(skipped),
        "created": created,
        "skipped": skipped[:50],
        "note": "Drafts generated only. No permanent ledger posting was performed.",
    }

def _read_journal_drafts_chronological(limit: int = 10000) -> list[Dict[str, Any]]:
    if not JOURNAL_DRAFT_STORE_PATH.exists():
        return []

    rows = []
    for line in JOURNAL_DRAFT_STORE_PATH.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            continue

    return rows


def _write_journal_drafts_chronological(drafts: list[Dict[str, Any]]) -> None:
    JOURNAL_DRAFT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with JOURNAL_DRAFT_STORE_PATH.open("w", encoding="utf-8") as f:
        for draft in drafts:
            f.write(json.dumps(draft, ensure_ascii=False, default=_json_default) + "\n")


@app.post("/api/v1/journal-drafts/{draft_id}/post-simulated")
def post_journal_draft_simulated(draft_id: str, body: Optional[Dict[str, Any]] = None, _: None = Depends(require_internal_key)) -> Dict[str, Any]:
    body = body or {}
    drafts = _read_journal_drafts_chronological(limit=10000)

    if not drafts:
        raise HTTPException(status_code=404, detail="No journal drafts found")

    now = now_iso()
    updated = None

    for draft in drafts:
        if draft.get("id") != draft_id:
            continue

        if draft.get("status") == "posted_simulated":
            ledger_result = _materialize_simulated_ledger_from_draft(
                draft,
                posted_by=draft.get("posted_simulated_by") or body.get("posted_by") or "system",
            )
            return {
                "ok": True,
                "status": "already_posted_simulated",
                "draft": draft,
                "summary": _public_journal_draft_summary(draft),
                "ledger_result": ledger_result.get("summary"),
            }

        if draft.get("status") not in {"draft", "reviewed", None}:
            raise HTTPException(status_code=400, detail=f"Draft status cannot be posted_simulated from {draft.get('status')}")

        if not draft.get("balanced"):
            raise HTTPException(status_code=400, detail="Unbalanced draft cannot be posted")

        draft["status"] = "posted_simulated"
        draft["posted_simulated_at"] = now
        draft["posted_simulated_by"] = body.get("posted_by") or "system"
        draft["posting_note"] = body.get("note") or "Posted as simulated journal; permanent ledger posting not enabled yet."
        draft["updated_at"] = now
        updated = draft
        break

    if not updated:
        raise HTTPException(status_code=404, detail="Journal draft not found")

    _write_journal_drafts_chronological(drafts)
    ledger_result = _materialize_simulated_ledger_from_draft(
        updated,
        posted_by=updated.get("posted_simulated_by") or "system",
    )

    return {
        "ok": True,
        "status": "posted_simulated",
        "draft": updated,
        "summary": _public_journal_draft_summary(updated),
        "ledger_result": ledger_result.get("summary"),
        "note": "State transition plus simulated ledger materialization. No permanent ledger posting was performed.",
    }


@app.post("/api/v1/journal-drafts/post-first-draft-simulated")
def post_first_draft_simulated(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    drafts = _read_journal_drafts_chronological(limit=10000)

    for draft in drafts:
        if draft.get("status") == "draft" and draft.get("balanced"):
            return post_journal_draft_simulated(
                draft.get("id"),
                body={"posted_by": "system", "note": "B12 smoke test post simulated"},
                _=None,
            )

    return {
        "ok": True,
        "status": "no_draft_available",
        "message": "No draft journal is available for simulated posting.",
    }

def _read_jsonl_chronological(path: Path, limit: int = 10000) -> list[Dict[str, Any]]:
    if not path.exists():
        return []

    rows = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        try:
            rows.append(json.loads(line))
        except Exception:
            continue

    return rows


def _append_jsonl(path: Path, row: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, default=_json_default) + "\n")


def _ledger_entry_key(draft: Dict[str, Any]) -> str:
    return f"simledger:{draft.get('draft_key') or draft.get('id') or 'unknown'}"


def _ledger_entry_id(entry_key: str) -> str:
    return f"le_{hashlib.sha1(entry_key.encode('utf-8')).hexdigest()[:16]}"


def _existing_simulated_ledger_entry(entry_key: str) -> Optional[Dict[str, Any]]:
    for entry in _read_jsonl_chronological(SIM_LEDGER_ENTRY_STORE_PATH, limit=20000):
        if entry.get("entry_key") == entry_key:
            return entry
    return None


def _simulated_ledger_counts() -> Dict[str, int]:
    return {
        "entries": len(_read_jsonl_chronological(SIM_LEDGER_ENTRY_STORE_PATH, limit=50000)),
        "lines": len(_read_jsonl_chronological(SIM_LEDGER_LINE_STORE_PATH, limit=100000)),
    }


def _public_simulated_ledger_entry_summary(entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": entry.get("id"),
        "entry_key": entry.get("entry_key"),
        "status": entry.get("status"),
        "tenant_id": entry.get("tenant_id"),
        "source": entry.get("source"),
        "event_type": entry.get("event_type"),
        "event_id": entry.get("event_id"),
        "source_number": entry.get("source_number"),
        "draft_id": entry.get("draft_id"),
        "summary": entry.get("summary"),
        "amount": entry.get("amount"),
        "total_debit": entry.get("total_debit"),
        "total_credit": entry.get("total_credit"),
        "balanced": entry.get("balanced"),
        "line_count": entry.get("line_count"),
        "posted_simulated_at": entry.get("posted_simulated_at"),
        "posted_simulated_by": entry.get("posted_simulated_by"),
    }


def _materialize_simulated_ledger_from_draft(draft: Dict[str, Any], posted_by: str = "system") -> Dict[str, Any]:
    if not draft:
        raise HTTPException(status_code=404, detail="Draft not found")

    if not draft.get("balanced"):
        raise HTTPException(status_code=400, detail="Unbalanced draft cannot be materialized to simulated ledger")

    entry_key = _ledger_entry_key(draft)
    existing = _existing_simulated_ledger_entry(entry_key)
    if existing:
        return {
            "ok": True,
            "status": "already_materialized",
            "entry": existing,
            "summary": _public_simulated_ledger_entry_summary(existing),
        }

    now = now_iso()
    entry_id = _ledger_entry_id(entry_key)
    lines = draft.get("lines") or []
    total_debit = _money(sum(_money(line.get("debit")) for line in lines))
    total_credit = _money(sum(_money(line.get("credit")) for line in lines))

    entry = {
        "id": entry_id,
        "entry_key": entry_key,
        "status": "posted_simulated",
        "tenant_id": draft.get("tenant_id"),
        "source": draft.get("source"),
        "event_type": draft.get("event_type"),
        "event_id": draft.get("event_id"),
        "source_number": draft.get("source_number"),
        "draft_id": draft.get("id"),
        "draft_key": draft.get("draft_key"),
        "summary": draft.get("summary"),
        "amount": draft.get("amount"),
        "total_debit": total_debit,
        "total_credit": total_credit,
        "balanced": _money(total_debit) == _money(total_credit),
        "line_count": len(lines),
        "posted_simulated_at": draft.get("posted_simulated_at") or now,
        "posted_simulated_by": posted_by or draft.get("posted_simulated_by") or "system",
        "created_at": now,
        "updated_at": now,
        "note": "Simulated ledger only. This is not a final accounting ledger posting.",
    }

    if not entry["balanced"]:
        raise HTTPException(status_code=400, detail="Draft lines became unbalanced during materialization")

    _append_jsonl(SIM_LEDGER_ENTRY_STORE_PATH, entry)

    for index, line in enumerate(lines, start=1):
        line_id_seed = f"{entry_id}:{index}:{line.get('account_code')}:{line.get('debit')}:{line.get('credit')}"
        ledger_line = {
            "id": f"ll_{hashlib.sha1(line_id_seed.encode('utf-8')).hexdigest()[:18]}",
            "entry_id": entry_id,
            "entry_key": entry_key,
            "line_no": index,
            "tenant_id": entry.get("tenant_id"),
            "account_code": line.get("account_code"),
            "account_name": line.get("account_name"),
            "debit": _money(line.get("debit")),
            "credit": _money(line.get("credit")),
            "memo": line.get("memo"),
            "source": entry.get("source"),
            "event_type": entry.get("event_type"),
            "event_id": entry.get("event_id"),
            "draft_id": draft.get("id"),
            "status": "posted_simulated",
            "created_at": now,
        }
        _append_jsonl(SIM_LEDGER_LINE_STORE_PATH, ledger_line)

    return {
        "ok": True,
        "status": "materialized",
        "entry": entry,
        "summary": _public_simulated_ledger_entry_summary(entry),
    }


@app.get("/api/v1/simulated-ledger/entries")
def list_simulated_ledger_entries_public() -> Dict[str, Any]:
    entries = list(reversed(_read_jsonl_chronological(SIM_LEDGER_ENTRY_STORE_PATH, limit=500)))
    return {
        "ok": True,
        "count": len(entries),
        "items": [_public_simulated_ledger_entry_summary(e) for e in entries],
        "counts": _simulated_ledger_counts(),
        "note": "Simulated ledger only. Permanent ledger posting is not enabled yet.",
    }


@app.get("/api/v1/simulated-ledger/lines")
def list_simulated_ledger_lines_public(entry_id: Optional[str] = None) -> Dict[str, Any]:
    lines = list(reversed(_read_jsonl_chronological(SIM_LEDGER_LINE_STORE_PATH, limit=2000)))
    if entry_id:
        lines = [line for line in lines if line.get("entry_id") == entry_id]

    return {
        "ok": True,
        "count": len(lines),
        "items": lines[:500],
        "note": "Simulated ledger lines only.",
    }


@app.post("/api/v1/simulated-ledger/materialize-posted-drafts")
def materialize_posted_drafts_to_simulated_ledger(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    drafts = _read_journal_drafts_chronological(limit=10000)
    created = []
    skipped = []

    for draft in drafts:
        if draft.get("status") != "posted_simulated":
            skipped.append({
                "id": draft.get("id"),
                "status": draft.get("status"),
                "reason": "not_posted_simulated",
            })
            continue

        result = _materialize_simulated_ledger_from_draft(draft, posted_by=draft.get("posted_simulated_by") or "system")
        if result.get("status") == "materialized":
            created.append(result.get("summary"))
        else:
            skipped.append({
                "id": draft.get("id"),
                "status": result.get("status"),
                "reason": "already_materialized",
            })

    return {
        "ok": True,
        "created_count": len(created),
        "skipped_count": len(skipped),
        "created": created,
        "skipped": skipped[:100],
        "counts": _simulated_ledger_counts(),
    }

@app.post("/api/v1/journal-drafts/post-all-simulated")
def post_all_journal_drafts_simulated(body: Optional[Dict[str, Any]] = None, _: None = Depends(require_internal_key)) -> Dict[str, Any]:
    body = body or {}
    drafts = _read_journal_drafts_chronological(limit=10000)

    if not drafts:
        return {
            "ok": True,
            "posted_count": 0,
            "already_posted_count": 0,
            "skipped_count": 0,
            "ledger_materialized_count": 0,
            "ledger_already_materialized_count": 0,
            "message": "No journal drafts found.",
        }

    now = now_iso()
    posted_by = body.get("posted_by") or "system"
    note = body.get("note") or "B14 post all simulated"

    posted = []
    already_posted = []
    skipped = []
    ledger_materialized = []
    ledger_already_materialized = []
    changed = False

    for draft in drafts:
        status = draft.get("status")

        if status == "posted_simulated":
            already_posted.append(_public_journal_draft_summary(draft))
            ledger_result = _materialize_simulated_ledger_from_draft(
                draft,
                posted_by=draft.get("posted_simulated_by") or posted_by,
            )
            if ledger_result.get("status") == "materialized":
                ledger_materialized.append(ledger_result.get("summary"))
            else:
                ledger_already_materialized.append(ledger_result.get("summary"))
            continue

        if status not in {"draft", "reviewed", None}:
            skipped.append({
                "id": draft.get("id"),
                "status": status,
                "reason": "unsupported_status",
            })
            continue

        if not draft.get("balanced"):
            skipped.append({
                "id": draft.get("id"),
                "status": status,
                "reason": "unbalanced",
            })
            continue

        draft["status"] = "posted_simulated"
        draft["posted_simulated_at"] = now
        draft["posted_simulated_by"] = posted_by
        draft["posting_note"] = note
        draft["updated_at"] = now
        changed = True

        posted.append(_public_journal_draft_summary(draft))

        ledger_result = _materialize_simulated_ledger_from_draft(draft, posted_by=posted_by)
        if ledger_result.get("status") == "materialized":
            ledger_materialized.append(ledger_result.get("summary"))
        else:
            ledger_already_materialized.append(ledger_result.get("summary"))

    if changed:
        _write_journal_drafts_chronological(drafts)

    return {
        "ok": True,
        "posted_count": len(posted),
        "already_posted_count": len(already_posted),
        "skipped_count": len(skipped),
        "ledger_materialized_count": len(ledger_materialized),
        "ledger_already_materialized_count": len(ledger_already_materialized),
        "posted": posted,
        "already_posted": already_posted[:100],
        "skipped": skipped[:100],
        "ledger_materialized": ledger_materialized,
        "ledger_already_materialized": ledger_already_materialized[:100],
        "counts": _simulated_ledger_counts(),
        "note": "All balanced drafts were posted_simulated and materialized to simulated ledger idempotently.",
    }

@app.get("/api/v1/simulated-ledger/summary")
def simulated_ledger_summary() -> Dict[str, Any]:
    entries = _read_jsonl_chronological(SIM_LEDGER_ENTRY_STORE_PATH, limit=50000)
    lines = _read_jsonl_chronological(SIM_LEDGER_LINE_STORE_PATH, limit=100000)

    total_debit = _money(sum(_money(line.get("debit")) for line in lines))
    total_credit = _money(sum(_money(line.get("credit")) for line in lines))

    by_account = {}
    for line in lines:
        code = str(line.get("account_code") or "-")
        name = str(line.get("account_name") or "Unknown Account")
        key = f"{code}:{name}"

        if key not in by_account:
            by_account[key] = {
                "account_code": code,
                "account_name": name,
                "debit": 0.0,
                "credit": 0.0,
                "net_debit": 0.0,
                "net_credit": 0.0,
                "line_count": 0,
            }

        item = by_account[key]
        item["debit"] = _money(item["debit"] + _money(line.get("debit")))
        item["credit"] = _money(item["credit"] + _money(line.get("credit")))
        item["line_count"] += 1

    for item in by_account.values():
        net = _money(item["debit"] - item["credit"])
        item["net_debit"] = net if net > 0 else 0.0
        item["net_credit"] = abs(net) if net < 0 else 0.0

    by_event_type = {}
    for entry in entries:
        event_type = str(entry.get("event_type") or "unknown")
        if event_type not in by_event_type:
            by_event_type[event_type] = {
                "event_type": event_type,
                "entry_count": 0,
                "line_count": 0,
                "amount": 0.0,
                "total_debit": 0.0,
                "total_credit": 0.0,
                "balanced_entries": 0,
                "unbalanced_entries": 0,
            }

        item = by_event_type[event_type]
        item["entry_count"] += 1
        item["line_count"] += int(entry.get("line_count") or 0)
        item["amount"] = _money(item["amount"] + _money(entry.get("amount")))
        item["total_debit"] = _money(item["total_debit"] + _money(entry.get("total_debit")))
        item["total_credit"] = _money(item["total_credit"] + _money(entry.get("total_credit")))

        if entry.get("balanced"):
            item["balanced_entries"] += 1
        else:
            item["unbalanced_entries"] += 1

    unbalanced_entries = [
        _public_simulated_ledger_entry_summary(entry)
        for entry in entries
        if not entry.get("balanced")
    ]

    return {
        "ok": True,
        "summary": {
            "entry_count": len(entries),
            "line_count": len(lines),
            "total_debit": total_debit,
            "total_credit": total_credit,
            "difference": _money(total_debit - total_credit),
            "balanced": _money(total_debit) == _money(total_credit),
            "unbalanced_entry_count": len(unbalanced_entries),
        },
        "by_account": sorted(by_account.values(), key=lambda x: str(x.get("account_code") or "")),
        "by_event_type": sorted(by_event_type.values(), key=lambda x: str(x.get("event_type") or "")),
        "unbalanced_entries": unbalanced_entries,
        "note": "Simulated ledger summary only. Permanent accounting ledger is not enabled yet.",
    }

@app.get("/api/v1/reports/trial-balance-simulated")
def simulated_trial_balance_report() -> Dict[str, Any]:
    lines = _read_jsonl_chronological(SIM_LEDGER_LINE_STORE_PATH, limit=100000)
    entries = _read_jsonl_chronological(SIM_LEDGER_ENTRY_STORE_PATH, limit=50000)

    grouped = {}
    for line in lines:
        code = str(line.get("account_code") or "-")
        name = str(line.get("account_name") or "Unknown Account")
        key = f"{code}:{name}"

        if key not in grouped:
            grouped[key] = {
                "account_code": code,
                "account_name": name,
                "debit": 0.0,
                "credit": 0.0,
                "ending_debit": 0.0,
                "ending_credit": 0.0,
                "line_count": 0,
            }

        row = grouped[key]
        row["debit"] = _money(row["debit"] + _money(line.get("debit")))
        row["credit"] = _money(row["credit"] + _money(line.get("credit")))
        row["line_count"] += 1

    for row in grouped.values():
        net = _money(row["debit"] - row["credit"])
        if net >= 0:
            row["ending_debit"] = net
            row["ending_credit"] = 0.0
        else:
            row["ending_debit"] = 0.0
            row["ending_credit"] = abs(net)

    rows = sorted(grouped.values(), key=lambda x: str(x.get("account_code") or ""))

    totals = {
        "debit": _money(sum(row["debit"] for row in rows)),
        "credit": _money(sum(row["credit"] for row in rows)),
        "ending_debit": _money(sum(row["ending_debit"] for row in rows)),
        "ending_credit": _money(sum(row["ending_credit"] for row in rows)),
    }
    totals["movement_difference"] = _money(totals["debit"] - totals["credit"])
    totals["ending_difference"] = _money(totals["ending_debit"] - totals["ending_credit"])

    return {
        "ok": True,
        "report": "trial_balance_simulated",
        "basis": "simulated_ledger",
        "summary": {
            "account_count": len(rows),
            "entry_count": len(entries),
            "line_count": len(lines),
            "movement_balanced": totals["movement_difference"] == 0,
            "ending_balanced": totals["ending_difference"] == 0,
            "balanced": totals["movement_difference"] == 0 and totals["ending_difference"] == 0,
            **totals,
        },
        "rows": rows,
        "note": "Simulated trial balance only. Permanent accounting ledger is not enabled yet.",
    }

def _draft_key_for_event(event: Dict[str, Any]) -> str:
    return f"{event.get('source') or 'unknown'}:{event.get('event_type') or 'unknown'}:{event.get('event_id') or 'unknown'}"


def _find_draft_for_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    draft_key = _draft_key_for_event(event)
    for draft in _read_journal_drafts(limit=20000):
        if draft.get("draft_key") == draft_key:
            return draft
    return None


def _event_pipeline_status(record: Dict[str, Any], records: Optional[list[Dict[str, Any]]] = None) -> Dict[str, Any]:
    event = record.get("event") or {}
    event_key = _event_key_from_record(record)

    if record.get("status") == "dead_letter":
        return {
            "event_key": event_key,
            "status": "dead_letter",
            "received": False,
            "previewed": False,
            "drafted": False,
            "posted_simulated": False,
            "ledger_simulated": False,
            "reason": record.get("reason"),
        }

    records = records or _read_event_records_chronological(limit=20000)
    preview = _build_journal_preview(record, records=records)
    draft = _find_draft_for_event(event)

    ledger_entry = None
    if draft:
        ledger_entry = _existing_simulated_ledger_entry(_ledger_entry_key(draft))

    if ledger_entry:
        status = "ledger_simulated"
    elif draft and draft.get("status") == "posted_simulated":
        status = "posted_simulated"
    elif draft:
        status = "drafted"
    elif preview:
        status = "previewed"
    else:
        status = record.get("status") or "received"

    return {
        "event_key": event_key,
        "status": status,
        "received": True,
        "previewed": bool(preview),
        "drafted": bool(draft),
        "draft_status": draft.get("status") if draft else None,
        "draft_id": draft.get("id") if draft else None,
        "posted_simulated": bool(draft and draft.get("status") == "posted_simulated"),
        "ledger_simulated": bool(ledger_entry),
        "ledger_entry_id": ledger_entry.get("id") if ledger_entry else None,
        "reason": record.get("reason"),
    }


def _public_event_with_pipeline_status(record: Dict[str, Any], records: Optional[list[Dict[str, Any]]] = None) -> Dict[str, Any]:
    base = _public_event_summary(record)
    base["pipeline"] = _event_pipeline_status(record, records=records)
    return base


@app.get("/api/v1/events/status")
def list_event_pipeline_status(limit: int = 100) -> Dict[str, Any]:
    records = list(reversed(_read_event_records_chronological(limit=max(1, min(limit, 500)))))
    return {
        "ok": True,
        "count": len(records),
        "events": [_public_event_with_pipeline_status(record, records=list(reversed(records))) for record in records],
        "note": "Public event pipeline metadata only. Payload values are not exposed.",
    }


@app.get("/api/v1/events/dead-letter")
def list_dead_letter_events(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    rows = []
    if EVENT_DEAD_LETTER_STORE_PATH.exists():
        for line in EVENT_DEAD_LETTER_STORE_PATH.read_text(encoding="utf-8").splitlines()[-500:]:
            try:
                row = json.loads(line)
                if "event_key" not in row:
                    row["event_key"] = _event_key_from_record(row)
                rows.append(row)
            except Exception:
                continue

    rows = list(reversed(rows))
    return {
        "ok": True,
        "count": len(rows),
        "items": rows,
    }


@app.post("/api/v1/events/{event_key}/reprocess")
def reprocess_event(event_key: str, _: None = Depends(require_internal_key)) -> Dict[str, Any]:
    record = _find_event_record(event_key)
    if not record:
        dead = _find_dead_letter_record(event_key)
        if dead:
            raise HTTPException(status_code=400, detail=f"Event is in dead-letter: {dead.get('reason')}")
        raise HTTPException(status_code=404, detail="Event not found")

    records = _read_event_records_chronological(limit=20000)
    preview = _build_journal_preview(record, records=records)
    if not preview:
        dead = {
            "received_at": now_iso(),
            "status": "dead_letter",
            "event_key": event_key,
            "event": record.get("event") or {},
            "reason": "no_preview_available",
            "message": "Event could not be converted to journal preview",
        }
        _append_dead_letter_record(dead)
        return {
            "ok": True,
            "status": "dead_letter",
            "event_key": event_key,
            "reason": "no_preview_available",
        }

    existing_draft = _find_draft_for_event(record.get("event") or {})
    if existing_draft:
        return {
            "ok": True,
            "status": "already_drafted",
            "event_key": event_key,
            "draft": _public_journal_draft_summary(existing_draft),
            "pipeline": _event_pipeline_status(record, records=records),
        }

    now = now_iso()
    draft_key = _journal_draft_key(preview)
    draft = {
        "id": f"jd_{hashlib.sha1(draft_key.encode('utf-8')).hexdigest()[:16]}",
        "draft_key": draft_key,
        "status": "draft",
        "source": preview.get("source"),
        "event_type": preview.get("event_type"),
        "event_id": preview.get("event_id"),
        "tenant_id": preview.get("tenant_id"),
        "received_at": preview.get("received_at"),
        "source_number": preview.get("source_number"),
        "summary": preview.get("summary"),
        "amount": preview.get("amount"),
        "balanced": preview.get("balanced"),
        "lines": preview.get("lines") or [],
        "preview_meta": {
            "paired_sale_completed_found": preview.get("paired_sale_completed_found"),
            "reprocessed": True,
        },
        "created_at": now,
        "updated_at": now,
    }
    _append_journal_draft(draft)

    return {
        "ok": True,
        "status": "draft_created",
        "event_key": event_key,
        "draft": _public_journal_draft_summary(draft),
        "pipeline": _event_pipeline_status(record, records=records),
    }


@app.get("/api/v1/events/{event_key}")
def get_event_detail(event_key: str, _: None = Depends(require_internal_key)) -> Dict[str, Any]:
    record = _find_event_record(event_key)
    dead = None

    if not record:
        dead = _find_dead_letter_record(event_key)

    if not record and not dead:
        raise HTTPException(status_code=404, detail="Event not found")

    selected = record or dead
    records = _read_event_records_chronological(limit=20000)

    return {
        "ok": True,
        "event_key": event_key,
        "record": selected,
        "pipeline": _event_pipeline_status(selected, records=records),
    }

# ---------- B23_CHART_OF_ACCOUNTS_AND_MAPPING ----------
CHART_OF_ACCOUNTS_STORE_PATH = Path(os.getenv("CHART_OF_ACCOUNTS_STORE_PATH", "/data/accounting/app/nexa-accounting/data/chart_of_accounts.json"))
ACCOUNT_MAPPING_STORE_PATH = Path(os.getenv("ACCOUNT_MAPPING_STORE_PATH", "/data/accounting/app/nexa-accounting/data/account_mappings.json"))


DEFAULT_CHART_OF_ACCOUNTS = [
    {"code": "1000", "name": "Cash / Payment Clearing", "type": "asset", "normal_balance": "debit", "active": True, "description": "Cash drawer, payment clearing, or temporary cash account."},
    {"code": "1010", "name": "Bank", "type": "asset", "normal_balance": "debit", "active": True, "description": "Bank account for settlement deposits."},
    {"code": "1200", "name": "Inventory", "type": "asset", "normal_balance": "debit", "active": True, "description": "Inventory value."},
    {"code": "2000", "name": "Accounts Payable", "type": "liability", "normal_balance": "credit", "active": True, "description": "Supplier payable balance."},
    {"code": "4000", "name": "Sales Revenue", "type": "revenue", "normal_balance": "credit", "active": True, "description": "Product sales revenue."},
    {"code": "4100", "name": "Sales Discount", "type": "contra_revenue", "normal_balance": "debit", "active": True, "description": "Sales discount and voucher discount."},
    {"code": "5000", "name": "Cost of Goods Sold", "type": "expense", "normal_balance": "debit", "active": True, "description": "COGS from POS sales."},
    {"code": "6000", "name": "Operating Expense", "type": "expense", "normal_balance": "debit", "active": True, "description": "General operating expense."},
    {"code": "6100", "name": "Payment Fee Expense", "type": "expense", "normal_balance": "debit", "active": True, "description": "QRIS/card/payment provider fee."},
    {"code": "6200", "name": "Cash Over / Short", "type": "expense", "normal_balance": "debit", "active": True, "description": "Cash movement offset and cash variance."},
    {"code": "6300", "name": "Inventory Adjustment", "type": "expense", "normal_balance": "debit", "active": True, "description": "Stock adjustment gain/loss offset."},
]


DEFAULT_ACCOUNT_MAPPINGS = [
    {"key": "sale_completed.cash_debit", "event_type": "sale_completed", "role": "cash_debit", "account_code": "1000", "description": "Debit cash/payment clearing when sale is completed."},
    {"key": "sale_completed.sales_credit", "event_type": "sale_completed", "role": "sales_credit", "account_code": "4000", "description": "Credit sales revenue."},
    {"key": "sale_completed.discount_debit", "event_type": "sale_completed", "role": "discount_debit", "account_code": "4100", "description": "Debit sales discount when present."},
    {"key": "sale_completed.cogs_debit", "event_type": "sale_completed", "role": "cogs_debit", "account_code": "5000", "description": "Debit COGS when available."},
    {"key": "sale_completed.inventory_credit", "event_type": "sale_completed", "role": "inventory_credit", "account_code": "1200", "description": "Credit inventory for COGS."},

    {"key": "sale_voided.sales_debit", "event_type": "sale_voided", "role": "sales_debit", "account_code": "4000", "description": "Reverse sales revenue."},
    {"key": "sale_voided.cash_credit", "event_type": "sale_voided", "role": "cash_credit", "account_code": "1000", "description": "Reverse cash/payment clearing."},
    {"key": "sale_voided.inventory_debit", "event_type": "sale_voided", "role": "inventory_debit", "account_code": "1200", "description": "Restore inventory when voided."},
    {"key": "sale_voided.cogs_credit", "event_type": "sale_voided", "role": "cogs_credit", "account_code": "5000", "description": "Reverse COGS."},

    {"key": "purchase_order_received.inventory_debit", "event_type": "purchase_order_received", "role": "inventory_debit", "account_code": "1200", "description": "Debit inventory when PO is received."},
    {"key": "purchase_order_received.ap_credit", "event_type": "purchase_order_received", "role": "ap_credit", "account_code": "2000", "description": "Credit accounts payable."},

    {"key": "cash_movement_created.cash", "event_type": "cash_movement_created", "role": "cash", "account_code": "1000", "description": "Cash account for in/out movement."},
    {"key": "cash_movement_created.offset", "event_type": "cash_movement_created", "role": "offset", "account_code": "6200", "description": "Offset account for cash movement."},

    {"key": "stock_adjusted.inventory", "event_type": "stock_adjusted", "role": "inventory", "account_code": "1200", "description": "Inventory account for stock adjustment."},
    {"key": "stock_adjusted.offset", "event_type": "stock_adjusted", "role": "offset", "account_code": "6300", "description": "Inventory adjustment offset."},

    {"key": "expense_created.expense_debit", "event_type": "expense_created", "role": "expense_debit", "account_code": "6000", "description": "Default expense account."},
    {"key": "expense_created.payment_credit", "event_type": "expense_created", "role": "payment_credit", "account_code": "1000", "description": "Payment account for expense."},

    {"key": "payment_settlement_created.bank_debit", "event_type": "payment_settlement_created", "role": "bank_debit", "account_code": "1010", "description": "Bank account receiving settlement."},
    {"key": "payment_settlement_created.fee_debit", "event_type": "payment_settlement_created", "role": "fee_debit", "account_code": "6100", "description": "Payment fee expense."},
    {"key": "payment_settlement_created.clearing_credit", "event_type": "payment_settlement_created", "role": "clearing_credit", "account_code": "1000", "description": "Clear payment clearing balance."},

    {"key": "supplier_payment_recorded.ap_debit", "event_type": "supplier_payment_recorded", "role": "ap_debit", "account_code": "2000", "description": "Debit accounts payable."},
    {"key": "supplier_payment_recorded.payment_credit", "event_type": "supplier_payment_recorded", "role": "payment_credit", "account_code": "1000", "description": "Credit cash/bank payment account."},
]


def _read_json_file(path: Path, default_value: Any) -> Any:
    if not path.exists():
        return default_value
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default_value


def _write_json_file(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=_json_default), encoding="utf-8")


def _seed_accounting_settings_if_missing() -> Dict[str, Any]:
    created = {"chart_of_accounts": False, "account_mappings": False}

    if not CHART_OF_ACCOUNTS_STORE_PATH.exists():
        _write_json_file(CHART_OF_ACCOUNTS_STORE_PATH, DEFAULT_CHART_OF_ACCOUNTS)
        created["chart_of_accounts"] = True

    if not ACCOUNT_MAPPING_STORE_PATH.exists():
        _write_json_file(ACCOUNT_MAPPING_STORE_PATH, DEFAULT_ACCOUNT_MAPPINGS)
        created["account_mappings"] = True

    return created


def _chart_of_accounts() -> list[Dict[str, Any]]:
    _seed_accounting_settings_if_missing()
    rows = _read_json_file(CHART_OF_ACCOUNTS_STORE_PATH, DEFAULT_CHART_OF_ACCOUNTS)
    return sorted(rows, key=lambda x: str(x.get("code") or ""))


def _account_mappings() -> list[Dict[str, Any]]:
    _seed_accounting_settings_if_missing()
    rows = _read_json_file(ACCOUNT_MAPPING_STORE_PATH, DEFAULT_ACCOUNT_MAPPINGS)
    accounts = {str(a.get("code")): a for a in _chart_of_accounts()}
    enriched = []
    for row in rows:
        item = dict(row)
        account = accounts.get(str(item.get("account_code")))
        item["account_name"] = account.get("name") if account else None
        item["account_type"] = account.get("type") if account else None
        item["valid_account"] = bool(account)
        enriched.append(item)
    return sorted(enriched, key=lambda x: (str(x.get("event_type") or ""), str(x.get("role") or "")))


@app.get("/api/v1/settings/chart-of-accounts")
def get_chart_of_accounts_public() -> Dict[str, Any]:
    accounts = _chart_of_accounts()
    active = [a for a in accounts if a.get("active", True)]
    return {
        "ok": True,
        "count": len(accounts),
        "active_count": len(active),
        "items": accounts,
        "note": "Chart of accounts settings. Public metadata only.",
    }


@app.get("/api/v1/settings/account-mappings")
def get_account_mappings_public() -> Dict[str, Any]:
    mappings = _account_mappings()
    invalid = [m for m in mappings if not m.get("valid_account")]
    return {
        "ok": True,
        "count": len(mappings),
        "invalid_count": len(invalid),
        "items": mappings,
        "note": "Event-to-account mapping settings. Preview builders still use current hardcoded/default mapping until B24.",
    }


@app.post("/api/v1/settings/seed-defaults")
def seed_accounting_settings_defaults(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    created = _seed_accounting_settings_if_missing()
    return {
        "ok": True,
        "created": created,
        "chart_of_accounts": {
            "count": len(_chart_of_accounts()),
            "path": str(CHART_OF_ACCOUNTS_STORE_PATH),
        },
        "account_mappings": {
            "count": len(_account_mappings()),
            "path": str(ACCOUNT_MAPPING_STORE_PATH),
        },
    }


@app.put("/api/v1/settings/chart-of-accounts/{account_code}")
def upsert_chart_of_account(account_code: str, body: Dict[str, Any], _: None = Depends(require_internal_key)) -> Dict[str, Any]:
    if not account_code.strip():
        raise HTTPException(status_code=400, detail="account_code is required")

    rows = _chart_of_accounts()
    now = now_iso()
    found = False
    allowed_types = {"asset", "liability", "equity", "revenue", "contra_revenue", "expense"}

    account_type = body.get("type") or "expense"
    if account_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"Invalid account type: {account_type}")

    new_row = {
        "code": account_code,
        "name": body.get("name") or account_code,
        "type": account_type,
        "normal_balance": body.get("normal_balance") or ("credit" if account_type in {"liability", "equity", "revenue"} else "debit"),
        "active": bool(body.get("active", True)),
        "description": body.get("description") or "",
        "updated_at": now,
    }

    for idx, row in enumerate(rows):
        if str(row.get("code")) == str(account_code):
            rows[idx] = {**row, **new_row}
            found = True
            break

    if not found:
        new_row["created_at"] = now
        rows.append(new_row)

    _write_json_file(CHART_OF_ACCOUNTS_STORE_PATH, sorted(rows, key=lambda x: str(x.get("code") or "")))
    return {"ok": True, "created": not found, "account": new_row}


@app.put("/api/v1/settings/account-mappings/{mapping_key}")
def upsert_account_mapping(mapping_key: str, body: Dict[str, Any], _: None = Depends(require_internal_key)) -> Dict[str, Any]:
    if not mapping_key.strip():
        raise HTTPException(status_code=400, detail="mapping_key is required")

    rows = _account_mappings()
    accounts = {str(a.get("code")): a for a in _chart_of_accounts()}
    account_code = str(body.get("account_code") or "")

    if account_code not in accounts:
        raise HTTPException(status_code=400, detail=f"Account code not found: {account_code}")

    now = now_iso()
    found = False
    new_row = {
        "key": mapping_key,
        "event_type": body.get("event_type") or mapping_key.split(".")[0],
        "role": body.get("role") or mapping_key.split(".")[-1],
        "account_code": account_code,
        "description": body.get("description") or "",
        "updated_at": now,
    }

    raw_rows = _read_json_file(ACCOUNT_MAPPING_STORE_PATH, DEFAULT_ACCOUNT_MAPPINGS)
    for idx, row in enumerate(raw_rows):
        if str(row.get("key")) == str(mapping_key):
            raw_rows[idx] = {**row, **new_row}
            found = True
            break

    if not found:
        new_row["created_at"] = now
        raw_rows.append(new_row)

    _write_json_file(ACCOUNT_MAPPING_STORE_PATH, sorted(raw_rows, key=lambda x: (str(x.get("event_type") or ""), str(x.get("role") or ""))))
    return {"ok": True, "created": not found, "mapping": new_row}


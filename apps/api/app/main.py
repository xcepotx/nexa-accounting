import hashlib
import json
import time
import secrets
import hmac
import base64
import sqlite3
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
ACCOUNTING_AUTH_SECRET_KEY = os.getenv("ACCOUNTING_AUTH_SECRET_KEY", INTERNAL_API_KEY or "dev-change-me")
ACCOUNTING_TOKEN_TTL_SECONDS = int(os.getenv("ACCOUNTING_TOKEN_TTL_SECONDS", "86400") or 86400)
APP_USER_STORE_PATH = Path(os.getenv("APP_USER_STORE_PATH", "/data/accounting/app/nexa-accounting/data/app_users.json"))
ACCOUNTING_OWNER_EMAIL = os.getenv("ACCOUNTING_OWNER_EMAIL", "owner@nexa-accounting.local")
ACCOUNTING_OWNER_PASSWORD = os.getenv("ACCOUNTING_OWNER_PASSWORD", "")
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


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=1)


class UserCreateRequest(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)
    name: Optional[str] = None
    role: str = "viewer"
    is_active: bool = True


class UserPatchRequest(BaseModel):
    email: Optional[str] = None
    password: Optional[str] = None
    name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("utf-8"))


def _password_hash(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 160000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        algo, salt, digest = stored_hash.split("$", 2)
        if algo != "pbkdf2_sha256":
            return False
        expected = _password_hash(password, salt)
        return hmac.compare_digest(expected, stored_hash)
    except Exception:
        return False


def _read_app_users() -> list[Dict[str, Any]]:
    _seed_default_owner_user_if_missing()
    return _read_json_file(APP_USER_STORE_PATH, [])


def _write_app_users(users: list[Dict[str, Any]]) -> None:
    _write_json_file(APP_USER_STORE_PATH, users)


def _seed_default_owner_user_if_missing() -> None:
    if APP_USER_STORE_PATH.exists():
        return

    if not ACCOUNTING_OWNER_PASSWORD:
        generated = secrets.token_urlsafe(18)
        password = generated
    else:
        password = ACCOUNTING_OWNER_PASSWORD

    user = {
        "id": "owner",
        "email": ACCOUNTING_OWNER_EMAIL.lower().strip(),
        "name": "Owner",
        "role": "owner",
        "is_active": True,
        "password_hash": _password_hash(password),
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "note": "Default owner user seeded from ACCOUNTING_OWNER_EMAIL / ACCOUNTING_OWNER_PASSWORD.",
    }
    _write_json_file(APP_USER_STORE_PATH, [user])


def _public_user(user: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "name": user.get("name"),
        "role": user.get("role"),
        "is_active": bool(user.get("is_active", True)),
    }


VALID_APP_USER_ROLES = {"owner", "accountant", "viewer"}


def _validate_app_user_role(role: str) -> str:
    role = (role or "viewer").strip().lower()
    if role not in VALID_APP_USER_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {role}")
    return role


def _ensure_active_owner_remains(users: list[Dict[str, Any]]) -> None:
    active_owners = [
        user for user in users
        if user.get("role") == "owner" and user.get("is_active", True)
    ]
    if not active_owners:
        raise HTTPException(status_code=400, detail="At least one active owner is required")


def _auth_sign(payload: str) -> str:
    return hmac.new(ACCOUNTING_AUTH_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _create_auth_token(user: Dict[str, Any]) -> str:
    now_ts = int(time.time())
    payload = {
        "sub": user.get("id"),
        "email": user.get("email"),
        "role": user.get("role"),
        "iat": now_ts,
        "exp": now_ts + ACCOUNTING_TOKEN_TTL_SECONDS,
    }
    payload_raw = _b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    signature = _auth_sign(payload_raw)
    return f"{payload_raw}.{signature}"


def _verify_auth_token(token: str) -> Dict[str, Any]:
    if not token or "." not in token:
        raise HTTPException(status_code=401, detail="Invalid bearer token")

    payload_raw, signature = token.rsplit(".", 1)
    expected = _auth_sign(payload_raw)

    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid bearer token signature")

    try:
        payload = json.loads(_b64url_decode(payload_raw).decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid bearer token payload")

    if int(payload.get("exp") or 0) < int(time.time()):
        raise HTTPException(status_code=401, detail="Bearer token expired")

    users = _read_app_users()
    for user in users:
        if user.get("id") == payload.get("sub") and user.get("is_active", True):
            return user

    raise HTTPException(status_code=401, detail="User not found or inactive")


def get_current_user_optional(authorization: str = Header(default="")) -> Optional[Dict[str, Any]]:
    if not authorization:
        return None

    prefix = "Bearer "
    if not authorization.startswith(prefix):
        return None

    token = authorization[len(prefix):].strip()
    return _verify_auth_token(token)


def require_user_roles(*roles: str):
    def dependency(authorization: str = Header(default="")) -> Dict[str, Any]:
        user = get_current_user_optional(authorization)
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        if roles and user.get("role") not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return dependency


def require_internal_key(
    x_internal_api_key: str = Header(default=""),
    authorization: str = Header(default=""),
) -> None:
    if INTERNAL_API_KEY and x_internal_api_key == INTERNAL_API_KEY:
        return

    # Console operator auth: owner/accountant may call protected operational endpoints.
    if authorization.startswith("Bearer "):
        user = _verify_auth_token(authorization[len("Bearer "):].strip())
        if user.get("role") in {"owner", "accountant"}:
            return
        raise HTTPException(status_code=403, detail="Insufficient role")

    if not INTERNAL_API_KEY:
        raise HTTPException(status_code=500, detail="Internal API key is not configured")

    raise HTTPException(status_code=401, detail="Invalid internal API key")


@app.post("/api/v1/auth/login")
def auth_login(body: LoginRequest) -> Dict[str, Any]:
    email = body.email.lower().strip()
    users = _read_app_users()

    for user in users:
        if user.get("email") == email and user.get("is_active", True):
            if not _verify_password(body.password, user.get("password_hash") or ""):
                break

            token = _create_auth_token(user)
            return {
                "ok": True,
                "access_token": token,
                "token_type": "bearer",
                "expires_in": ACCOUNTING_TOKEN_TTL_SECONDS,
                "user": _public_user(user),
            }

    raise HTTPException(status_code=401, detail="Invalid email or password")


@app.get("/api/v1/auth/me")
def auth_me(user: Dict[str, Any] = Depends(require_user_roles("owner", "accountant", "viewer"))) -> Dict[str, Any]:
    return {
        "ok": True,
        "user": _public_user(user),
    }

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


def _mapping_account(event_type: str, role: str, fallback_code: str, fallback_name: str) -> Dict[str, Any]:
    mapping_key = f"{event_type}.{role}"

    try:
        for mapping in _account_mappings():
            if mapping.get("event_type") == event_type and mapping.get("role") == role and mapping.get("valid_account"):
                return {
                    "account_code": str(mapping.get("account_code") or fallback_code),
                    "account_name": str(mapping.get("account_name") or fallback_name),
                    "mapping_key": mapping.get("key") or mapping_key,
                    "mapping_source": "settings",
                }
    except Exception as exc:
        print(f"WARNING: account mapping lookup failed for {mapping_key}: {exc!r}", flush=True)

    return {
        "account_code": str(fallback_code),
        "account_name": str(fallback_name),
        "mapping_key": mapping_key,
        "mapping_source": "fallback",
    }


def _mapped_journal_line(event_type: str, role: str, fallback_code: str, fallback_name: str, debit: float = 0, credit: float = 0, memo: str = "") -> Dict[str, Any]:
    account = _mapping_account(event_type, role, fallback_code, fallback_name)
    line = _journal_line(
        account["account_code"],
        account["account_name"],
        debit=debit,
        credit=credit,
        memo=memo,
    )
    line["mapping_key"] = account.get("mapping_key")
    line["mapping_role"] = role
    line["mapping_source"] = account.get("mapping_source")
    return line


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
        _mapped_journal_line("sale_completed", "cash_debit", "1000", "Cash / Payment Clearing", debit=total, memo=f"Receive payment for {invoice}"),
        _mapped_journal_line("sale_completed", "sales_credit", "4000", "Sales Revenue", credit=net_sales, memo=f"Recognize sale {invoice}"),
    ]

    if discount > 0:
        lines.append(_mapped_journal_line("sale_completed", "discount_debit", "4100", "Sales Discount", debit=discount, memo=f"Discount for {invoice}"))

    if cogs > 0:
        lines.extend([
            _mapped_journal_line("sale_completed", "cogs_debit", "5000", "Cost of Goods Sold", debit=cogs, memo=f"COGS for {invoice}"),
            _mapped_journal_line("sale_completed", "inventory_credit", "1200", "Inventory", credit=cogs, memo=f"Inventory out for {invoice}"),
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
        _mapped_journal_line("sale_voided", "sales_debit", "4000", "Sales Revenue", debit=total, memo=f"Reverse sale {invoice}"),
        _mapped_journal_line("sale_voided", "cash_credit", "1000", "Cash / Payment Clearing", credit=total, memo=f"Refund/void payment for {invoice}"),
    ]

    if cogs > 0:
        lines.extend([
            _mapped_journal_line("sale_voided", "inventory_debit", "1200", "Inventory", debit=cogs, memo=f"Inventory restored for void {invoice}"),
            _mapped_journal_line("sale_voided", "cogs_credit", "5000", "Cost of Goods Sold", credit=cogs, memo=f"Reverse COGS for {invoice}"),
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
        _mapped_journal_line("purchase_order_received", "inventory_debit", "1200", "Inventory", debit=amount, memo=f"Receive inventory {po_number}/{receive_id}"),
        _mapped_journal_line("purchase_order_received", "ap_credit", "2000", "Accounts Payable", credit=amount, memo=f"AP for received PO {po_number}/{receive_id}"),
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
            _mapped_journal_line("cash_movement_created", "cash", "1000", "Cash / Payment Clearing", debit=amount, memo=f"Cash in {movement_id}"),
            _mapped_journal_line("cash_movement_created", "offset", "6200", "Cash Over / Short", credit=amount, memo=f"Cash movement offset {movement_id}"),
        ]
        summary = f"Preview journal for cash in {movement_id}"
    else:
        lines = [
            _mapped_journal_line("cash_movement_created", "offset", "6200", "Cash Over / Short", debit=amount, memo=f"Cash movement offset {movement_id}"),
            _mapped_journal_line("cash_movement_created", "cash", "1000", "Cash / Payment Clearing", credit=amount, memo=f"Cash out {movement_id}"),
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
            _mapped_journal_line("stock_adjusted", "inventory", "1200", "Inventory", debit=amount, memo=f"Stock increase {product_name} / {movement_id}"),
            _mapped_journal_line("stock_adjusted", "offset", "6300", "Inventory Adjustment", credit=amount, memo=f"Inventory adjustment offset {movement_id}"),
        ]
    else:
        lines = [
            _mapped_journal_line("stock_adjusted", "offset", "6300", "Inventory Adjustment", debit=amount, memo=f"Stock decrease {product_name} / {movement_id}"),
            _mapped_journal_line("stock_adjusted", "inventory", "1200", "Inventory", credit=amount, memo=f"Inventory decrease {movement_id}"),
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
        _mapped_journal_line("expense_created", "expense_debit", expense_code, expense_name, debit=amount, memo=f"Expense {expense_number}"),
        _mapped_journal_line("expense_created", "payment_credit", payment_code, payment_name, credit=amount, memo=f"Expense payment {expense_number}"),
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
        _mapped_journal_line("payment_settlement_created", "bank_debit", bank_code, bank_name, debit=net, memo=f"Settlement net received {settlement_number}"),
    ]

    if fee > 0:
        lines.append(_mapped_journal_line("payment_settlement_created", "fee_debit", fee_code, fee_name, debit=fee, memo=f"Settlement fee {settlement_number}"))

    lines.append(_mapped_journal_line("payment_settlement_created", "clearing_credit", clearing_code, clearing_name, credit=gross, memo=f"Clear payment settlement {settlement_number}"))

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
        _mapped_journal_line("supplier_payment_recorded", "ap_debit", ap_code, ap_name, debit=amount, memo=f"Supplier payment {payment_number}"),
        _mapped_journal_line("supplier_payment_recorded", "payment_credit", payment_code, payment_name, credit=amount, memo=f"Pay supplier {payment_number}"),
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
        db_sync_result = _sync_simulated_ledger_entry_to_db(existing)
        return {
            "ok": True,
            "status": "already_materialized",
            "entry": existing,
            "summary": _public_simulated_ledger_entry_summary(existing),
            "db_sync_result": db_sync_result,
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

    db_sync_result = _sync_simulated_ledger_entry_to_db(entry)

    return {
        "ok": True,
        "status": "materialized",
        "entry": entry,
        "summary": _public_simulated_ledger_entry_summary(entry),
        "db_sync_result": db_sync_result,
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
        "db_counts": _ledger_db_counts(),
        "db_note": "B25C: materialized entries are synced into SQLite ledger DB idempotently.",
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
    {"code": "1100", "name": "QRIS Clearing", "type": "asset", "normal_balance": "debit", "active": True, "description": "QRIS/payment provider clearing account before settlement to bank."},
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

# ---------- B25A_REAL_LEDGER_DB_SQLITE ----------
LEDGER_DB_PATH = Path(os.getenv("LEDGER_DB_PATH", "/data/accounting/app/nexa-accounting/data/nexa_accounting_ledger.db"))


def _ledger_db_connect() -> sqlite3.Connection:
    LEDGER_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(LEDGER_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _ledger_db_init() -> Dict[str, Any]:
    with _ledger_db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_entries (
                id TEXT PRIMARY KEY,
                entry_key TEXT UNIQUE NOT NULL,
                status TEXT NOT NULL,
                tenant_id TEXT,
                source TEXT,
                event_type TEXT,
                event_id TEXT,
                source_number TEXT,
                draft_id TEXT,
                draft_key TEXT,
                summary TEXT,
                amount REAL DEFAULT 0,
                total_debit REAL DEFAULT 0,
                total_credit REAL DEFAULT 0,
                balanced INTEGER DEFAULT 0,
                line_count INTEGER DEFAULT 0,
                posted_at TEXT,
                posted_by TEXT,
                created_at TEXT,
                updated_at TEXT,
                raw_json TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_lines (
                id TEXT PRIMARY KEY,
                entry_id TEXT NOT NULL,
                entry_key TEXT,
                line_no INTEGER,
                tenant_id TEXT,
                account_code TEXT,
                account_name TEXT,
                debit REAL DEFAULT 0,
                credit REAL DEFAULT 0,
                memo TEXT,
                source TEXT,
                event_type TEXT,
                event_id TEXT,
                draft_id TEXT,
                status TEXT,
                created_at TEXT,
                raw_json TEXT,
                FOREIGN KEY(entry_id) REFERENCES ledger_entries(id)
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_entries_event ON ledger_entries(event_type, event_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_entries_draft ON ledger_entries(draft_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_lines_entry ON ledger_lines(entry_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_lines_account ON ledger_lines(account_code)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_lines_event ON ledger_lines(event_type, event_id)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ledger_meta (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TEXT
            )
        """)

        conn.execute(
            "INSERT OR REPLACE INTO ledger_meta(key, value, updated_at) VALUES (?, ?, ?)",
            ("schema_version", "b25a_sqlite_ledger_v1", now_iso()),
        )
        conn.commit()

    return {
        "ok": True,
        "path": str(LEDGER_DB_PATH),
        "schema_version": "b25a_sqlite_ledger_v1",
    }


def _db_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _ledger_db_counts() -> Dict[str, int]:
    _ledger_db_init()
    with _ledger_db_connect() as conn:
        entries = conn.execute("SELECT COUNT(*) AS c FROM ledger_entries").fetchone()["c"]
        lines = conn.execute("SELECT COUNT(*) AS c FROM ledger_lines").fetchone()["c"]
    return {"entries": int(entries or 0), "lines": int(lines or 0)}


def _insert_ledger_entry_db(conn: sqlite3.Connection, entry: Dict[str, Any]) -> bool:
    raw_json = json.dumps(entry, ensure_ascii=False, default=_json_default)
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO ledger_entries (
            id, entry_key, status, tenant_id, source, event_type, event_id,
            source_number, draft_id, draft_key, summary, amount, total_debit,
            total_credit, balanced, line_count, posted_at, posted_by,
            created_at, updated_at, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.get("id"),
            entry.get("entry_key"),
            entry.get("status") or "posted_simulated",
            entry.get("tenant_id"),
            entry.get("source"),
            entry.get("event_type"),
            entry.get("event_id"),
            entry.get("source_number"),
            entry.get("draft_id"),
            entry.get("draft_key"),
            entry.get("summary"),
            _money(entry.get("amount")),
            _money(entry.get("total_debit")),
            _money(entry.get("total_credit")),
            1 if entry.get("balanced") else 0,
            int(entry.get("line_count") or 0),
            entry.get("posted_simulated_at") or entry.get("posted_at"),
            entry.get("posted_simulated_by") or entry.get("posted_by"),
            entry.get("created_at"),
            entry.get("updated_at"),
            raw_json,
        ),
    )
    return cur.rowcount > 0


def _insert_ledger_line_db(conn: sqlite3.Connection, line: Dict[str, Any]) -> bool:
    raw_json = json.dumps(line, ensure_ascii=False, default=_json_default)
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO ledger_lines (
            id, entry_id, entry_key, line_no, tenant_id, account_code,
            account_name, debit, credit, memo, source, event_type, event_id,
            draft_id, status, created_at, raw_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            line.get("id"),
            line.get("entry_id"),
            line.get("entry_key"),
            int(line.get("line_no") or 0),
            line.get("tenant_id"),
            line.get("account_code"),
            line.get("account_name"),
            _money(line.get("debit")),
            _money(line.get("credit")),
            line.get("memo"),
            line.get("source"),
            line.get("event_type"),
            line.get("event_id"),
            line.get("draft_id"),
            line.get("status") or "posted_simulated",
            line.get("created_at"),
            raw_json,
        ),
    )
    return cur.rowcount > 0


def _backfill_ledger_db_from_simulated_jsonl() -> Dict[str, Any]:
    _ledger_db_init()

    entries = _read_jsonl_chronological(SIM_LEDGER_ENTRY_STORE_PATH, limit=100000)
    lines = _read_jsonl_chronological(SIM_LEDGER_LINE_STORE_PATH, limit=200000)

    created_entries = 0
    skipped_entries = 0
    created_lines = 0
    skipped_lines = 0

    with _ledger_db_connect() as conn:
        for entry in entries:
            if _insert_ledger_entry_db(conn, entry):
                created_entries += 1
            else:
                skipped_entries += 1

        for line in lines:
            if _insert_ledger_line_db(conn, line):
                created_lines += 1
            else:
                skipped_lines += 1

        conn.execute(
            "INSERT OR REPLACE INTO ledger_meta(key, value, updated_at) VALUES (?, ?, ?)",
            ("last_backfill_from_simulated_jsonl", json.dumps({
                "created_entries": created_entries,
                "skipped_entries": skipped_entries,
                "created_lines": created_lines,
                "skipped_lines": skipped_lines,
            }, ensure_ascii=False), now_iso()),
        )
        conn.commit()

    return {
        "ok": True,
        "created_entries": created_entries,
        "skipped_entries": skipped_entries,
        "created_lines": created_lines,
        "skipped_lines": skipped_lines,
        "counts": _ledger_db_counts(),
    }


def _public_ledger_db_entry_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": row.get("id"),
        "entry_key": row.get("entry_key"),
        "status": row.get("status"),
        "tenant_id": row.get("tenant_id"),
        "source": row.get("source"),
        "event_type": row.get("event_type"),
        "event_id": row.get("event_id"),
        "source_number": row.get("source_number"),
        "draft_id": row.get("draft_id"),
        "summary": row.get("summary"),
        "amount": row.get("amount"),
        "total_debit": row.get("total_debit"),
        "total_credit": row.get("total_credit"),
        "balanced": bool(row.get("balanced")),
        "line_count": row.get("line_count"),
        "posted_at": row.get("posted_at"),
        "posted_by": row.get("posted_by"),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


@app.post("/api/v1/ledger-db/init")
def init_ledger_db(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    result = _ledger_db_init()
    result["counts"] = _ledger_db_counts()
    return result


@app.post("/api/v1/ledger-db/backfill-from-simulated")
def backfill_ledger_db_from_simulated(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    return _backfill_ledger_db_from_simulated_jsonl()


@app.get("/api/v1/ledger-db/entries")
def list_ledger_db_entries(limit: int = 500) -> Dict[str, Any]:
    _ledger_db_init()
    limit = max(1, min(limit, 1000))
    with _ledger_db_connect() as conn:
        rows = [
            _db_row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM ledger_entries ORDER BY COALESCE(posted_at, created_at, id) DESC LIMIT ?",
                (limit,),
            ).fetchall()
        ]

    return {
        "ok": True,
        "basis": "sqlite_ledger_db",
        "count": len(rows),
        "items": [_public_ledger_db_entry_summary(row) for row in rows],
        "counts": _ledger_db_counts(),
    }


@app.get("/api/v1/ledger-db/lines")
def list_ledger_db_lines(entry_id: Optional[str] = None, limit: int = 1000) -> Dict[str, Any]:
    _ledger_db_init()
    limit = max(1, min(limit, 5000))

    with _ledger_db_connect() as conn:
        if entry_id:
            rows = [
                _db_row_to_dict(row)
                for row in conn.execute(
                    "SELECT * FROM ledger_lines WHERE entry_id = ? ORDER BY line_no ASC LIMIT ?",
                    (entry_id, limit),
                ).fetchall()
            ]
        else:
            rows = [
                _db_row_to_dict(row)
                for row in conn.execute(
                    "SELECT * FROM ledger_lines ORDER BY COALESCE(created_at, id) DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            ]

    return {
        "ok": True,
        "basis": "sqlite_ledger_db",
        "count": len(rows),
        "items": rows,
    }


@app.get("/api/v1/ledger-db/summary")
def ledger_db_summary() -> Dict[str, Any]:
    _ledger_db_init()

    with _ledger_db_connect() as conn:
        totals = _db_row_to_dict(conn.execute("""
            SELECT
              COUNT(*) AS line_count,
              COALESCE(SUM(debit), 0) AS total_debit,
              COALESCE(SUM(credit), 0) AS total_credit
            FROM ledger_lines
        """).fetchone())

        entry_count = conn.execute("SELECT COUNT(*) AS c FROM ledger_entries").fetchone()["c"]

        by_account = [
            _db_row_to_dict(row)
            for row in conn.execute("""
                SELECT
                  account_code,
                  account_name,
                  COUNT(*) AS line_count,
                  COALESCE(SUM(debit), 0) AS debit,
                  COALESCE(SUM(credit), 0) AS credit
                FROM ledger_lines
                GROUP BY account_code, account_name
                ORDER BY account_code
            """).fetchall()
        ]

        by_event_type = [
            _db_row_to_dict(row)
            for row in conn.execute("""
                SELECT
                  event_type,
                  COUNT(DISTINCT entry_id) AS entry_count,
                  COUNT(*) AS line_count,
                  COALESCE(SUM(debit), 0) AS total_debit,
                  COALESCE(SUM(credit), 0) AS total_credit
                FROM ledger_lines
                GROUP BY event_type
                ORDER BY event_type
            """).fetchall()
        ]

        unbalanced_entries = [
            _public_ledger_db_entry_summary(_db_row_to_dict(row))
            for row in conn.execute("""
                SELECT * FROM ledger_entries
                WHERE balanced = 0 OR ROUND(total_debit - total_credit, 2) != 0
                ORDER BY COALESCE(posted_at, created_at, id) DESC
            """).fetchall()
        ]

    for item in by_account:
        net = _money(_money(item.get("debit")) - _money(item.get("credit")))
        item["net_debit"] = net if net > 0 else 0.0
        item["net_credit"] = abs(net) if net < 0 else 0.0

    total_debit = _money(totals.get("total_debit"))
    total_credit = _money(totals.get("total_credit"))

    return {
        "ok": True,
        "basis": "sqlite_ledger_db",
        "summary": {
            "entry_count": int(entry_count or 0),
            "line_count": int(totals.get("line_count") or 0),
            "total_debit": total_debit,
            "total_credit": total_credit,
            "difference": _money(total_debit - total_credit),
            "balanced": _money(total_debit) == _money(total_credit),
            "unbalanced_entry_count": len(unbalanced_entries),
        },
        "by_account": by_account,
        "by_event_type": by_event_type,
        "unbalanced_entries": unbalanced_entries,
    }


@app.get("/api/v1/reports/trial-balance-db")
def trial_balance_db_report() -> Dict[str, Any]:
    summary = ledger_db_summary()
    rows = []

    for item in summary.get("by_account", []):
        rows.append({
            "account_code": item.get("account_code"),
            "account_name": item.get("account_name"),
            "debit": _money(item.get("debit")),
            "credit": _money(item.get("credit")),
            "ending_debit": _money(item.get("net_debit")),
            "ending_credit": _money(item.get("net_credit")),
            "line_count": item.get("line_count"),
        })

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
        "report": "trial_balance_db",
        "basis": "sqlite_ledger_db",
        "summary": {
            "account_count": len(rows),
            "entry_count": summary.get("summary", {}).get("entry_count", 0),
            "line_count": summary.get("summary", {}).get("line_count", 0),
            "movement_balanced": totals["movement_difference"] == 0,
            "ending_balanced": totals["ending_difference"] == 0,
            "balanced": totals["movement_difference"] == 0 and totals["ending_difference"] == 0,
            **totals,
        },
        "rows": rows,
        "note": "Trial balance generated from SQLite ledger DB.",
    }

# ---------- B25C_DIRECT_SQLITE_LEDGER_WRITE ----------
def _sync_simulated_ledger_entry_to_db(entry: Dict[str, Any]) -> Dict[str, Any]:
    if not entry:
        return {"ok": False, "reason": "empty_entry"}

    if "LEDGER_DB_PATH" not in globals():
        return {"ok": False, "reason": "ledger_db_not_available"}

    _ledger_db_init()

    entry_key = entry.get("entry_key")
    entry_id = entry.get("id")

    all_lines = _read_jsonl_chronological(SIM_LEDGER_LINE_STORE_PATH, limit=300000)
    lines = [
        line for line in all_lines
        if (entry_key and line.get("entry_key") == entry_key)
        or (entry_id and line.get("entry_id") == entry_id)
    ]

    created_entry = 0
    created_lines = 0
    skipped_entry = 0
    skipped_lines = 0

    with _ledger_db_connect() as conn:
        if _insert_ledger_entry_db(conn, entry):
            created_entry = 1
        else:
            skipped_entry = 1

        for line in lines:
            if _insert_ledger_line_db(conn, line):
                created_lines += 1
            else:
                skipped_lines += 1

        conn.execute(
            "INSERT OR REPLACE INTO ledger_meta(key, value, updated_at) VALUES (?, ?, ?)",
            (
                "last_direct_sync_from_materialize",
                json.dumps({
                    "entry_key": entry_key,
                    "entry_id": entry_id,
                    "created_entry": created_entry,
                    "created_lines": created_lines,
                    "skipped_entry": skipped_entry,
                    "skipped_lines": skipped_lines,
                }, ensure_ascii=False),
                now_iso(),
            ),
        )
        conn.commit()

    return {
        "ok": True,
        "basis": "sqlite_ledger_db",
        "entry_key": entry_key,
        "entry_id": entry_id,
        "created_entry": created_entry,
        "created_lines": created_lines,
        "skipped_entry": skipped_entry,
        "skipped_lines": skipped_lines,
        "counts": _ledger_db_counts(),
    }


def _sync_all_simulated_ledger_to_db() -> Dict[str, Any]:
    return _backfill_ledger_db_from_simulated_jsonl()

@app.post("/api/v1/ledger-db/sync-from-simulated")
def sync_ledger_db_from_simulated(_: None = Depends(require_internal_key)) -> Dict[str, Any]:
    result = _sync_all_simulated_ledger_to_db()
    result["note"] = "Idempotent sync from simulated JSONL compatibility store into SQLite ledger DB."
    return result

@app.get("/api/v1/users")
def list_app_users(user: Dict[str, Any] = Depends(require_user_roles("owner"))) -> Dict[str, Any]:
    users = _read_app_users()
    public_users = sorted(
        [_public_user(item) for item in users],
        key=lambda x: (str(x.get("role") or ""), str(x.get("email") or "")),
    )
    return {
        "ok": True,
        "count": len(public_users),
        "items": public_users,
    }


@app.post("/api/v1/users")
def create_app_user(body: UserCreateRequest, user: Dict[str, Any] = Depends(require_user_roles("owner"))) -> Dict[str, Any]:
    users = _read_app_users()
    email = body.email.lower().strip()
    role = _validate_app_user_role(body.role)

    if any((item.get("email") or "").lower().strip() == email for item in users):
        raise HTTPException(status_code=400, detail="Email already exists")

    now = now_iso()
    new_user = {
        "id": f"usr_{secrets.token_hex(8)}",
        "email": email,
        "name": body.name or email.split("@")[0],
        "role": role,
        "is_active": bool(body.is_active),
        "password_hash": _password_hash(body.password),
        "created_at": now,
        "updated_at": now,
        "created_by": user.get("id"),
    }

    next_users = users + [new_user]
    _ensure_active_owner_remains(next_users)
    _write_app_users(next_users)

    return {
        "ok": True,
        "user": _public_user(new_user),
    }


@app.patch("/api/v1/users/{user_id}")
def update_app_user(user_id: str, body: UserPatchRequest, user: Dict[str, Any] = Depends(require_user_roles("owner"))) -> Dict[str, Any]:
    users = _read_app_users()
    now = now_iso()
    found = None

    for idx, item in enumerate(users):
        if item.get("id") == user_id:
            found = idx
            break

    if found is None:
        raise HTTPException(status_code=404, detail="User not found")

    target = dict(users[found])

    if body.email is not None:
        email = body.email.lower().strip()
        if any((item.get("email") or "").lower().strip() == email and item.get("id") != user_id for item in users):
            raise HTTPException(status_code=400, detail="Email already exists")
        target["email"] = email

    if body.name is not None:
        target["name"] = body.name

    if body.role is not None:
        target["role"] = _validate_app_user_role(body.role)

    if body.is_active is not None:
        target["is_active"] = bool(body.is_active)

    if body.password:
        if len(body.password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        target["password_hash"] = _password_hash(body.password)

    target["updated_at"] = now
    target["updated_by"] = user.get("id")

    next_users = list(users)
    next_users[found] = target
    _ensure_active_owner_remains(next_users)
    _write_app_users(next_users)

    return {
        "ok": True,
        "user": _public_user(target),
    }

@app.get("/api/v1/reports/profit-loss-db")
def profit_loss_db_report() -> Dict[str, Any]:
    _ledger_db_init()

    accounts = {str(a.get("code")): a for a in _chart_of_accounts()}

    with _ledger_db_connect() as conn:
        grouped = [
            _db_row_to_dict(row)
            for row in conn.execute("""
                SELECT
                  account_code,
                  account_name,
                  COUNT(*) AS line_count,
                  COALESCE(SUM(debit), 0) AS debit,
                  COALESCE(SUM(credit), 0) AS credit
                FROM ledger_lines
                GROUP BY account_code, account_name
                ORDER BY account_code
            """).fetchall()
        ]

    revenue_rows = []
    contra_revenue_rows = []
    expense_rows = []
    other_rows = []

    total_revenue = 0.0
    total_contra_revenue = 0.0
    total_expense = 0.0

    for row in grouped:
        account_code = str(row.get("account_code") or "")
        account = accounts.get(account_code) or {}
        account_type = account.get("type") or "unknown"
        account_name = account.get("name") or row.get("account_name") or account_code

        debit = _money(row.get("debit"))
        credit = _money(row.get("credit"))

        item = {
            "account_code": account_code,
            "account_name": account_name,
            "account_type": account_type,
            "line_count": int(row.get("line_count") or 0),
            "debit": debit,
            "credit": credit,
            "amount": 0.0,
        }

        if account_type == "revenue":
            amount = _money(credit - debit)
            item["amount"] = amount
            total_revenue = _money(total_revenue + amount)
            revenue_rows.append(item)
        elif account_type == "contra_revenue":
            amount = _money(debit - credit)
            item["amount"] = amount
            total_contra_revenue = _money(total_contra_revenue + amount)
            contra_revenue_rows.append(item)
        elif account_type == "expense":
            amount = _money(debit - credit)
            item["amount"] = amount
            total_expense = _money(total_expense + amount)
            expense_rows.append(item)
        else:
            # Asset/liability/equity accounts are not P&L rows, but expose them for audit context.
            item["amount"] = _money(debit - credit)
            other_rows.append(item)

    net_revenue = _money(total_revenue - total_contra_revenue)
    net_income = _money(net_revenue - total_expense)

    return {
        "ok": True,
        "report": "profit_loss_db",
        "basis": "sqlite_ledger_db",
        "summary": {
            "revenue": total_revenue,
            "contra_revenue": total_contra_revenue,
            "net_revenue": net_revenue,
            "expenses": total_expense,
            "net_income": net_income,
            "revenue_account_count": len(revenue_rows),
            "contra_revenue_account_count": len(contra_revenue_rows),
            "expense_account_count": len(expense_rows),
            "other_account_count": len(other_rows),
        },
        "sections": {
            "revenue": revenue_rows,
            "contra_revenue": contra_revenue_rows,
            "expenses": expense_rows,
            "other_non_pl_accounts": other_rows,
        },
        "note": "Profit & Loss generated from SQLite ledger DB and account types in Chart of Accounts.",
    }

@app.get("/api/v1/reports/balance-sheet-db")
def balance_sheet_db_report() -> Dict[str, Any]:
    _ledger_db_init()

    accounts = {str(a.get("code")): a for a in _chart_of_accounts()}
    pl = profit_loss_db_report()
    current_period_net_income = _money((pl.get("summary") or {}).get("net_income"))

    with _ledger_db_connect() as conn:
        grouped = [
            _db_row_to_dict(row)
            for row in conn.execute("""
                SELECT
                  account_code,
                  account_name,
                  COUNT(*) AS line_count,
                  COALESCE(SUM(debit), 0) AS debit,
                  COALESCE(SUM(credit), 0) AS credit
                FROM ledger_lines
                GROUP BY account_code, account_name
                ORDER BY account_code
            """).fetchall()
        ]

    asset_rows = []
    liability_rows = []
    equity_rows = []
    non_balance_sheet_rows = []

    total_assets = 0.0
    total_liabilities = 0.0
    total_equity = 0.0

    for row in grouped:
        account_code = str(row.get("account_code") or "")
        account = accounts.get(account_code) or {}
        account_type = account.get("type") or "unknown"
        account_name = account.get("name") or row.get("account_name") or account_code

        debit = _money(row.get("debit"))
        credit = _money(row.get("credit"))

        item = {
            "account_code": account_code,
            "account_name": account_name,
            "account_type": account_type,
            "line_count": int(row.get("line_count") or 0),
            "debit": debit,
            "credit": credit,
            "amount": 0.0,
        }

        if account_type == "asset":
            amount = _money(debit - credit)
            item["amount"] = amount
            total_assets = _money(total_assets + amount)
            asset_rows.append(item)
        elif account_type == "liability":
            amount = _money(credit - debit)
            item["amount"] = amount
            total_liabilities = _money(total_liabilities + amount)
            liability_rows.append(item)
        elif account_type == "equity":
            amount = _money(credit - debit)
            item["amount"] = amount
            total_equity = _money(total_equity + amount)
            equity_rows.append(item)
        else:
            # Revenue and expense accounts are represented through current period net income.
            item["amount"] = _money(credit - debit)
            non_balance_sheet_rows.append(item)

    total_equity_with_income = _money(total_equity + current_period_net_income)
    total_liabilities_and_equity = _money(total_liabilities + total_equity_with_income)
    difference = _money(total_assets - total_liabilities_and_equity)

    retained_income_row = {
        "account_code": "NET-INCOME",
        "account_name": "Current Period Net Income",
        "account_type": "equity_bridge",
        "line_count": 0,
        "debit": 0.0,
        "credit": 0.0,
        "amount": current_period_net_income,
    }

    return {
        "ok": True,
        "report": "balance_sheet_db",
        "basis": "sqlite_ledger_db",
        "summary": {
            "assets": total_assets,
            "liabilities": total_liabilities,
            "equity": total_equity,
            "current_period_net_income": current_period_net_income,
            "equity_with_current_income": total_equity_with_income,
            "liabilities_and_equity": total_liabilities_and_equity,
            "difference": difference,
            "balanced": difference == 0,
            "asset_account_count": len(asset_rows),
            "liability_account_count": len(liability_rows),
            "equity_account_count": len(equity_rows),
            "non_balance_sheet_account_count": len(non_balance_sheet_rows),
        },
        "sections": {
            "assets": asset_rows,
            "liabilities": liability_rows,
            "equity": equity_rows,
            "current_period_income": [retained_income_row],
            "non_balance_sheet_accounts": non_balance_sheet_rows,
        },
        "note": "Balance Sheet generated from SQLite ledger DB and Chart of Accounts. Revenue/expense accounts are bridged through current period net income.",
    }

@app.get("/api/v1/reports/balance-sheet-diagnostics-db")
def balance_sheet_diagnostics_db_report() -> Dict[str, Any]:
    _ledger_db_init()

    accounts = {str(a.get("code")): a for a in _chart_of_accounts()}
    bs = balance_sheet_db_report()
    pl = profit_loss_db_report()
    tb = trial_balance_db_report()

    with _ledger_db_connect() as conn:
        grouped = [
            _db_row_to_dict(row)
            for row in conn.execute("""
                SELECT
                  account_code,
                  account_name,
                  COUNT(*) AS line_count,
                  COALESCE(SUM(debit), 0) AS debit,
                  COALESCE(SUM(credit), 0) AS credit
                FROM ledger_lines
                GROUP BY account_code, account_name
                ORDER BY account_code
            """).fetchall()
        ]

    diagnostic_rows = []
    unknown_accounts = []
    negative_assets = []
    negative_liabilities = []
    negative_equity = []
    p_and_l_rows = []
    balance_sheet_rows = []

    for row in grouped:
        account_code = str(row.get("account_code") or "")
        account = accounts.get(account_code)
        account_type = (account or {}).get("type") or "unknown"
        account_name = (account or {}).get("name") or row.get("account_name") or account_code

        debit = _money(row.get("debit"))
        credit = _money(row.get("credit"))

        if account_type == "asset":
            amount = _money(debit - credit)
            section = "balance_sheet"
            sign_issue = amount < 0
        elif account_type in {"liability", "equity"}:
            amount = _money(credit - debit)
            section = "balance_sheet"
            sign_issue = amount < 0
        elif account_type == "revenue":
            amount = _money(credit - debit)
            section = "profit_loss"
            sign_issue = amount < 0
        elif account_type in {"contra_revenue", "expense"}:
            amount = _money(debit - credit)
            section = "profit_loss"
            sign_issue = amount < 0
        else:
            amount = _money(debit - credit)
            section = "unclassified"
            sign_issue = amount != 0

        issue = None
        severity = "ok"

        if account_type == "unknown":
            issue = "Account is not found in Chart of Accounts, so it is excluded from formal P&L/Balance Sheet classification."
            severity = "high"
        elif account_type == "asset" and amount < 0:
            issue = "Asset has credit balance."
            severity = "medium"
        elif account_type == "liability" and amount < 0:
            issue = "Liability has debit balance. This can happen if supplier payments exceed AP/opening payable."
            severity = "medium"
        elif account_type == "equity" and amount < 0:
            issue = "Equity has debit balance."
            severity = "medium"
        elif account_type in {"revenue", "contra_revenue", "expense"}:
            issue = "P&L account; represented in Balance Sheet through current period net income."
            severity = "info"

        item = {
            "account_code": account_code,
            "account_name": account_name,
            "account_type": account_type,
            "section": section,
            "line_count": int(row.get("line_count") or 0),
            "debit": debit,
            "credit": credit,
            "amount": amount,
            "issue": issue,
            "severity": severity,
            "sign_issue": sign_issue,
        }
        diagnostic_rows.append(item)

        if account_type == "unknown":
            unknown_accounts.append(item)
        if account_type == "asset" and amount < 0:
            negative_assets.append(item)
        if account_type == "liability" and amount < 0:
            negative_liabilities.append(item)
        if account_type == "equity" and amount < 0:
            negative_equity.append(item)
        if section == "profit_loss":
            p_and_l_rows.append(item)
        if section == "balance_sheet":
            balance_sheet_rows.append(item)

    bs_summary = bs.get("summary") or {}
    pl_summary = pl.get("summary") or {}
    tb_summary = tb.get("summary") or {}

    likely_causes = []

    if unknown_accounts:
        likely_causes.append({
            "severity": "high",
            "title": "Unclassified ledger accounts found",
            "detail": "Some account codes in ledger DB do not exist in Chart of Accounts. Add them to COA with correct type.",
            "count": len(unknown_accounts),
        })

    if negative_liabilities:
        likely_causes.append({
            "severity": "medium",
            "title": "Negative liability balance",
            "detail": "Accounts Payable or another liability has debit balance. This usually means payment was recorded without enough AP/opening payable.",
            "count": len(negative_liabilities),
        })

    if not bs_summary.get("balanced"):
        likely_causes.append({
            "severity": "medium",
            "title": "Balance Sheet difference exists",
            "detail": "Difference may require account classification fix, opening balance, owner capital, retained earnings, or correction entry.",
            "difference": bs_summary.get("difference"),
        })

    if not [row for row in balance_sheet_rows if row.get("account_type") == "equity"]:
        likely_causes.append({
            "severity": "info",
            "title": "No equity account balance",
            "detail": "If this dataset starts mid-period or after historical transactions, an opening equity/capital balance may be needed.",
            "count": 0,
        })

    suggested_actions = [
        "First fix unknown account classifications in Chart of Accounts.",
        "Review negative liability accounts, especially Accounts Payable, against purchase receipts and supplier payments.",
        "If the dataset starts mid-period, create opening balance / owner capital entry after classification is correct.",
        "Do not force a balancing adjustment until unclassified accounts and negative AP are reviewed.",
    ]

    return {
        "ok": True,
        "report": "balance_sheet_diagnostics_db",
        "basis": "sqlite_ledger_db",
        "summary": {
            "trial_balance_balanced": tb_summary.get("balanced"),
            "balance_sheet_balanced": bs_summary.get("balanced"),
            "balance_sheet_difference": bs_summary.get("difference"),
            "assets": bs_summary.get("assets"),
            "liabilities": bs_summary.get("liabilities"),
            "equity": bs_summary.get("equity"),
            "current_period_net_income": bs_summary.get("current_period_net_income"),
            "liabilities_and_equity": bs_summary.get("liabilities_and_equity"),
            "net_income": pl_summary.get("net_income"),
            "unknown_account_count": len(unknown_accounts),
            "negative_asset_count": len(negative_assets),
            "negative_liability_count": len(negative_liabilities),
            "negative_equity_count": len(negative_equity),
            "diagnostic_row_count": len(diagnostic_rows),
        },
        "likely_causes": likely_causes,
        "suggested_actions": suggested_actions,
        "rows": diagnostic_rows,
        "sections": {
            "unknown_accounts": unknown_accounts,
            "negative_assets": negative_assets,
            "negative_liabilities": negative_liabilities,
            "negative_equity": negative_equity,
            "profit_loss_accounts": p_and_l_rows,
            "balance_sheet_accounts": balance_sheet_rows,
        },
        "note": "Diagnostics only. No automatic balancing adjustment is posted by this endpoint.",
    }


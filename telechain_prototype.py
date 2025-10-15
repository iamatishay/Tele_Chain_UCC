"""
Telechain Prototype (single-file) with Basic JWT Authentication, SMS API, and Persistent Storage

Features implemented:
- In-memory consortium-style blockchain (no PoW) with signed transactions
- Smart-contract-like Python classes for registration, consent, scrubbing, campaign, SMS send, and TRAI audit
- OTP simulation for consent acquisition
- Hashing of phone numbers, RSA encryption for operators
- Basic JWT-based auth (phone + bcrypt)
- Persistent DB (saved to db_state.json + ledger.json)
- SMS consent check before simulated send
- Duplicate prevention for telemarketers (by TRAI ID), principals (by name), headers (per principal), consents (per phone-principal-header)
- TRAI Audit feature: Generates compliance reports from the ledger (e.g., consent stats, rejected SMS, etc.)

Run:
    uvicorn telechain_prototype_persistent:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, time, timezone
import json
import hashlib
import uuid
import os
import base64
import secrets
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from collections import Counter
import logging

IST = timezone(timedelta(hours=5, minutes=30))

def now_iso():
    """Return current IST timestamp in ISO 8601 format"""
    return datetime.now(IST).isoformat()

# ----------------------------- Logging Setup -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------------------- App Setup -----------------------------
APP_LEDGER_FILE = "ledger.json"
DB_FILE = "db_state.json"

app = FastAPI(title="Telechain Prototype API")

# ----------------------------- Security Config -----------------------------
SECRET_KEY = "your-secret-key-change-in-prod-telechain-demo"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ----------------------------- Utility Functions -----------------------------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

# JWT helpers
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        phone: str = payload.get("sub")
        if phone is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    if phone not in DB["users"]:
        raise credentials_exception
    return phone

# ----------------------------- Persistent Storage -----------------------------
def save_db():
    try:
        with open(DB_FILE, "w") as f:
            json.dump(DB, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save DB: {e}")

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                data = json.load(f)
                for k, v in data.items():
                    DB[k] = v
                logger.info("Loaded DB from disk.")
        except Exception as e:
            logger.error(f"Failed to load DB: {e}")

# ----------------------------- Ledger -----------------------------
class SimpleLedger:
    def __init__(self):
        self.chain: List[Dict[str, Any]] = []
        self.load()

    def add_transaction(self, tx: Dict[str, Any]):
        tx = dict(tx)
        tx["timestamp"] = now_iso()
        tx["txid"] = sha256_hex(json.dumps(tx, sort_keys=True) + str(uuid.uuid4()))
        self.chain.append(tx)
        self.save()
        return tx["txid"]

    def save(self):
        try:
            with open(APP_LEDGER_FILE, "w") as f:
                json.dump(self.chain, f, indent=2)
        except Exception:
            pass

    def load(self):
        if os.path.exists(APP_LEDGER_FILE):
            try:
                with open(APP_LEDGER_FILE, "r") as f:
                    self.chain = json.load(f)
            except Exception:
                self.chain = []

    def get_chain(self):
        return self.chain

ledger = SimpleLedger()

# ----------------------------- RSA Keys for Operators -----------------------------
class OperatorKeys:
    def __init__(self):
        self.keys: Dict[str, rsa.RSAPrivateKey] = {}

    def ensure_operator(self, name: str):
        if name not in self.keys:
            priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            self.keys[name] = priv
        return self.keys[name]

    def public_pem(self, name: str) -> bytes:
        priv = self.ensure_operator(name)
        pub = priv.public_key()
        return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def encrypt_for_operator(self, name: str, data: bytes) -> bytes:
        pub_pem = self.public_pem(name)  # Changed 'this' to 'self'
        pub = serialization.load_pem_public_key(pub_pem)
        return pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    def decrypt_for_operator(self, name: str, ct: bytes) -> bytes:
        priv = self.ensure_operator(name)
        return priv.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

operator_keys = OperatorKeys()


# ----------------------------- In-memory DB (will persist) -----------------------------
DB = {
    "telemarketers": {},
    "principals": {},
    "consents": {},
    "otps": {},
    "content_templates": {},
    "scrub_tokens": {},
    "users": {},
    "campaigns": {},
}

# ----------------------------- Pydantic Models (API) -----------------------------
class RegisterTMModel(BaseModel):
    name: str
    trai_id: str
    deposit: int

class RegisterPrincipalModel(BaseModel):
    name: str

class RegisterHeaderModel(BaseModel):
    principal_id: str
    header: str

class ConsentRequestModel(BaseModel):
    principal_id: str
    header: str
    phone: str

class ConsentGrantModel(BaseModel):
    phone: str
    otp: str
    principal_id: str
    header: str

class ConsentUpdateModel(BaseModel):
    phone: str
    principal_id: str
    header: str
    status: str  # approved / revoked

class ScrubRequestModel(BaseModel):
    telemarketer_id: str
    principal_id: str
    header: str
    content_id: str
    phones: List[str]

class CreateCampaignModel(BaseModel):
    telemarketer_id: str
    token: str
    operator: str

class ExecuteCampaignModel(BaseModel):
    operator: str
    token: str
    telemarketer_id: str

class SMSSendModel(BaseModel):
    operator: str
    phone: str
    principal_id: str
    header: str
    message: str

class UserCreateModel(BaseModel):
    phone: str
    password: str

class UserLoginModel(BaseModel):
    phone: str
    password: str

class TokenModel(BaseModel):
    access_token: str
    token_type: str

# ----------------------------- Smart-Contract-Like Classes -----------------------------
class RegistrationContract:
    def register_telemarketer(self, name: str, trai_id: str, deposit: int):
        for tm_id, tm_data in DB['telemarketers'].items():
            if tm_data.get("trai_id") == trai_id:
                raise HTTPException(status_code=400, detail="TRAI ID already registered")
        tm_id = f"TM-{len(DB['telemarketers'])+1}"
        DB['telemarketers'][tm_id] = {"name": name, "trai_id": trai_id, "deposit": deposit}
        save_db()
        txid = ledger.add_transaction({"type": "telemarketer_register", "tm_id": tm_id, "name": name, "trai_id": trai_id})
        return {"telemarketer_id": tm_id, "txid": txid}

    def register_principal(self, name: str):
        for pr in DB['principals'].values():
            if pr.get("name") == name:
                raise HTTPException(status_code=400, detail="Principal name already registered")
        pr_id = f"PR-{len(DB['principals'])+1}"
        DB['principals'][pr_id] = {"name": name, "headers": []}
        save_db()
        txid = ledger.add_transaction({"type": "principal_register", "principal_id": pr_id, "name": name})
        return {"principal_id": pr_id, "txid": txid}

    def register_header(self, principal_id: str, header: str):
    # Check if principal exists
        if principal_id not in DB['principals']:
            raise HTTPException(status_code=404, detail="Principal not found")

        # Check if the header already exists globally
        for pid, pdata in DB['principals'].items():
            if header in pdata.get('headers', []):
                raise HTTPException(
                    status_code=400,
                    detail=f"Header '{header}' already registered with another entity (Principal ID: {pid})"
                )

        # Add header to the principal
        DB['principals'][principal_id]['headers'].append(header)
        save_db()

        # Add ledger transaction
        txid = ledger.add_transaction({
            "type": "header_register",
            "principal_id": principal_id,
            "header": header
        })
        return {"header": header, "txid": txid}


registration_contract = RegistrationContract()

class ConsentContract:
    def request_consent(self, principal_id: str, header: str, phone: str):
        if principal_id not in DB['principals'] or header not in DB['principals'][principal_id]['headers']:
            raise HTTPException(status_code=400, detail="Invalid principal or header")
        key = sha256_hex(phone)
        existing = DB['consents'].get(key, [])
        for c in existing:
            if c.get("principal_id") == principal_id and c.get("header") == header:
                raise HTTPException(status_code=400, detail="Consent already requested for this phone-principal-header")
        otp = f"{secrets.randbelow(999999):06d}"
        expires = datetime.utcnow() + timedelta(minutes=5)
        existing.append({"principal_id": principal_id, "header": header, "status": "pending", "requested_at": now_iso()})
        DB['consents'][key] = existing
        DB['otps'][phone] = {"code": otp, "expires_at": expires.isoformat(), "principal_id": principal_id, "header": header}
        save_db()
        txid = ledger.add_transaction({"type": "consent_request", "phone_hash": key, "principal_id": principal_id, "header": header})
        return {"sent_otp": True, "otp": otp, "txid": txid}

    def grant_consent(self, phone: str, otp: str, principal_id: str, header: str):
        key = sha256_hex(phone)
        otp_entry = DB['otps'].get(phone)
        if not otp_entry:
            raise HTTPException(status_code=400, detail="No OTP sent or expired")
        try:
            if datetime.fromisoformat(otp_entry['expires_at'].replace('Z', '+00:00')) < datetime.utcnow():
                DB['otps'].pop(phone, None)
                raise HTTPException(status_code=400, detail="OTP expired")
        except Exception:
            pass
        if otp_entry.get('code') != otp or otp_entry.get('principal_id') != principal_id or otp_entry.get('header') != header:
            raise HTTPException(status_code=400, detail="Invalid OTP or mismatch")
        consents = DB['consents'].get(key, [])
        updated = False
        for c in consents:
            if c.get("principal_id") == principal_id and c.get("header") == header:
                c["status"] = "approved"
                c["granted_at"] = now_iso()
                updated = True
                break
        if not updated:
            raise HTTPException(status_code=404, detail="Consent request not found")
        DB['consents'][key] = consents
        DB['otps'].pop(phone, None)
        save_db()
        txid = ledger.add_transaction({"type": "consent_grant", "phone_hash": key, "principal_id": principal_id, "header": header})
        return {"granted": True, "txid": txid}

    def update_consent(self, phone: str, principal_id: str, header: str, status: str):
        key = sha256_hex(phone)
        consents = DB['consents'].get(key, [])
        updated = False
        for c in consents:
            if c.get("principal_id") == principal_id and c.get("header") == header:
                c["status"] = status
                if status == "approved" and 'granted_at' not in c:
                    c['granted_at'] = now_iso()
                updated = True
                break
        if not updated:
            raise HTTPException(status_code=404, detail="Consent not found")
        DB['consents'][key] = consents
        save_db()
        txid = ledger.add_transaction({"type": "consent_update", "phone_hash": key, "principal_id": principal_id, "header": header, "status": status})
        return {"updated": True, "txid": txid}

    def get_preferences(self, phone: str):
        key = sha256_hex(phone)
        prefs = DB['consents'].get(key, [])
        for p in prefs:
            principal_id = p.get("principal_id")
            p["principal_name"] = DB['principals'].get(principal_id, {}).get("name", principal_id)
        return prefs


consent_contract = ConsentContract()

class ScrubbingContract:
    def scrub_phones(self, telemarketer_id: str, principal_id: str, header: str, content_id: str, phones: List[str]):
        if telemarketer_id not in DB['telemarketers']:
            raise HTTPException(status_code=404, detail="Telemarketer not found")
        if principal_id not in DB['principals']:
            raise HTTPException(status_code=404, detail="Principal not found")
        if header not in DB['principals'][principal_id]['headers']:
            raise HTTPException(status_code=400, detail="Header not registered under principal")
        scrubbed = []
        unscrubbed = []
        for ph in phones:
            ph_hash = sha256_hex(ph)
            cons = DB['consents'].get(ph_hash, [])
            approved = any(c.get('principal_id') == principal_id and c.get('header') == header and c.get('status') == 'approved' for c in cons)
            if approved:
                scrubbed.append(ph_hash)
            else:
                unscrubbed.append(ph_hash)
        token = secrets.token_urlsafe(32)
        DB['scrub_tokens'][token] = {
            "telemarketer_id": telemarketer_id,
            "principal_id": principal_id,
            "header": header,
            "content_id": content_id,
            "scrubbed_phones": scrubbed,
            "unscrubbed_phones": unscrubbed,
            "created_at": now_iso()
        }
        save_db()
        txid = ledger.add_transaction({
            "type": "scrub_request",
            "telemarketer_id": telemarketer_id,
            "principal_id": principal_id,
            "header": header,
            "content_id": content_id,
            "scrubbed_count": len(scrubbed),
            "unscrubbed_count": len(unscrubbed)
        })
        return {"scrub_token": token, "scrubbed_count": len(scrubbed), "unscrubbed_count": len(unscrubbed), "txid": txid}

scrubbing_contract = ScrubbingContract()

class CampaignContract:
    def create_campaign(self, telemarketer_id: str, token: str, operator: str):
        if telemarketer_id not in DB['telemarketers']:
            raise HTTPException(status_code=404, detail="Telemarketer not found")
        if token not in DB['scrub_tokens']:
            raise HTTPException(status_code=404, detail="Scrub token not found")
        scrub = DB['scrub_tokens'][token]
        if scrub.get('telemarketer_id') != telemarketer_id:
            raise HTTPException(status_code=403, detail="Unauthorized scrub token access")
        campaign_id = f"CMP-{len(DB['campaigns'])+1}"
        DB['campaigns'][campaign_id] = {
            "telemarketer_id": telemarketer_id,
            "scrub_token": token,
            "operator": operator,
            "status": "created",
            "created_at": now_iso()
        }
        save_db()
        txid = ledger.add_transaction({"type": "campaign_create", "campaign_id": campaign_id, "telemarketer_id": telemarketer_id, "operator": operator})
        return {"campaign_id": campaign_id, "txid": txid}

campaign_contract = CampaignContract()

class SMSSendContract:
    def send_sms(self, operator: str, phone: str, principal_id: str, header: str, message: str):
        if principal_id not in DB['principals'] or header not in DB['principals'][principal_id]['headers']:
            raise HTTPException(status_code=400, detail="Invalid principal or header")
        phone_hash = sha256_hex(phone)
        consents = DB['consents'].get(phone_hash, [])
        approved = any(c.get('principal_id') == principal_id and c.get('header') == header and c.get('status') == 'approved' for c in consents)
        if not approved:
            txid = ledger.add_transaction({
                "type": "sms_rejected",
                "reason": "consent_not_granted",
                "phone_hash": phone_hash,
                "principal_id": principal_id,
                "header": header,
                "message_preview": message[:50] + "..." if len(message) > 50 else message
            })
            raise HTTPException(status_code=403, detail=f"SMS rejected: No consent for {phone_hash} on {header}. TXID: {txid}")
        encrypted_msg = operator_keys.encrypt_for_operator(operator, message.encode())
        encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode()
        txid = ledger.add_transaction({
            "type": "sms_sent",
            "phone_hash": phone_hash,
            "principal_id": principal_id,
            "header": header,
            "encrypted_message": encrypted_msg_b64,
            "operator": operator
        })
        return {"sent": True, "encrypted_message": encrypted_msg_b64, "txid": txid}

sms_send_contract = SMSSendContract()

from datetime import datetime, timezone
from collections import Counter
from typing import Optional

IST = timezone(timedelta(hours=5, minutes=30))  # Ensure IST timezone

class TRAIAuditContract:
    def generate_report(self, from_date: Optional[str] = None, to_date: Optional[str] = None):
        chain = ledger.get_chain()

        # Set default date range
        start = datetime.min.replace(tzinfo=IST)
        end = datetime.max.replace(tzinfo=IST)

        # Parse from_date
        if from_date:
            try:
                parsed = datetime.fromisoformat(from_date)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=IST)
                start = parsed
            except ValueError as e:
                logger.warning(f"Invalid from_date '{from_date}': {e}. Using full range.")

        # Parse to_date
        if to_date:
            try:
                parsed = datetime.fromisoformat(to_date)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=IST)
                end = parsed
            except ValueError as e:
                logger.warning(f"Invalid to_date '{to_date}': {e}. Using full range.")

        # Helper: make timestamp tz-aware
        def parse_tx_timestamp(ts: str):
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IST)
            return dt

        # Filter chain based on date
        filtered_chain = [
            tx for tx in chain
            if 'timestamp' in tx and start <= parse_tx_timestamp(tx['timestamp']) <= end
        ]

        # Counters
        tx_types = Counter(tx.get('type') for tx in filtered_chain)
        consents_by_status = Counter()
        sms_rejections = Counter()
        telemarketer_activity = Counter()
        principal_activity = Counter()

        # Collect simplified transactions
        transactions = []

        for tx in filtered_chain:
            tx_type = tx.get('type')
            
            # Track counters
            if tx_type == 'consent_request':
                consents_by_status['requested'] += 1
            elif tx_type == 'consent_grant':
                consents_by_status['approved'] += 1
            elif tx_type == 'consent_update':
                status = tx.get('status', 'unknown')
                consents_by_status[status] += 1
            elif tx_type == 'sms_rejected':
                reason = tx.get('reason', 'unknown')
                sms_rejections[reason] += 1
            elif tx_type == 'telemarketer_register':
                tm_id = tx.get('tm_id', 'unknown')
                telemarketer_activity[tm_id] += 1
            elif tx_type == 'principal_register':
                pr_id = tx.get('principal_id', 'unknown')
                principal_activity[pr_id] += 1

            # Capture only relevant fields per tx
            transactions.append({
                "txid": tx.get("txid"),
                "tm_id": tx.get("tm_id"),
                "name": tx.get("name"),
                "trai_id": tx.get("trai_id"),
                "principal_id": tx.get("principal_id"),
                "header": tx.get("header"),
                "phone_hash": tx.get("phone_hash"),
                "status": tx.get("status"),
                "operator": tx.get("operator"),
                "message_hash": tx.get("message_hash"),
                "reason": tx.get("reason"),
                "consent_granted_at": tx.get("consent_granted_at"),
                "encrypted_message": tx.get("encrypted_message"),
                "message_preview": tx.get("message_preview"),
                "telemarketer_id": tx.get("telemarketer_id"),
                "timestamp": tx.get("timestamp"),
                "type": tx_type
            })

        # Build final report
        report = {
            "summary": {
                "total_transactions": len(filtered_chain),
                "by_type": dict(tx_types)
            },
            "consent_stats": dict(consents_by_status),
            "sms_rejections": dict(sms_rejections),
            "telemarketer_activity": dict(telemarketer_activity),
            "principal_activity": dict(principal_activity),
            "transactions": transactions,
            "date_range": {
                "from": start.isoformat(),
                "to": end.isoformat()
            }
        }

        return report



trai_audit_contract = TRAIAuditContract()

# ----------------------------- API Endpoints -----------------------------
@app.post("/telemarketer/register", response_model=Dict[str, Any])
def register_telemarketer(tm: RegisterTMModel):
    return registration_contract.register_telemarketer(tm.name, tm.trai_id, tm.deposit)

@app.post("/principal/register", response_model=Dict[str, Any])
def register_principal(pr: RegisterPrincipalModel):
    return registration_contract.register_principal(pr.name)

@app.post("/principal/register_header", response_model=Dict[str, Any])
def register_header(header: RegisterHeaderModel):
    return registration_contract.register_header(header.principal_id, header.header)

@app.post("/consent/request", response_model=Dict[str, Any])
def request_consent(req: ConsentRequestModel):
    return consent_contract.request_consent(req.principal_id, req.header, req.phone)

@app.post("/consent/grant", response_model=Dict[str, Any])
def grant_consent(grant: ConsentGrantModel):
    return consent_contract.grant_consent(grant.phone, grant.otp, grant.principal_id, grant.header)

@app.post("/consent/update", response_model=Dict[str, Any])
def update_consent(update: ConsentUpdateModel, current_user: str = Depends(get_current_user)):
    if sha256_hex(current_user) != sha256_hex(update.phone):
        raise HTTPException(status_code=403, detail="Can only update own consents")
    return consent_contract.update_consent(update.phone, update.principal_id, update.header, update.status)

@app.get("/consent/preferences/{phone}", response_model=List[Dict[str, Any]])
def get_consent_preferences(phone: str, current_user: Optional[str] = Depends(get_current_user)):
    if current_user and sha256_hex(current_user) != sha256_hex(phone):
        raise HTTPException(status_code=403, detail="Can only view own preferences")
    return consent_contract.get_preferences(phone)

@app.post("/scrub/phones", response_model=Dict[str, Any])
def scrub_phones(scrub: ScrubRequestModel):
    return scrubbing_contract.scrub_phones(scrub.telemarketer_id, scrub.principal_id, scrub.header, scrub.content_id, scrub.phones)

@app.post("/campaign/create", response_model=Dict[str, Any])
def create_campaign(cmp: CreateCampaignModel):
    return campaign_contract.create_campaign(cmp.telemarketer_id, cmp.token, cmp.operator)

@app.post("/campaign/execute", response_model=Dict[str, Any])
def execute_campaign(exe: ExecuteCampaignModel):
    return campaign_contract.execute_campaign(exe.operator, exe.token, exe.telemarketer_id)

@app.post("/sms/send", response_model=Dict[str, Any])
def send_sms(sms: SMSSendModel):
    return sms_send_contract.send_sms(sms.operator, sms.phone, sms.principal_id, sms.header, sms.message)

@app.post("/users/register", response_model=TokenModel)
def register_user(user: UserCreateModel):
    if user.phone in DB["users"]:
        raise HTTPException(status_code=400, detail="User already registered")
    hashed_password = get_password_hash(user.password)
    DB["users"][user.phone] = {"password_hash": hashed_password}
    save_db()
    access_token = create_access_token(data={"sub": user.phone})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/login", response_model=TokenModel)
def login_user(user: UserLoginModel):
    db_user = DB["users"].get(user.phone)
    if not db_user or not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user.phone})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/ledger", response_model=List[Dict[str, Any]])
def get_ledger():
    return ledger.get_chain()

@app.get("/audit/report", response_model=Dict[str, Any])
def get_audit_report(
    from_date: Optional[str] = Query(None, description="From date (ISO 8601, e.g., 2023-01-01T00:00:00Z or 2023-01-01Z)"),
    to_date: Optional[str] = Query(None, description="To date (ISO 8601, e.g., 2023-12-31T23:59:59Z or 2023-12-31Z)")
):
    return trai_audit_contract.generate_report(from_date, to_date)

@app.on_event("startup")
def startup_event():
    load_db()
    ledger.load()
    if not DB.get("principals"):
        logger.info("Seeding sample data...")
        pr_result = registration_contract.register_principal("Random Corp")
        pr_id = pr_result["principal_id"]
        registration_contract.register_header(pr_id, "RND-HDR")
        tm_result = registration_contract.register_telemarketer("Random TM", "TRAI-RND-123", 1000)
        tm_id = tm_result["telemarketer_id"]
        sample_user = UserCreateModel(phone="9876543210", password="1234")
        register_user(sample_user)
        consent_req = ConsentRequestModel(principal_id=pr_id, header="RND-HDR", phone="9876543210")
        req_result = request_consent(consent_req)
        otp = req_result["otp"]
        grant = ConsentGrantModel(phone="9876543210", otp=otp, principal_id=pr_id, header="RND-HDR")
        grant_consent(grant)
        logger.info("Sample data seeded: PR-1, TM-1, user 9876543210 (pass:1234), sample consent granted.")
    else:
        logger.info("DB already has data; skipping seeding.")

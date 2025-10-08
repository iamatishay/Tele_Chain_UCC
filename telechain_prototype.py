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
from datetime import datetime, timedelta
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
        print(f"⚠️ Failed to save DB: {e}")

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r") as f:
                data = json.load(f)
                # Merge keys to DB (do not replace the DB reference)
                for k, v in data.items():
                    DB[k] = v
                print("✅ Loaded DB from disk.")
        except Exception as e:
            print(f"⚠️ Failed to load DB: {e}")

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
        pub_pem = self.public_pem(name)
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
        # duplicate TRAI ID prevention
        for tm_id, tm_data in DB['telemarketers'].items():
            if tm_data.get("trai_id") == trai_id:
                raise HTTPException(status_code=400, detail="TRAI ID already registered")
        tm_id = f"TM-{len(DB['telemarketers'])+1}"
        DB['telemarketers'][tm_id] = {"name": name, "trai_id": trai_id, "deposit": deposit}
        save_db()
        txid = ledger.add_transaction({"type": "telemarketer_register", "tm_id": tm_id, "name": name, "trai_id": trai_id})
        return {"telemarketer_id": tm_id, "txid": txid}

    def register_principal(self, name: str):
        # duplicate principal name prevention
        for pr in DB['principals'].values():
            if pr.get("name") == name:
                raise HTTPException(status_code=400, detail="Principal name already registered")
        pr_id = f"PR-{len(DB['principals'])+1}"
        DB['principals'][pr_id] = {"name": name, "headers": []}
        save_db()
        txid = ledger.add_transaction({"type": "principal_register", "principal_id": pr_id, "name": name})
        return {"principal_id": pr_id, "txid": txid}

    def register_header(self, principal_id: str, header: str):
        if principal_id not in DB['principals']:
            raise HTTPException(status_code=404, detail="Principal not found")
        if header in DB['principals'][principal_id]['headers']:
            raise HTTPException(status_code=400, detail="Header already registered for this principal")
        DB['principals'][principal_id]['headers'].append(header)
        save_db()
        txid = ledger.add_transaction({"type": "header_register", "principal_id": principal_id, "header": header})
        return {"header": header, "txid": txid}

registration_contract = RegistrationContract()

class ConsentContract:
    def request_consent(self, principal_id: str, header: str, phone: str):
        if principal_id not in DB['principals'] or header not in DB['principals'][principal_id]['headers']:
            raise HTTPException(status_code=400, detail="Invalid principal or header")
        key = sha256_hex(phone)
        existing = DB['consents'].get(key, [])
        # prevent duplicate consent request for same phone-principal-header
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
        # expiry check
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
        return DB['consents'].get(key, [])

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

    def execute_campaign(self, operator: str, token: str, telemarketer_id: str):
        if token not in DB['scrub_tokens']:
            raise HTTPException(status_code=404, detail="Scrub token not found")
        scrub = DB['scrub_tokens'][token]
        if scrub.get('telemarketer_id') != telemarketer_id:
            raise HTTPException(status_code=403, detail="Unauthorized scrub token access")
        # find campaign
        campaign_id = None
        for cid, c in DB['campaigns'].items():
            if c.get('scrub_token') == token and c.get('operator') == operator:
                campaign_id = cid
                campaign = c
                break
        if not campaign_id:
            raise HTTPException(status_code=404, detail="Campaign not found for this token/operator")
        if campaign.get('status') != 'created':
            raise HTTPException(status_code=400, detail="Campaign already executed or invalid status")
        sent_count = len(scrub.get('scrubbed_phones', []))
        campaign['status'] = 'executed'
        campaign['executed_at'] = now_iso()
        campaign['sent_count'] = sent_count
        DB['campaigns'][campaign_id] = campaign
        save_db()
        txid = ledger.add_transaction({"type": "campaign_execute", "campaign_id": campaign_id, "operator": operator, "sent_count": sent_count})
        return {"executed": True, "sent_count": sent_count, "txid": txid}

campaign_contract = CampaignContract()

class SMSSendContract:
    def send_sms(self, operator: str, phone: str, principal_id: str, header: str, message: str):
        operator_keys.ensure_operator(operator)
        phone_hash = sha256_hex(phone)
        consents = DB.get('consents', {}).get(phone_hash, [])
        approved = next((c for c in consents if c.get('principal_id') == principal_id and c.get('header') == header and c.get('status') == 'approved'), None)
        if not approved:
            txid = ledger.add_transaction({"type": "sms_rejected", "operator": operator, "phone_hash": phone_hash, "principal_id": principal_id, "header": header, "reason": "consent_not_granted"})
            save_db()
            raise HTTPException(status_code=400, detail="Consent not granted")
        # Simulate send: log to ledger, encrypt message to operator
        encrypted_msg = operator_keys.encrypt_for_operator(operator, message.encode())
        msg_b64 = base64.b64encode(encrypted_msg).decode()
        txid = ledger.add_transaction({"type": "sms_sent", "operator": operator, "phone_hash": phone_hash, "principal_id": principal_id, "header": header, "message_hash": sha256_hex(message)})
        save_db()
        return {"sent": True, "txid": txid, "encrypted_message": msg_b64}

sms_send_contract = SMSSendContract()

from collections import Counter
from datetime import datetime
from typing import Optional

from datetime import datetime, timezone
from collections import Counter
from typing import Optional

class TRAIAuditContract:
    """Generates TRAI compliance reports from the ledger."""

    def generate_report(self, from_date: Optional[str] = None, to_date: Optional[str] = None):
        chain = ledger.get_chain()

        # -------------------- Date Filtering --------------------
        start = datetime.min.replace(tzinfo=timezone.utc)
        end = datetime.max.replace(tzinfo=timezone.utc)

        if from_date:
            start = datetime.fromisoformat(str(from_date).replace('Z', '+00:00'))
        if to_date:
            end = datetime.fromisoformat(str(to_date).replace('Z', '+00:00'))

        filtered_chain = []
        for tx in chain:
            ts = tx.get("timestamp")
            if not ts:
                continue  # skip if timestamp missing
            try:
                tx_time = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                if start <= tx_time <= end:
                    filtered_chain.append(tx)
            except Exception:
                continue

        # -------------------- Counters --------------------
        tx_types = Counter()
        consents_by_status = Counter()
        sms_rejected_reasons = Counter()
        telemarketer_activity = Counter()
        principal_activity = Counter()

        for tx in filtered_chain:
            ttype = tx.get("type", "unknown")
            tx_types[ttype] += 1

            # Consent stats
            if ttype == "consent_request":
                consents_by_status["requested"] += 1
            elif ttype in ("consent_grant", "consent_update"):
                status = tx.get("status", "approved" if ttype == "consent_grant" else "unknown")
                consents_by_status[status] += 1

            # SMS rejections
            if ttype == "sms_rejected":
                reason = tx.get("reason", "unknown")
                sms_rejected_reasons[reason] += 1

            # Telemarketer activity
            if ttype == "telemarketer_register":
                telemarketer_activity[tx.get("tm_id", "unknown")] += 1

            # Principal activity
            if ttype == "principal_register":
                principal_activity[tx.get("principal_id", "unknown")] += 1

        # -------------------- Report --------------------
        report = {
            "summary": {
                "total_transactions": len(filtered_chain),
                "by_type": dict(tx_types),
            },
            "consent_stats": dict(consents_by_status),
            "sms_rejections": dict(sms_rejected_reasons),
            "telemarketer_activity": dict(telemarketer_activity),
            "principal_activity": dict(principal_activity),
        }

        return report

# Instantiate for FastAPI usage
trai_audit_contract = TRAIAuditContract()

# ----------------------------- FastAPI Endpoints -----------------------------
# Auth endpoints
@app.post("/users/register", response_model=TokenModel)
def register_user(u: UserCreateModel):
    if u.phone in DB['users']:
        raise HTTPException(status_code=400, detail="Phone already registered")
    DB['users'][u.phone] = {"password_hash": get_password_hash(u.password)}
    save_db()
    access_token = create_access_token({"sub": u.phone}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    txid = ledger.add_transaction({"type": "user_register", "phone_hash": sha256_hex(u.phone)})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/login", response_model=TokenModel)
def login_user(u: UserLoginModel):
    rec = DB['users'].get(u.phone)
    if not rec or not verify_password(u.password, rec.get('password_hash', '')):
        raise HTTPException(status_code=400, detail="Incorrect phone or password")
    access_token = create_access_token({"sub": u.phone}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}

# Registration endpoints
@app.post("/telemarketer/register")
def api_register_tm(r: RegisterTMModel):
    res = registration_contract.register_telemarketer(r.name, r.trai_id, r.deposit)
    return res

@app.post("/principal/register")
def api_register_principal(r: RegisterPrincipalModel):
    res = registration_contract.register_principal(r.name)
    return res

@app.post("/principal/register_header")
def api_register_header(r: RegisterHeaderModel):
    res = registration_contract.register_header(r.principal_id, r.header)
    return res

# Consent endpoints
@app.post("/consent/request")
def api_consent_request(r: ConsentRequestModel):
    return consent_contract.request_consent(r.principal_id, r.header, r.phone)

@app.post("/consent/grant")
def api_consent_grant(r: ConsentGrantModel):
    return consent_contract.grant_consent(r.phone, r.otp, r.principal_id, r.header)

@app.post("/consent/update")
def api_consent_update(r: ConsentUpdateModel, current_user: str = Depends(get_current_user)):
    # Only allow updating own phone consents
    if sha256_hex(r.phone) != sha256_hex(current_user):
        raise HTTPException(status_code=403, detail="Cannot update other user's consents")
    return consent_contract.update_consent(r.phone, r.principal_id, r.header, r.status)

@app.get("/consent/preferences/{phone}")
def api_get_preferences(phone: str, current_user: str = Depends(get_current_user)):
    # Only allow viewing own preferences
    if sha256_hex(phone) != sha256_hex(current_user):
        raise HTTPException(status_code=403, detail="Cannot view other user's preferences")
    return consent_contract.get_preferences(phone)

# Scrub & Campaign endpoints
@app.post("/scrub")
def api_scrub(r: ScrubRequestModel):
    return scrubbing_contract.scrub_phones(r.telemarketer_id, r.principal_id, r.header, r.content_id, r.phones)

@app.post("/campaign/create")
def api_campaign_create(r: CreateCampaignModel):
    return campaign_contract.create_campaign(r.telemarketer_id, r.token, r.operator)

@app.post("/campaign/execute")
def api_campaign_execute(r: ExecuteCampaignModel):
    return campaign_contract.execute_campaign(r.operator, r.token, r.telemarketer_id)

# SMS send endpoint
@app.post("/sms/send")
def api_send_sms(r: SMSSendModel):
    return sms_send_contract.send_sms(r.operator, r.phone, r.principal_id, r.header, r.message)

# Ledger & audit
@app.get("/ledger")
def api_get_ledger():
    return ledger.get_chain()

@app.get("/audit/report")
def api_audit_report(from_date: Optional[str] = Query(None), to_date: Optional[str] = Query(None)):
    """
    Returns a TRAI compliance report.
    Optional ISO date filters:
        - from_date: "YYYY-MM-DDTHH:MM:SSZ"
        - to_date: "YYYY-MM-DDTHH:MM:SSZ"
    """
    return trai_audit_contract.generate_report(from_date=from_date, to_date=to_date)

# ----------------------------- Startup -----------------------------
@app.on_event("startup")
def startup_event():
    # load persisted DB first
    load_db()
    # ensure operators
    operator_keys.ensure_operator("OperatorA")
    operator_keys.ensure_operator("OperatorB")
    # seed sample principal/telemarketer/user if not present
    if "PR-1" not in DB.get("principals", {}):
        DB["principals"]["PR-1"] = {"name": "SeedBiz", "headers": ["HDR-1"]}
    if "TM-1" not in DB.get("telemarketers", {}):
        DB["telemarketers"]["TM-1"] = {"name": "SeedTM", "trai_id": "TR-0001", "deposit": 1000}
    if "9876543210" not in DB.get("users", {}):
        DB["users"]["9876543210"] = {"password_hash": get_password_hash("1234")}
    save_db()
    ledger.add_transaction({"type": "seed", "msg": "startup seeded defaults if missing"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

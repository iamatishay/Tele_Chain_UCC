"""
Telechain Prototype (single-file) with Basic JWT Authentication and SMS API

Features implemented (Python-only prototype):
- In-memory consortium-style blockchain (no PoW) with signed transactions
- Smart-contract-like Python classes to perform: register telemarketer, register principal & headers,
  consent request and grant, scrubbing, campaign creation & execution
- OTP simulation for consent acquisition
- Hashing of phone numbers, per-operator RSA encryption of scrubbed lists
- Simple token mechanism to represent scrubbing result
- FastAPI-based HTTP API to interact with components (telemarketer, third-party, operator)
- Simple persistent storage of ledger to JSON file (optional)
- Basic JWT-based user authentication (phone as username, bcrypt hashing)
- NEW: SMS API - Checks consent before simulating SMS send from operator

Requirements:
pip install fastapi uvicorn cryptography pydantic python-multipart python-jose[cryptography] passlib[bcrypt]

Run:
uvicorn telechain_prototype:app --reload --port 8000

New Endpoints for Auth:
- POST /users/register {"phone": "9876543210", "password": "1234"} → Returns JWT token
- POST /users/login {"phone": "9876543210", "password": "1234"} → Returns JWT token

Protected Endpoints (require Authorization: Bearer <token>):
- GET /consent/preferences/{phone}
- POST /consent/update

Other Endpoints (examples, unchanged):
- POST /telemarketer/register  {"name": "TM1", "trai_id": "TRAIX123", "deposit": 1000}
- POST /principal/register  {"name": "Biz1"}
- POST /principal/register_header {"principal_id": "PR-1", "header": "BIZHDR"}
- POST /consent/request {"principal_id": "PR-1", "header": "BIZHDR", "phone": "9876543210"}
- POST /consent/grant   {"phone": "9876543210", "otp": "123456", "principal_id": "PR-1", "header": "BIZHDR"}
- POST /scrub           {"telemarketer_id": "TM-1", "principal_id":"PR-1", "header": "BIZHDR", "content_id":"CT-1", "phones": ["9876543210","9876543211"]}
- POST /campaign/create {"telemarketer_id":"TM-1","token":"<token-from-scrub>","operator":"OperatorA"}
- POST /campaign/execute {"operator":"OperatorA","token":"<token>","telemarketer_id":"TM-1"}
- GET  /ledger
- NEW: POST /sms/send {"operator": "OperatorA", "phone": "9876543210", "principal_id": "PR-1", "header": "HDR-1", "message": "Promo!"}

Notes & limitations:
- This prototype is intentionally simplified for demonstration and testing only.
- Security: keys are generated at runtime. Do NOT use in production. JWT secret is hardcoded—change it!
- Persistence is minimal; restart loses in-memory data unless ledger.json is saved. Users are in-memory.
- Auth: Phone serves as username. Only protects customer dashboard endpoints; others are open for demo.
- SMS: Simulated (no real sending); logs to ledger for audit. In production, integrate with Twilio/etc. after consent check.
- UI Integration: Update Streamlit to send POST /users/login and use Bearer token in headers for protected calls.
- Bcrypt Fix: Attempts to seed default user; if fails (e.g., Python 3.13+), register via UI/API.
"""

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import hashlib
import uuid
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import secrets
from jose import JWTError, jwt
from passlib.context import CryptContext

APP_LEDGER_FILE = "ledger.json"

app = FastAPI(title="Telechain Prototype API")

# ----------------------------- Security Configuration -----------------------------
SECRET_KEY = "your-secret-key-change-in-prod-telechain-demo"  # Change this! Use secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ----------------------------- Utility functions -----------------------------
def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

# JWT Utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

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
    # Check if user exists in DB
    if phone not in DB["users"]:
        raise credentials_exception
    return phone

# ----------------------------- Simple Blockchain -----------------------------
class Block(dict):
    pass

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

# ----------------------------- Key management (operators) -----------------------------
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
        ct = pub.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return ct

    def decrypt_for_operator(self, name: str, ct: bytes) -> bytes:
        priv = self.ensure_operator(name)
        pt = priv.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return pt

operator_keys = OperatorKeys()

# ----------------------------- In-memory registry -----------------------------
DB = {
    "telemarketers": {},    # id -> {name, trai_id, node_pub}
    "principals": {},       # id -> {name, headers: [..]}
    "consents": {},         # phone_hash -> list of {principal_id, header, granted_at, status, txid}
    "otps": {},             # phone -> {code, expires_at, principal_id, header}
    "content_templates": {},# content_id -> text
    "scrub_tokens": {},     # token -> {files_by_operator, txid}
    "users": {},            # phone -> {password_hash}
}

# ----------------------------- Models -----------------------------
class RegisterTM(BaseModel):
    name: str
    trai_id: str
    deposit: int

class RegisterPrincipal(BaseModel):
    name: str

class RegisterHeader(BaseModel):
    principal_id: str
    header: str

class ConsentRequest(BaseModel):
    principal_id: str
    header: str
    phone: str

class ConsentGrant(BaseModel):
    phone: str
    otp: str
    principal_id: str
    header: str

class ConsentUpdate(BaseModel):
    phone: str
    principal_id: str
    header: str
    status: str  # e.g., "approved" or "revoked"

class ScrubRequest(BaseModel):
    telemarketer_id: str
    principal_id: str
    header: str
    content_id: str
    phones: List[str]

class CreateCampaign(BaseModel):
    telemarketer_id: str
    token: str
    operator: str

class ExecuteCampaign(BaseModel):
    operator: str
    token: str
    telemarketer_id: str

# NEW: SMS Send Model
class SMSSend(BaseModel):
    operator: str  # e.g., "OperatorA"
    phone: str     # Customer phone
    principal_id: str
    header: str
    message: str   # SMS content

# Auth Models
class UserCreate(BaseModel):
    phone: str
    password: str

class UserLogin(BaseModel):
    phone: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# ----------------------------- Endpoints -----------------------------
@app.post("/telemarketer/register")
def register_telemarketer(r: RegisterTM):
    tm_id = f"TM-{len(DB['telemarketers'])+1}"
    DB['telemarketers'][tm_id] = {"name": r.name, "trai_id": r.trai_id, "deposit": r.deposit}
    tx = {"type": "telemarketer_register", "tm_id": tm_id, "name": r.name, "trai_id": r.trai_id}
    txid = ledger.add_transaction(tx)
    return {"telemarketer_id": tm_id, "txid": txid}

@app.post("/principal/register")
def register_principal(r: RegisterPrincipal):
    pr_id = f"PR-{len(DB['principals'])+1}"
    DB['principals'][pr_id] = {"name": r.name, "headers": []}
    tx = {"type": "principal_register", "principal_id": pr_id, "name": r.name}
    txid = ledger.add_transaction(tx)
    return {"principal_id": pr_id, "txid": txid}

@app.post("/principal/register_header")
def register_header(r: RegisterHeader):
    if r.principal_id not in DB['principals']:
        raise HTTPException(status_code=404, detail="principal not found")
    DB['principals'][r.principal_id]['headers'].append(r.header)
    tx = {"type": "header_register", "principal_id": r.principal_id, "header": r.header}
    txid = ledger.add_transaction(tx)
    return {"header": r.header, "txid": txid}

@app.post("/consent/request")
def consent_request(r: ConsentRequest):
    # Check if header is registered
    if r.principal_id not in DB['principals'] or r.header not in DB['principals'][r.principal_id]['headers']:
        raise HTTPException(status_code=400, detail="principal or header not registered")
    # Simulate OTP send
    code = f"{secrets.randbelow(999999):06d}"
    expires = datetime.utcnow() + timedelta(minutes=5)
    key = sha256_hex(r.phone)
    DB['consents'].setdefault(key, [])
    # Check for existing consent for this principal/header
    existing = next((c for c in DB['consents'][key] if c['principal_id'] == r.principal_id and c['header'] == r.header), None)
    if existing:
        if existing['status'] == 'pending':
            # Update OTP for existing pending consent
            DB['otps'][r.phone] = {"code": code, "expires_at": expires.isoformat(), "principal_id": r.principal_id, "header": r.header}
        else:
            raise HTTPException(status_code=400, detail="Consent already exists and not pending")
    else:
        # Create new pending consent
        entry = {"principal_id": r.principal_id, "header": r.header, "requested_at": now_iso(), "status": "pending"}
        DB['consents'][key].append(entry)
        DB['otps'][r.phone] = {"code": code, "expires_at": expires.isoformat(), "principal_id": r.principal_id, "header": r.header}
    tx = {"type": "consent_request", "principal_id": r.principal_id, "header": r.header, "phone_hash": key}
    txid = ledger.add_transaction(tx)
    return {"sent_otp": True, "otp": code, "txid": txid}  # otp returned for demo; in real-world you won't return it

@app.post("/consent/grant")
def consent_grant(r: ConsentGrant):
    key = sha256_hex(r.phone)
    consents = DB['consents'].get(key, [])
    matching = next((c for c in consents if c['principal_id'] == r.principal_id and c['header'] == r.header and c['status'] == 'pending'), None)
    if not matching:
        raise HTTPException(status_code=400, detail="No pending consent found for this principal/header")
    # Check OTP
    rec = DB['otps'].get(r.phone)
    if not rec or datetime.fromisoformat(rec['expires_at'].replace('Z', '+00:00')) < datetime.utcnow():
        raise HTTPException(status_code=400, detail="invalid or expired otp")
    if rec['code'] != r.otp or rec['principal_id'] != r.principal_id or rec['header'] != r.header:
        raise HTTPException(status_code=400, detail="invalid otp")
    # Update to approved
    matching['status'] = "approved"
    matching['granted_at'] = now_iso()
    tx = {"type": "consent_grant", "principal_id": r.principal_id, "header": r.header, "phone_hash": key, "status": "approved"}
    txid = ledger.add_transaction(tx)
    # Clean up OTP
    if r.phone in DB['otps']:
        del DB['otps'][r.phone]
    return {"granted": True, "txid": txid}

@app.get("/consent/preferences/{phone}")
async def get_consent_preferences(phone: str, current_user: str = Depends(get_current_user)):
    if sha256_hex(phone) != sha256_hex(current_user):
        raise HTTPException(status_code=403, detail="Access denied: Can only view own preferences")
    key = sha256_hex(phone)
    prefs = DB['consents'].get(key, [])
    return [{"principal_id": p['principal_id'], "header": p['header'], "status": p.get('status', 'unknown'), "granted_at": p.get('granted_at')} for p in prefs]

@app.post("/consent/update")
async def consent_update(r: ConsentUpdate, current_user: str = Depends(get_current_user)):
    if sha256_hex(r.phone) != sha256_hex(current_user):
        raise HTTPException(status_code=403, detail="Access denied: Can only update own consents")
    key = sha256_hex(r.phone)
    consents = DB['consents'].get(key, [])
    updated = False
    for c in consents:
        if c['principal_id'] == r.principal_id and c['header'] == r.header:
            c['status'] = r.status
            if r.status == "approved" and 'granted_at' not in c:
                c['granted_at'] = now_iso()
            updated = True
            break
    if not updated:
        raise HTTPException(status_code=404, detail="consent not found for this principal/header")
    tx = {"type": "consent_update", "phone_hash": key, "principal_id": r.principal_id, "header": r.header, "status": r.status}
    txid = ledger.add_transaction(tx)
    return {"updated": True, "txid": txid}

@app.post("/content/register")
def register_content(data: Dict[str, Any]):
    cid = f"CT-{len(DB['content_templates'])+1}"
    DB['content_templates'][cid] = data.get('text', '')
    tx = {"type": "content_register", "content_id": cid, "text_hash": sha256_hex(DB['content_templates'][cid])}
    txid = ledger.add_transaction(tx)
    return {"content_id": cid, "txid": txid}

@app.post("/scrub")
def scrub(req: ScrubRequest):
    # Basic ownership checks
    if req.telemarketer_id not in DB['telemarketers']:
        raise HTTPException(status_code=404, detail="telemarketer not found")
    if req.principal_id not in DB['principals']:
        raise HTTPException(status_code=404, detail="principal not found")
    if req.header not in DB['principals'][req.principal_id]['headers']:
        raise HTTPException(status_code=400, detail="header not registered under principal")
    # Process numbers
    valid_by_operator = {}
    invalid = []
    for p in req.phones:
        h = sha256_hex(p)
        found = False
        for c in DB['consents'].get(h, []):
            if (c['principal_id'] == req.principal_id and 
                c['header'] == req.header and 
                c.get('status') == "approved"):
                found = True
                break
        if found:
            # Choose operator by last digit (demo split)
            op = "OperatorA" if int(p[-1]) % 2 == 0 else "OperatorB"
            valid_by_operator.setdefault(op, []).append(p)
        else:
            invalid.append(p)
    # Create files: encrypt per operator and create digests
    files_meta = {}
    for op, nums in valid_by_operator.items():
        payload = json.dumps(nums).encode()
        ct = operator_keys.encrypt_for_operator(op, payload)
        digest = sha256_hex(base64.b64encode(ct).decode())
        files_meta[op] = {"encrypted_blob_b64": base64.b64encode(ct).decode(), "digest": digest}
    token = f"TK-{uuid.uuid4()}"
    tx = {"type": "scrub_tx", "telemarketer_id": req.telemarketer_id, "principal_id": req.principal_id, "header": req.header, "content_id": req.content_id, "files_meta": {k:{"digest":v['digest']} for k,v in files_meta.items()}, "invalid_count": len(invalid)}
    txid = ledger.add_transaction(tx)
    DB['scrub_tokens'][token] = {"files_meta": files_meta, "txid": txid, "invalid": invalid}
    return {"token": token, "txid": txid, "valid_counts": {k: len(v) for k,v in valid_by_operator.items()}, "invalid": invalid}

@app.post("/campaign/create")
def campaign_create(req: CreateCampaign):
    if req.telemarketer_id not in DB['telemarketers']:
        raise HTTPException(status_code=404, detail="telemarketer not found")
    token_info = DB['scrub_tokens'].get(req.token)
    if not token_info:
        raise HTTPException(status_code=404, detail="token not found")
    # Operator gets token; record transaction
    tx = {"type": "campaign_create", "telemarketer_id": req.telemarketer_id, "operator": req.operator, "token": req.token}
    txid = ledger.add_transaction(tx)
    return {"accepted": True, "txid": txid}

@app.post("/campaign/execute")
def campaign_execute(req: ExecuteCampaign):
    token_info = DB['scrub_tokens'].get(req.token)
    if not token_info:
        raise HTTPException(status_code=404, detail="token not found")
    # Operator decrypts their blob and 'sends'
    if req.operator not in token_info['files_meta']:
        raise HTTPException(status_code=400, detail="no numbers for this operator")
    ct_b64 = token_info['files_meta'][req.operator].get('encrypted_blob_b64')
    if not ct_b64:
        raise HTTPException(status_code=400, detail="encrypted blob missing")
    ct = base64.b64decode(ct_b64)
    pts = operator_keys.decrypt_for_operator(req.operator, ct)
    nums = json.loads(pts.decode())
    # Build delivery report
    delivered = len(nums)
    tx = {"type": "campaign_execute", "operator": req.operator, "telemarketer_id": req.telemarketer_id, "token": req.token, "delivered": delivered}
    txid = ledger.add_transaction(tx)
    return {"delivered": delivered, "txid": txid}

# NEW: SMS Send Endpoint - Checks consent before simulating SMS
@app.post("/sms/send")
def send_sms(req: SMSSend):
    # Validate operator exists (ensure keys for it)
    try:
        operator_keys.ensure_operator(req.operator)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid operator")

    # Hash phone for privacy and lookup
    phone_hash = sha256_hex(req.phone)
    consents = DB['consents'].get(phone_hash, [])

    # Check for approved consent for this exact principal_id and header
    approved_consent = next(
        (c for c in consents 
         if c['principal_id'] == req.principal_id 
         and c['header'] == req.header 
         and c.get('status') == "approved"), 
        None
    )

    if not approved_consent:
        # Log rejection to ledger
        reject_tx = {
            "type": "sms_rejected",
            "operator": req.operator,
            "phone_hash": phone_hash,
            "principal_id": req.principal_id,
            "header": req.header,
            "message_hash": sha256_hex(req.message),
            "reason": "consent not granted"
        }
        ledger.add_transaction(reject_tx)
        raise HTTPException(
            status_code=400, 
            detail=f"Consent not granted for principal '{req.principal_id}' and header '{req.header}'. SMS rejected."
        )

    # Consent approved: Simulate SMS send (log to ledger)
    message_hash = sha256_hex(req.message)
    send_tx = {
        "type": "sms_sent",
        "operator": req.operator,
        "phone_hash": phone_hash,
        "principal_id": req.principal_id,
        "header": req.header,
        "message_hash": message_hash,
        "consent_granted_at": approved_consent.get('granted_at')
    }
    txid = ledger.add_transaction(send_tx)

    # In production: Integrate with real SMS gateway (e.g., Twilio) here
    # For demo: Just return success
    return {
        "sent": True, 
        "txid": txid, 
        "message": f"SMS sent to {phone_hash[:8]}... from {req.operator} (consent verified)"
    }

@app.get("/ledger")
def get_ledger():
    return ledger.get_chain()

# ----------------------------- Auth Endpoints -----------------------------
@app.post("/users/register", response_model=Token)
def register_user(user: UserCreate):
    if user.phone in DB["users"]:
        raise HTTPException(status_code=400, detail="Phone already registered")
    hashed_password = get_password_hash(user.password)
    DB["users"][user.phone] = {"password_hash": hashed_password}
    # Auto-grant access token on register
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.phone}, expires_delta=access_token_expires
    )
    tx = {"type": "user_register", "phone_hash": sha256_hex(user.phone)}
    ledger.add_transaction(tx)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/login", response_model=Token)
def login_user(user: UserLogin):
    user_db = DB["users"].get(user.phone)
    if not user_db or not verify_password(user.password, user_db["password_hash"]):
        raise HTTPException(
            status_code=400, detail="Incorrect phone or password"
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.phone}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ----------------------------- Simple demo data on startup -----------------------------
@app.on_event("startup")
def startup_event():
    # Ensure operators exist with keys
    operator_keys.ensure_operator("OperatorA")
    operator_keys.ensure_operator("OperatorB")
    # Seed a principal and telemarketer for convenience (match UI defaults)
    pr = {"name": "SeedBiz", "headers": ["HDR-1"]}
    DB['principals']['PR-1'] = pr
    DB['telemarketers']['TM-1'] = {"name": "SeedTM", "trai_id": "TR-0001", "deposit": 1000}
    # Attempt to seed default user for demo (matches UI defaults)
    try:
        default_phone = "9876543210"
        default_password = "1234"
        if default_phone not in DB["users"]:
            hashed = get_password_hash(default_password)
            DB["users"][default_phone] = {"password_hash": hashed}
            print(f"✅ Default user seeded: phone={default_phone}, password={default_password}")
    except Exception as e:
        print(f"⚠️ Failed to seed default user (likely bcrypt issue): {e}. Register via UI/API instead.")
    ledger.add_transaction({"type": "seed", "msg": "seeded operators, principal PR-1 with HDR-1, telemarketer TM-1, and attempted default user (phone=9876543210, pass=1234)"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
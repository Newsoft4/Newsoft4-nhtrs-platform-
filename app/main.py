"""NHTRS secure pilot API. Aggregated national metrics; property-scoped private guest records."""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, model_validator
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, create_engine, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

STATES = ["Abia", "Adamawa", "Akwa Ibom", "Anambra", "Bauchi", "Bayelsa", "Benue", "Borno", "Cross River", "Delta", "Ebonyi", "Edo", "Ekiti", "Enugu", "FCT", "Gombe", "Imo", "Jigawa", "Kaduna", "Kano", "Katsina", "Kebbi", "Kogi", "Kwara", "Lagos", "Nasarawa", "Niger", "Ogun", "Ondo", "Osun", "Oyo", "Plateau", "Rivers", "Sokoto", "Taraba", "Yobe", "Zamfara"]
KINDS = ["hotel", "guesthouse", "serviced_apartment", "short_let", "resort", "lodge", "hostel", "other"]
JWT_SECRET = os.getenv("JWT_SECRET", "")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
ID_HASH_SECRET = os.getenv("ID_HASH_SECRET", "")
if not (len(JWT_SECRET) >= 32 and len(ID_HASH_SECRET) >= 32 and ENCRYPTION_KEY):
    raise RuntimeError("Set JWT_SECRET, ID_HASH_SECRET and ENCRYPTION_KEY before launching the API")
crypto = Fernet(ENCRYPTION_KEY.encode())
hasher = PasswordHasher()
DB_URL = os.getenv("DATABASE_URL", "sqlite:///./nht.db")
engine = create_engine(DB_URL, pool_pre_ping=True, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "http://localhost:8000").rstrip("/")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

class Base(DeclarativeBase): pass

class Property(Base):
    __tablename__ = "properties"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    code: Mapped[str] = mapped_column(String(28), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    state: Mapped[str] = mapped_column(String(35), nullable=False, index=True)
    city: Mapped[str] = mapped_column(String(90), nullable=False)
    total_units: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(30), nullable=False)
    state: Mapped[str | None] = mapped_column(String(35))
    property_id: Mapped[str | None] = mapped_column(ForeignKey("properties.id"))
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

class Stay(Base):
    __tablename__ = "stays"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    property_id: Mapped[str] = mapped_column(ForeignKey("properties.id"), index=True)
    unit: Mapped[str] = mapped_column(String(30), nullable=False)
    source: Mapped[str] = mapped_column(String(30), nullable=False, default="manual")
    external_ref: Mapped[str | None] = mapped_column(String(100))
    checked_in_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    checked_out_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    guests: Mapped[list["Guest"]] = relationship(back_populates="stay", cascade="all, delete-orphan")
    __table_args__ = (
        Index("unique_active_unit", "property_id", "unit", unique=True,
              postgresql_where=(checked_out_at.is_(None)), sqlite_where=(checked_out_at.is_(None))),
        UniqueConstraint("property_id", "source", "external_ref", name="unique_source_reference"),
    )

class Guest(Base):
    __tablename__ = "guests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    stay_id: Mapped[str] = mapped_column(ForeignKey("stays.id"), index=True)
    citizenship: Mapped[str] = mapped_column(String(16), nullable=False)
    nationality: Mapped[str] = mapped_column(String(70), nullable=False)
    record_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    identifier_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    identifier_last4: Mapped[str] = mapped_column(String(4), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(30), default="not_connected")
    stay: Mapped[Stay] = relationship(back_populates="guests")

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(55), nullable=False)
    property_id: Mapped[str | None] = mapped_column(String(36))
    target_id: Mapped[str | None] = mapped_column(String(100))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class PMSKey(Base):
    __tablename__ = "pms_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    property_id: Mapped[str] = mapped_column(ForeignKey("properties.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(70), nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

class PMSEvent(Base):
    __tablename__ = "pms_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_id: Mapped[str] = mapped_column(ForeignKey("pms_keys.id"), nullable=False)
    event_id: Mapped[str] = mapped_column(String(100), nullable=False)
    __table_args__ = (UniqueConstraint("key_id", "event_id", name="unique_pms_event"),)

class Login(BaseModel):
    username: str
    password: str

class PropertyIn(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    kind: Literal["hotel", "guesthouse", "serviced_apartment", "short_let", "resort", "lodge", "hostel", "other"]
    state: str
    city: str = Field(min_length=2, max_length=90)
    total_units: int = Field(ge=1, le=100000)
    @model_validator(mode="after")
    def validate_state(self):
        if self.state not in STATES: raise ValueError("Invalid Nigerian state/FCT")
        return self

class UserIn(BaseModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9_.-]{3,60}$")
    password: str = Field(min_length=12, max_length=200)
    role: Literal["national", "state", "property"]
    state: str | None = None
    property_id: str | None = None
    @model_validator(mode="after")
    def scope_valid(self):
        if self.role == "state" and self.state not in STATES: raise ValueError("Select state for state-scoped account")
        if self.role == "property" and not self.property_id: raise ValueError("Select property for property-scoped account")
        return self

class GuestIn(BaseModel):
    citizenship: Literal["nigerian", "foreign"]
    full_name: str = Field(min_length=2, max_length=160)
    phone: str = Field(min_length=6, max_length=35)
    email: EmailStr
    nationality: str = Field(default="Nigeria", max_length=70)
    contact_address: str | None = Field(default=None, max_length=250)
    occupation: str | None = Field(default=None, max_length=120)
    nin: str | None = None
    passport_number: str | None = Field(default=None, max_length=35)
    passport_expiry: date | None = None
    entry_basis: Literal["visa", "visa_exempt", "ecowas", "residence_permit"] | None = None
    visa_type: str | None = Field(default=None, max_length=60)
    visa_number: str | None = Field(default=None, max_length=80)
    visa_expiry: date | None = None
    residency_status: Literal["visitor", "resident"] | None = None
    residency_permit_number: str | None = Field(default=None, max_length=60)
    @model_validator(mode="after")
    def identity_fields(self):
        if self.citizenship == "nigerian":
            if not self.nin or not re.fullmatch(r"\d{11}", self.nin):
                raise ValueError("Nigerian guest requires an 11-digit NIN in this pilot; implement lawful exceptions for minors")
            self.nationality = "Nigeria"
            self.passport_number = None
            self.passport_expiry = None
            self.entry_basis = None
            self.visa_type = None
            self.visa_number = None
            self.visa_expiry = None
            self.residency_status = None
            self.residency_permit_number = None
        else:
            self.nin = None
            if not self.passport_number or not self.nationality or self.nationality.strip().lower() == "nigeria":
                raise ValueError("Foreign guest requires passport number and non-Nigerian nationality")
            if not self.entry_basis or not self.residency_status:
                raise ValueError("Foreign guest requires entry basis and residency status")
            if self.entry_basis == "visa" and not self.visa_number:
                raise ValueError("Provide visa reference where visa-based entry applies")
            if self.entry_basis == "residence_permit" and not self.residency_permit_number:
                raise ValueError("Provide residence permit number for residence-permit entry")
        return self

class StayIn(BaseModel):
    unit: str = Field(min_length=1, max_length=30, pattern=r"^[A-Za-z0-9._-]+$")
    source: Literal["manual", "pms", "channel_manager", "airbnb_host"] = "manual"
    external_ref: str | None = Field(default=None, max_length=100)
    guests: list[GuestIn] = Field(min_length=1, max_length=25)

class CheckOutIn(BaseModel):
    stay_id: str | None = None
    external_ref: str | None = None

@asynccontextmanager
async def lifespan(_app: FastAPI):
    bootstrap()
    yield

app = FastAPI(title="NHTRS API", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json", lifespan=lifespan)
ROOT = Path(__file__).parent
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")

@app.middleware("http")
async def guards(request: Request, call_next):
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path != "/api/integrations/pms":
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") != ALLOWED_ORIGIN:
            return JSONResponse(status_code=403, content={"detail": "Origin not permitted"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' ws: wss:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/", include_in_schema=False)
def index(): return FileResponse(ROOT / "static" / "index.html")

@app.get("/api/health")
def health():
    with SessionLocal() as db: db.execute(select(func.count()).select_from(Property)).scalar_one()
    return {"status": "ok", "identity_verification": "not_connected", "immigration_verification": "not_connected"}

def db_dep():
    with SessionLocal() as db: yield db

def require_user(request: Request, db: Session = Depends(db_dep)) -> User:
    token = request.cookies.get("nht_session")
    try:
        payload = jwt.decode(token or "", JWT_SECRET, algorithms=["HS256"], options={"require": ["exp", "sub", "csrf"]})
        user = db.get(User, payload["sub"])
    except (jwt.PyJWTError, KeyError):
        raise HTTPException(401, "Login required")
    if not user or not user.enabled: raise HTTPException(401, "Login required")
    return user

def mutation_user(request: Request, db: Session = Depends(db_dep)) -> User:
    user = require_user(request, db)
    token = request.cookies.get("nht_session")
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    supplied = request.headers.get("X-CSRF-Token", "")
    if not secrets.compare_digest(supplied, payload["csrf"]):
        raise HTTPException(403, "CSRF token missing or invalid")
    return user

def only(user: User, *roles):
    if user.role not in roles: raise HTTPException(403, "Permission denied")

def log(db: Session, user: str, action: str, prop: str | None = None, target: str | None = None):
    db.add(Audit(actor=user, action=action, property_id=prop, target_id=target))

def encrypt(data: dict) -> str: return crypto.encrypt(json.dumps(data, default=str).encode()).decode()
def decrypt(value: str) -> dict: return json.loads(crypto.decrypt(value.encode()))
def identity_digest(value: str) -> str: return hmac.new(ID_HASH_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()

def is_visible(user: User, prop: Property) -> bool:
    return user.role == "national" or (user.role == "state" and user.state == prop.state) or (user.role == "property" and user.property_id == prop.id)

def safe_property(prop: Property):
    return {"id": prop.id, "code": prop.code, "name": prop.name, "kind": prop.kind, "state": prop.state, "city": prop.city, "total_units": prop.total_units}

@app.post("/api/auth/login")
def login(body: Login, response: Response, db: Session = Depends(db_dep)):
    user = db.scalar(select(User).where(User.username == body.username))
    try:
        valid = bool(user and user.enabled and hasher.verify(user.password_hash, body.password))
    except (VerifyMismatchError, VerificationError):
        valid = False
    if not valid: raise HTTPException(401, "Invalid username or password")
    csrf = secrets.token_urlsafe(24)
    token = jwt.encode({"sub": user.id, "exp": datetime.now(timezone.utc) + timedelta(hours=8), "csrf": csrf}, JWT_SECRET, algorithm="HS256")
    response.set_cookie("nht_session", token, max_age=8 * 3600, httponly=True, samesite="strict", secure=COOKIE_SECURE, path="/")
    log(db, user.username, "login")
    db.commit()
    return {"csrf": csrf, "username": user.username, "role": user.role, "property_id": user.property_id, "state": user.state}

@app.get("/api/auth/me")
def me(request: Request, user: User = Depends(require_user)):
    return {"username": user.username, "role": user.role, "property_id": user.property_id, "state": user.state, "csrf": jwt.decode(request.cookies["nht_session"], JWT_SECRET, algorithms=["HS256"])["csrf"]}

@app.post("/api/auth/logout")
def logout(response: Response, user: User = Depends(mutation_user)):
    response.delete_cookie("nht_session", path="/")
    return {"ok": True}

@app.post("/api/properties", status_code=201)
async def create_property(body: PropertyIn, db: Session = Depends(db_dep), user: User = Depends(mutation_user)):
    only(user, "national")
    prop = Property(code=f"NHT-{secrets.token_hex(5).upper()}", **body.model_dump())
    db.add(prop)
    log(db, user.username, "create_property", prop.id)
    db.commit()
    await announce(prop.id, prop.state)
    return safe_property(prop)

@app.get("/api/properties")
def list_properties(user: User = Depends(require_user), db: Session = Depends(db_dep)):
    stmt = select(Property).order_by(Property.state, Property.name)
    if user.role == "state": stmt = stmt.where(Property.state == user.state)
    elif user.role == "property": stmt = stmt.where(Property.id == user.property_id)
    return [safe_property(p) for p in db.scalars(stmt).all()]

@app.post("/api/users", status_code=201)
def create_user(body: UserIn, db: Session = Depends(db_dep), user: User = Depends(mutation_user)):
    only(user, "national")
    if body.role == "property" and not db.get(Property, body.property_id):
        raise HTTPException(404, "Unknown property")
    account = User(username=body.username, password_hash=hasher.hash(body.password), role=body.role,
                   state=body.state if body.role == "state" else None,
                   property_id=body.property_id if body.role == "property" else None)
    db.add(account)
    log(db, user.username, "create_user", body.property_id, account.id)
    try: db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username already exists")
    return {"id": account.id, "username": account.username, "role": account.role}

@app.get("/api/dashboard")
def dashboard(state: str | None = None, user: User = Depends(require_user), db: Session = Depends(db_dep)):
    query = select(Property)
    if user.role == "state": query = query.where(Property.state == user.state)
    elif user.role == "property": query = query.where(Property.id == user.property_id)
    elif state:
        if state not in STATES: raise HTTPException(422, "Invalid state")
        query = query.where(Property.state == state)
    properties = db.scalars(query).all()
    ids = [p.id for p in properties]
    occupied_by_property = {p.id: 0 for p in properties}
    nationals_by_property = {p.id: 0 for p in properties}
    foreigners_by_property = {p.id: 0 for p in properties}
    if ids:
        active = db.execute(select(Stay.id, Stay.property_id).where(Stay.property_id.in_(ids), Stay.checked_out_at.is_(None))).all()
        stay_to_prop = {stay_id: prop_id for stay_id, prop_id in active}
        for prop_id in stay_to_prop.values(): occupied_by_property[prop_id] += 1
        if stay_to_prop:
            for stay_id, citizenship in db.execute(select(Guest.stay_id, Guest.citizenship).where(Guest.stay_id.in_(list(stay_to_prop)))):
                p = stay_to_prop[stay_id]
                if citizenship == "nigerian": nationals_by_property[p] += 1
                else: foreigners_by_property[p] += 1
    total_units = sum(p.total_units for p in properties)
    occupied = sum(occupied_by_property.values())
    national_guests = sum(nationals_by_property.values())
    foreign_guests = sum(foreigners_by_property.values())
    breakdown = {}
    type_breakdown = {}
    for p in properties:
        s = breakdown.setdefault(p.state, {"state": p.state, "properties": 0, "units": 0, "occupied": 0, "nigerian_guests": 0, "foreign_guests": 0})
        k = type_breakdown.setdefault(p.kind, {"kind": p.kind, "properties": 0, "units": 0, "occupied": 0})
        s["properties"] += 1; s["units"] += p.total_units; s["occupied"] += occupied_by_property[p.id]
        s["nigerian_guests"] += nationals_by_property[p.id]; s["foreign_guests"] += foreigners_by_property[p.id]
        k["properties"] += 1; k["units"] += p.total_units; k["occupied"] += occupied_by_property[p.id]
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "scope": user.role,
            "properties": len(properties), "total_units": total_units, "occupied_units": occupied,
            "available_units": total_units - occupied,
            "occupancy_rate": round(100 * occupied / total_units, 1) if total_units else 0,
            "nigerian_guests": national_guests, "foreign_guests": foreign_guests,
            "active_guests": national_guests + foreign_guests,
            "states": sorted(breakdown.values(), key=lambda x: x["state"]),
            "types": sorted(type_breakdown.values(), key=lambda x: x["kind"]),
            "definition": "Current checked-in stays and guests reported by participating properties; not independently observed physical presence."}

async def _create_stay(db: Session, actor: str, prop: Property, body: StayIn):
    unit = body.unit.strip().upper()
    # Serialise concurrent check-ins per property on PostgreSQL to enforce total_units.
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:prop_id))"), {"prop_id": prop.id})
    count = db.scalar(select(func.count()).select_from(Stay).where(Stay.property_id == prop.id, Stay.checked_out_at.is_(None))) or 0
    if count >= prop.total_units: raise HTTPException(409, "Property has no unoccupied units")
    if db.scalar(select(Stay.id).where(Stay.property_id == prop.id, Stay.unit == unit, Stay.checked_out_at.is_(None))):
        raise HTTPException(409, "Unit already occupied")
    if body.external_ref and db.scalar(select(Stay.id).where(Stay.property_id == prop.id, Stay.source == body.source, Stay.external_ref == body.external_ref)):
        raise HTTPException(409, "External reference already registered")
    stay = Stay(property_id=prop.id, unit=unit, source=body.source, external_ref=body.external_ref)
    db.add(stay)
    db.flush()
    for guest in body.guests:
        data = guest.model_dump(mode="json", exclude_none=True)
        raw_identifier = data.get("nin") if guest.citizenship == "nigerian" else data.get("passport_number")
        db.add(Guest(stay_id=stay.id, citizenship=guest.citizenship, nationality=guest.nationality,
                     record_encrypted=encrypt(data), identifier_digest=identity_digest(raw_identifier),
                     identifier_last4=raw_identifier[-4:], verification_status="not_connected"))
    log(db, actor, "checkin", prop.id, stay.id)
    try: db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Duplicate unit or external reference")
    await announce(prop.id, prop.state)
    return {"stay_id": stay.id, "property_id": prop.id, "unit": unit, "guest_count": len(body.guests), "status": "checked_in", "identity_verification": "not_connected"}

@app.post("/api/stays", status_code=201)
async def checkin(body: StayIn, db: Session = Depends(db_dep), user: User = Depends(mutation_user)):
    only(user, "property")
    prop = db.get(Property, user.property_id)
    if not prop: raise HTTPException(404, "Property missing")
    return await _create_stay(db, user.username, prop, body)

@app.get("/api/stays")
def active_stays(user: User = Depends(require_user), db: Session = Depends(db_dep)):
    only(user, "property")
    stays = db.scalars(select(Stay).where(Stay.property_id == user.property_id, Stay.checked_out_at.is_(None)).order_by(Stay.checked_in_at.desc())).all()
    result = []
    for stay in stays:
        result.append({"stay_id": stay.id, "unit": stay.unit, "source": stay.source, "checked_in_at": stay.checked_in_at,
                       "guest_count": len(stay.guests), "guest_names": [decrypt(g.record_encrypted)["full_name"] for g in stay.guests]})
    return result

@app.get("/api/stays/{stay_id}")
def stay_details(stay_id: str, user: User = Depends(require_user), db: Session = Depends(db_dep)):
    only(user, "property")
    stay = db.get(Stay, stay_id)
    if not stay or stay.property_id != user.property_id: raise HTTPException(404, "Stay not found")
    log(db, user.username, "read_guest_record", stay.property_id, stay.id)
    db.commit()
    def masked_detail(g):
        fields = decrypt(g.record_encrypted)
        for k in ("nin", "passport_number", "visa_number", "residency_permit_number"):
            fields.pop(k, None)
        fields["identity_last4"] = g.identifier_last4
        fields["identity_verification"] = g.verification_status
        return fields
    return {"stay_id": stay.id, "unit": stay.unit, "checked_in_at": stay.checked_in_at,
            "checked_out_at": stay.checked_out_at,
            "guests": [masked_detail(g) for g in stay.guests]}

async def _checkout(db: Session, actor: str, prop: Property, stay: Stay):
    if stay.property_id != prop.id: raise HTTPException(404, "Stay not found")
    if stay.checked_out_at: raise HTTPException(409, "Already checked out")
    stay.checked_out_at = datetime.now(timezone.utc)
    log(db, actor, "checkout", prop.id, stay.id)
    db.commit()
    await announce(prop.id, prop.state)
    return {"stay_id": stay.id, "status": "checked_out"}

@app.post("/api/stays/{stay_id}/checkout")
async def checkout(stay_id: str, db: Session = Depends(db_dep), user: User = Depends(mutation_user)):
    only(user, "property")
    stay = db.get(Stay, stay_id)
    if not stay or stay.property_id != user.property_id: raise HTTPException(404, "Stay not found")
    return await _checkout(db, user.username, db.get(Property, user.property_id), stay)

@app.post("/api/integrations/issue-key", status_code=201)
def issue_key(label: str, db: Session = Depends(db_dep), user: User = Depends(mutation_user)):
    only(user, "property")
    if not (2 <= len(label) <= 70): raise HTTPException(422, "Label must be between 2 and 70 characters")
    secret = secrets.token_urlsafe(40)
    record = PMSKey(property_id=user.property_id, label=label, encrypted_secret=encrypt({"secret": secret}))
    db.add(record)
    log(db, user.username, "issue_pms_key", user.property_id, record.id)
    db.commit()
    return {"key_id": record.id, "shared_secret_once": secret, "property_id": user.property_id, "signature": "hex HMAC-SHA256 of '<unix_timestamp>.<event_id>.' + exact JSON bytes"}

@app.post("/api/integrations/revoke-key/{key_id}")
def revoke_key(key_id: str, db: Session = Depends(db_dep), user: User = Depends(mutation_user)):
    only(user, "property")
    record = db.get(PMSKey, key_id)
    if not record or record.property_id != user.property_id: raise HTTPException(404, "Key not found")
    record.enabled = False
    log(db, user.username, "revoke_pms_key", user.property_id, key_id)
    db.commit()
    return {"revoked": True}

@app.post("/api/integrations/pms")
async def pms_webhook(request: Request, db: Session = Depends(db_dep),
                      x_nhtrs_key_id: str = Header(default=""), x_nhtrs_timestamp: str = Header(default=""),
                      x_nhtrs_event_id: str = Header(default=""), x_nhtrs_signature: str = Header(default="")):
    if not (1 <= len(x_nhtrs_event_id) <= 100): raise HTTPException(400, "Missing valid event ID")
    try:
        ts = int(x_nhtrs_timestamp)
        if abs(time.time() - ts) > 300: raise ValueError()
    except ValueError: raise HTTPException(401, "Invalid timestamp")
    key = db.get(PMSKey, x_nhtrs_key_id)
    if not key or not key.enabled: raise HTTPException(401, "Invalid integration credentials")
    raw = await request.body()
    if len(raw) > 256_000: raise HTTPException(413, "Request too large")
    secret = decrypt(key.encrypted_secret)["secret"].encode()
    expected = hmac.new(secret, f"{ts}.{x_nhtrs_event_id}.".encode() + raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_nhtrs_signature): raise HTTPException(401, "Invalid signature")
    if db.scalar(select(PMSEvent.id).where(PMSEvent.key_id == key.id, PMSEvent.event_id == x_nhtrs_event_id)):
        return {"status": "duplicate_ignored"}
    try: payload = json.loads(raw)
    except ValueError: raise HTTPException(422, "Invalid JSON")
    if not isinstance(payload, dict): raise HTTPException(422, "Expected JSON object")
    prop = db.get(Property, key.property_id)
    event = payload.get("event")
    if event == "checkin":
        try: body = StayIn.model_validate(payload.get("stay", {}))
        except Exception: raise HTTPException(422, "Invalid stay payload")
        if not body.external_ref: raise HTTPException(422, "PMS check-in requires external_ref")
        body.source = "pms"
        # Persist the event receipt in the same transaction as the stay.
        # A network retry must never create an untracked guest check-in.
        db.add(PMSEvent(key_id=key.id, event_id=x_nhtrs_event_id))
        result = await _create_stay(db, f"pms:{key.id}", prop, body)
    elif event == "checkout":
        try: checked = CheckOutIn.model_validate(payload)
        except Exception: raise HTTPException(422, "Invalid checkout payload")
        if not checked.stay_id and not checked.external_ref: raise HTTPException(422, "Provide stay_id or external_ref")
        stmt = select(Stay).where(Stay.property_id == key.property_id)
        if checked.stay_id: stmt = stmt.where(Stay.id == checked.stay_id)
        else: stmt = stmt.where(Stay.external_ref == checked.external_ref, Stay.source == "pms")
        stay = db.scalar(stmt)
        if not stay: raise HTTPException(404, "Stay not found")
        # Checkout and replay receipt commit atomically as well.
        db.add(PMSEvent(key_id=key.id, event_id=x_nhtrs_event_id))
        result = await _checkout(db, f"pms:{key.id}", prop, stay)
    else: raise HTTPException(422, "Event must be checkin or checkout")
    return result

@app.get("/api/audit")
def audit(user: User = Depends(require_user), db: Session = Depends(db_dep)):
    only(user, "national")
    entries = db.scalars(select(Audit).order_by(Audit.at.desc()).limit(100)).all()
    return [{"at": a.at, "actor": a.actor, "action": a.action, "property_id": a.property_id, "target_id": a.target_id} for a in entries]

# Per-process WebSocket push for a pilot deployment; use shared Redis pub/sub for multiple API replicas.
subscribers: dict[WebSocket, tuple[str, str | None, str | None]] = {}
async def announce(prop_id: str, state: str):
    dead = []
    for ws, (role, scoped_state, scoped_prop) in list(subscribers.items()):
        if role == "national" or (role == "state" and scoped_state == state) or (role == "property" and scoped_prop == prop_id):
            try: await ws.send_json({"type": "occupancy_changed"})
            except Exception: dead.append(ws)
    for ws in dead: subscribers.pop(ws, None)

@app.websocket("/api/live")
async def live(websocket: WebSocket):
    origin = websocket.headers.get("origin", "")
    if origin.rstrip("/") != ALLOWED_ORIGIN:
        await websocket.close(code=1008); return
    token = websocket.cookies.get("nht_session", "")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        with SessionLocal() as db:
            user = db.get(User, payload["sub"])
            if not user or not user.enabled: raise ValueError()
            info = (user.role, user.state, user.property_id)
    except (jwt.PyJWTError, ValueError, KeyError):
        await websocket.close(code=1008); return
    await websocket.accept()
    subscribers[websocket] = info
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: pass
    finally: subscribers.pop(websocket, None)

def bootstrap():
    Base.metadata.create_all(engine)
    username = os.getenv("BOOTSTRAP_USERNAME", "admin")
    password = os.getenv("BOOTSTRAP_PASSWORD", "")
    with SessionLocal() as db:
        exists = db.scalar(select(User.id).limit(1))
        if not exists:
            if len(password) < 12: raise RuntimeError("BOOTSTRAP_PASSWORD must be >= 12 chars")
            db.add(User(username=username, password_hash=hasher.hash(password), role="national"))
            db.commit()

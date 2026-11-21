"""End-to-end tests with fictional records only."""
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from cryptography.fernet import Fernet

os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)
os.environ["ID_HASH_SECRET"] = secrets.token_urlsafe(48)
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["BOOTSTRAP_PASSWORD"] = "demo_admin_strong_password"
os.environ["DATABASE_URL"] = "sqlite:///" + tempfile.mkdtemp(prefix="nhtrs_tests_") + "/demo.db"
os.environ["ALLOWED_ORIGIN"] = "http://testserver"

from fastapi.testclient import TestClient
from sqlalchemy import select
from app.main import Guest, PMSEvent, SessionLocal, app

NIG = {"citizenship": "nigerian", "full_name": "Demo Citizen", "phone": "+2348000000000", "email": "citizen@example.com", "nin": "99999999999"}
FOR = {"citizenship": "foreign", "full_name": "Demo Visitor", "phone": "+441111111111", "email": "visitor@example.com", "nationality": "Canada", "passport_number": "SAMPLE-PASSPORT", "entry_basis": "visa", "visa_number": "TEST-VISA", "residency_status": "visitor"}

def login(client, name, password):
    r = client.post("/api/auth/login", json={"username": name, "password": password})
    assert r.status_code == 200, r.text
    return {"X-CSRF-Token": r.json()["csrf"]}

def test_registration_occupancy_scoping_and_encryption():
    with TestClient(app, base_url="http://testserver") as national:
        admin = login(national, "admin", "demo_admin_strong_password")
        prop = national.post("/api/properties", headers=admin, json={"name": "Sample Borno Lodge", "kind": "lodge", "state": "Borno", "city": "Maiduguri", "total_units": 2})
        assert prop.status_code == 201, prop.text
        prop = prop.json()
        another = national.post("/api/properties", headers=admin, json={"name": "Sample Lagos Suites", "kind": "short_let", "state": "Lagos", "city": "Ikeja", "total_units": 3}).json()
        for body in [
            {"username": "borno", "password": "borno_strong_password", "role": "property", "property_id": prop["id"]},
            {"username": "lagos", "password": "lagos_strong_password", "role": "property", "property_id": another["id"]},
            {"username": "state", "password": "state_strong_password", "role": "state", "state": "Borno"},
        ]:
            r=national.post("/api/users", headers=admin, json=body)
            assert r.status_code==201, r.text
        with TestClient(app, base_url="http://testserver") as hotel:
            headers = login(hotel, "borno", "borno_strong_password")
            stay = hotel.post("/api/stays", headers=headers, json={"unit": "Room-1", "guests": [NIG, FOR]})
            assert stay.status_code == 201, stay.text
            sid = stay.json()["stay_id"]
            assert hotel.get("/api/stays").json()[0]["guest_count"] == 2
            detail = hotel.get("/api/stays/" + sid).json()["guests"][1]
            assert detail["identity_last4"] == "PORT"
            assert "passport_number" not in detail
            assert hotel.post("/api/stays", headers=headers, json={"unit": "Room-1", "guests": [NIG]}).status_code == 409
            assert hotel.post("/api/stays", json={"unit": "Room-2", "guests": [NIG]}).status_code == 403
            national_dash = national.get("/api/dashboard").json()
            assert national_dash["properties"] == 2 and national_dash["occupied_units"] == 1
            assert national_dash["nigerian_guests"] == 1 and national_dash["foreign_guests"] == 1
            assert "SAMPLE-PASSPORT" not in json.dumps(national_dash)
            assert national.get("/api/stays/" + sid).status_code == 403
            with SessionLocal() as db:
                record = db.scalar(select(Guest).where(Guest.citizenship == "foreign"))
                assert "SAMPLE-PASSPORT" not in record.record_encrypted
                assert "Demo Visitor" not in record.record_encrypted
                assert record.identifier_last4 == "PORT"
            with TestClient(app, base_url="http://testserver") as state_client:
                login(state_client, "state", "state_strong_password")
                dash = state_client.get("/api/dashboard").json()
                assert dash["properties"] == 1 and dash["occupied_units"] == 1
                assert state_client.get("/api/stays/" + sid).status_code == 403
            with TestClient(app, base_url="http://testserver") as other:
                login(other, "lagos", "lagos_strong_password")
                assert other.get("/api/stays/" + sid).status_code == 404
                assert other.get("/api/dashboard").json()["occupied_units"] == 0
            assert hotel.post(f"/api/stays/{sid}/checkout", headers=headers).status_code == 200
            assert national.get("/api/dashboard").json()["occupied_units"] == 0

def test_pms_signed_ingest_replay_and_scoping():
    with TestClient(app, base_url="http://testserver") as national:
        admin = login(national, "admin", "demo_admin_strong_password")
        prop = national.post("/api/properties", headers=admin, json={"name": "PMS Test Hotel", "kind": "hotel", "state": "Abia", "city": "Aba", "total_units": 3}).json()
        national.post("/api/users", headers=admin, json={"username": "pms_operator", "password": "pms_operator_password", "role": "property", "property_id": prop["id"]})
        with TestClient(app, base_url="http://testserver") as hotel:
            h = login(hotel, "pms_operator", "pms_operator_password")
            key = hotel.post("/api/integrations/issue-key?label=Demo", headers=h)
            assert key.status_code == 201, key.text
            key=key.json()
            payload={"event":"checkin", "stay":{"unit":"102", "external_ref":"DEMO-BOOKING-102", "guests":[NIG]}}
            raw=json.dumps(payload,separators=(',',':')).encode()
            timestamp=str(int(time.time()));event_id=str(uuid4())
            canonical=f"{timestamp}.{event_id}.".encode()+raw
            signature=hmac.new(key['shared_secret_once'].encode(),canonical,hashlib.sha256).hexdigest()
            headers={"X-NHTRS-Key-ID":key['key_id'],"X-NHTRS-Timestamp":timestamp,"X-NHTRS-Event-ID":event_id,"X-NHTRS-Signature":signature,"Content-Type":"application/json"}
            assert hotel.post('/api/integrations/pms', headers={**headers, "X-NHTRS-Signature":'0'*64}, content=raw).status_code==401
            r=hotel.post('/api/integrations/pms', headers=headers, content=raw)
            assert r.status_code==200, r.text
            assert hotel.post('/api/integrations/pms', headers=headers, content=raw).json()=={"status":"duplicate_ignored"}
            assert hotel.get('/api/dashboard').json()['occupied_units']==1
            with SessionLocal() as db:
                assert db.scalar(select(PMSEvent).where(PMSEvent.event_id == event_id)) is not None
            checkout_event_id=str(uuid4())
            checkout_body=json.dumps({"event":"checkout","external_ref":"DEMO-BOOKING-102"},separators=(',',':')).encode()
            checkout_signature=hmac.new(key['shared_secret_once'].encode(),f"{timestamp}.{checkout_event_id}.".encode()+checkout_body,hashlib.sha256).hexdigest()
            checkout_headers={**headers,"X-NHTRS-Event-ID":checkout_event_id,"X-NHTRS-Signature":checkout_signature}
            out=hotel.post('/api/integrations/pms',headers=checkout_headers,content=checkout_body)
            assert out.status_code==200, out.text
            assert hotel.get('/api/dashboard').json()['occupied_units']==0
            with SessionLocal() as db:
                assert db.scalar(select(PMSEvent).where(PMSEvent.event_id == checkout_event_id)) is not None
            assert hotel.post('/api/integrations/pms',headers=checkout_headers,content=checkout_body).json()=={"status":"duplicate_ignored"}
            assert hotel.post('/api/integrations/revoke-key/'+key['key_id'],headers=h).status_code==200
            assert hotel.post('/api/integrations/pms',headers=headers,content=raw).status_code==401

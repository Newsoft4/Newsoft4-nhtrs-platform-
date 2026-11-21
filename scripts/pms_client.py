"""Minimal signed PMS client. All sample guests are fictional."""
import hashlib
import hmac
import json
import os
import time
from urllib.request import Request, urlopen
from uuid import uuid4

host=os.getenv('NHTRS_URL','http://localhost:8000').rstrip('/')
key_id=os.environ['NHTRS_PMS_KEY_ID']
secret=os.environ['NHTRS_PMS_SECRET']
payload={
  "event":"checkin",
  "stay":{"unit":"PILOT-101","external_ref":"TEST-BOOKING-123",
          "guests":[{"citizenship":"nigerian","full_name":"Fictional Test Guest",
                     "phone":"+2348000000000","email":"test@example.com","nin":"99999999999"}]}
}
raw=json.dumps(payload,separators=(',',':')).encode()
timestamp=str(int(time.time()))
event_id=str(uuid4())
signature=hmac.new(secret.encode(),f'{timestamp}.{event_id}.'.encode()+raw,hashlib.sha256).hexdigest()
headers={"Content-Type":"application/json","X-NHTRS-Key-ID":key_id,"X-NHTRS-Timestamp":timestamp,
         "X-NHTRS-Event-ID":event_id,"X-NHTRS-Signature":signature}
req=Request(host+'/api/integrations/pms',data=raw,headers=headers,method='POST')
with urlopen(req,timeout=10) as res:
    print(res.read().decode())

from flask import current_app
import uuid
import hashlib
import json
from datetime import datetime

def generate_certificate(user_id, certificate_data):
    certificate_id = str(uuid.uuid4())
    certificate_hash = hashlib.sha256(certificate_id.encode()).hexdigest()
    
    certificate = {
        "id": certificate_id,
        "user_id": user_id,
        "data": certificate_data,
        "hash": certificate_hash,
        "issued_at": datetime.utcnow().isoformat()
    }
    
    store_certificate(certificate)
    return certificate

def store_certificate(certificate):
    db = current_app.firestore
    certificates_ref = db.collection('certificates')
    certificates_ref.document(certificate['id']).set(certificate)
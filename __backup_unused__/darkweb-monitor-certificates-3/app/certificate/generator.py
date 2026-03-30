from datetime import datetime
import uuid
import hashlib

def generate_certificate_id():
    return str(uuid.uuid4())

def generate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def create_certificate_data(user_info):
    certificate_id = generate_certificate_id()
    issue_date = datetime.utcnow().isoformat()
    certificate_hash = generate_hash(certificate_id + issue_date + user_info)

    certificate_data = {
        "certificate_id": certificate_id,
        "user_info": user_info,
        "issue_date": issue_date,
        "hash": certificate_hash
    }
    
    return certificate_data
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
import uuid

class CertificateGenerator:
    def __init__(self):
        self.certificates = []

    def generate_certificate(self, user_id, user_name, course_name, score):
        certificate_id = str(uuid.uuid4())
        issue_date = datetime.now().isoformat()
        verification_hash = self.create_verification_hash(certificate_id, user_id, score)

        certificate = {
            "certificate_id": certificate_id,
            "user_id": user_id,
            "user_name": user_name,
            "course_name": course_name,
            "score": score,
            "issue_date": issue_date,
            "verification_hash": verification_hash,
            "is_verified": False
        }

        self.certificates.append(certificate)
        return certificate

    def create_verification_hash(self, certificate_id, user_id, score):
        data = f"{certificate_id}{user_id}{score}".encode()
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize().hex()
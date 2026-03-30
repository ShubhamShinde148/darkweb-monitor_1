from flask import current_app
from app.certificate.storage import CertificateStorage

class CertificateVerifier:
    def __init__(self):
        self.storage = CertificateStorage()

    def verify_by_id(self, certificate_id):
        certificate = self.storage.get_certificate_by_id(certificate_id)
        if certificate:
            return {
                "status": "valid",
                "certificate": certificate
            }
        return {
            "status": "invalid",
            "message": "Certificate not found."
        }

    def verify_by_hash(self, verification_hash):
        certificate = self.storage.get_certificate_by_hash(verification_hash)
        if certificate:
            return {
                "status": "valid",
                "certificate": certificate
            }
        return {
            "status": "invalid",
            "message": "Certificate not found."
        }
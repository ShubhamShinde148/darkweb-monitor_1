from flask import current_app
from app.certificates.storage import get_certificate_by_id, get_certificate_by_hash

def verify_certificate(cert_id=None, cert_hash=None):
    if cert_id:
        certificate = get_certificate_by_id(cert_id)
        if certificate:
            return {
                "status": "valid",
                "certificate": certificate
            }
        else:
            return {
                "status": "invalid",
                "message": "Certificate not found."
            }
    elif cert_hash:
        certificate = get_certificate_by_hash(cert_hash)
        if certificate:
            return {
                "status": "valid",
                "certificate": certificate
            }
        else:
            return {
                "status": "invalid",
                "message": "Certificate not found."
            }
    else:
        return {
            "status": "error",
            "message": "No certificate ID or hash provided."
        }
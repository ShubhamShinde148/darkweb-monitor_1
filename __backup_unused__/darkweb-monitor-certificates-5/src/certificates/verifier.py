class CertificateVerifier:
    def __init__(self, storage):
        self.storage = storage

    def verify_certificate(self, certificate_id, verification_hash):
        certificate = self.storage.get_certificate(certificate_id)
        if not certificate:
            return False
        return certificate['verification_hash'] == verification_hash

    def is_certificate_verified(self, certificate_id):
        certificate = self.storage.get_certificate(certificate_id)
        if not certificate:
            return False
        return certificate['is_verified']
from firebase_admin import firestore

class CertificateStorage:
    def __init__(self):
        self.db = firestore.client()

    def save_certificate(self, certificate_data):
        certificate_ref = self.db.collection('certificates').add(certificate_data)
        return certificate_ref.id

    def get_certificate(self, certificate_id):
        certificate_ref = self.db.collection('certificates').document(certificate_id)
        certificate = certificate_ref.get()
        if certificate.exists:
            return certificate.to_dict()
        else:
            return None

    def get_all_certificates(self):
        certificates_ref = self.db.collection('certificates')
        certificates = certificates_ref.stream()
        return [cert.to_dict() for cert in certificates]
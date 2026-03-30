from google.cloud import firestore

class CertificateStorage:
    def __init__(self):
        self.db = firestore.Client()

    def save_certificate(self, certificate_data):
        certificate_ref = self.db.collection('certificates').document(certificate_data['id'])
        certificate_ref.set(certificate_data)

    def get_certificate(self, certificate_id):
        certificate_ref = self.db.collection('certificates').document(certificate_id)
        certificate = certificate_ref.get()
        if certificate.exists:
            return certificate.to_dict()
        return None

    def list_certificates(self):
        certificates_ref = self.db.collection('certificates')
        return [doc.to_dict() for doc in certificates_ref.stream()]
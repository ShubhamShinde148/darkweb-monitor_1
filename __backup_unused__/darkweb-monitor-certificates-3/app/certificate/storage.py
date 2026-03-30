from firebase_admin import firestore

class CertificateStorage:
    def __init__(self, db):
        self.db = db
        self.certificates_ref = db.collection('certificates')

    def save_certificate(self, certificate_data):
        certificate_id = certificate_data.get('id')
        self.certificates_ref.document(certificate_id).set(certificate_data)

    def get_certificate(self, certificate_id):
        certificate_doc = self.certificates_ref.document(certificate_id).get()
        if certificate_doc.exists:
            return certificate_doc.to_dict()
        return None

    def list_certificates(self):
        return [doc.to_dict() for doc in self.certificates_ref.stream()]

    def delete_certificate(self, certificate_id):
        self.certificates_ref.document(certificate_id).delete()
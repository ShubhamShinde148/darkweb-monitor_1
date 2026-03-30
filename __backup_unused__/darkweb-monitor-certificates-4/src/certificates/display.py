from flask import render_template
from src.certificates.storage import CertificateStorage

class CertificateDisplay:
    def __init__(self):
        self.storage = CertificateStorage()

    def display_certificates(self, user_id):
        certificates = self.storage.get_certificates_by_user(user_id)
        return render_template('certificate_display.html', certificates=certificates)
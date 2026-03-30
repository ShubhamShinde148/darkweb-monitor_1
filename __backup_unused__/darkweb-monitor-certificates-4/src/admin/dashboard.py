from flask import render_template
from src.certificates.storage import CertificateStorage

class AdminDashboard:
    def __init__(self):
        self.storage = CertificateStorage()

    def get_total_certificates(self):
        return len(self.storage.get_all_certificates())

    def get_recent_certificates(self, limit=5):
        return self.storage.get_recent_certificates(limit)

    def get_top_users(self, limit=5):
        return self.storage.get_top_users_by_score(limit)

    def render_dashboard(self):
        total_certificates = self.get_total_certificates()
        recent_certificates = self.get_recent_certificates()
        top_users = self.get_top_users()

        return render_template('dashboard.html', 
                               total_certificates=total_certificates, 
                               recent_certificates=recent_certificates, 
                               top_users=top_users)
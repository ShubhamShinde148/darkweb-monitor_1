from flask import Blueprint, render_template
from app.certificate.storage import CertificateStorage

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/dashboard')
def dashboard():
    storage = CertificateStorage()
    total_certificates = storage.get_total_certificates()
    recent_certificates = storage.get_recent_certificates(limit=5)
    top_users = storage.get_top_users(limit=5)

    return render_template('admin_dashboard.html', 
                           total_certificates=total_certificates, 
                           recent_certificates=recent_certificates, 
                           top_users=top_users)
from flask import Blueprint, render_template
from app.certificates.storage import get_all_certificates, get_recent_certificates, get_verification_logs

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin/dashboard')
def dashboard():
    total_certificates = get_all_certificates()
    recent_certificates = get_recent_certificates()
    verification_logs = get_verification_logs()
    
    return render_template('dashboard.html', 
                           total_certificates=len(total_certificates), 
                           recent_certificates=recent_certificates, 
                           verification_logs=verification_logs)
from flask import Flask, render_template, request, redirect, url_for
from certificates.generator import CertificateGenerator
from certificates.storage import CertificateStorage
from certificates.verifier import CertificateVerifier
from certificates.display import CertificateDisplay
from certificates.download import CertificateDownload
from admin.dashboard import AdminDashboard
from admin.monitor import CertificateMonitor

app = Flask(__name__)

# Initialize components
certificate_generator = CertificateGenerator()
certificate_storage = CertificateStorage()
certificate_verifier = CertificateVerifier()
certificate_display = CertificateDisplay()
certificate_download = CertificateDownload()
admin_dashboard = AdminDashboard()
certificate_monitor = CertificateMonitor()

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    user_data = request.form
    certificate = certificate_generator.generate(user_data)
    certificate_storage.save(certificate)
    return redirect(url_for('home'))

@app.route('/verify_certificate/<certificate_id>', methods=['GET'])
def verify_certificate(certificate_id):
    is_verified = certificate_verifier.verify(certificate_id)
    return render_template('certificate_display.html', is_verified=is_verified)

@app.route('/download_certificate/<certificate_id>', methods=['GET'])
def download_certificate(certificate_id):
    pdf = certificate_download.generate_pdf(certificate_id)
    return pdf

@app.route('/admin/dashboard')
def admin_dashboard_view():
    stats = admin_dashboard.get_statistics()
    return render_template('dashboard.html', stats=stats)

@app.route('/admin/monitor')
def monitor_view():
    logs = certificate_monitor.get_logs()
    return render_template('monitor.html', logs=logs)

if __name__ == '__main__':
    app.run(debug=True)
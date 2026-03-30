from flask import render_template, request
from app.certificates.storage import get_certificate_by_id

def display_certificate(certificate_id):
    certificate = get_certificate_by_id(certificate_id)
    if certificate:
        return render_template('certificate.html', certificate=certificate)
    else:
        return render_template('404.html'), 404

def display_user_certificates(user_id):
    certificates = get_certificates_by_user_id(user_id)
    return render_template('dashboard.html', certificates=certificates)

def download_certificate(certificate_id):
    certificate = get_certificate_by_id(certificate_id)
    if certificate:
        # Logic to generate and return the PDF of the certificate
        pass
    else:
        return render_template('404.html'), 404
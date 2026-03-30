from flask import Blueprint, request, jsonify, render_template
from app.certificate.generator import generate_certificate
from app.certificate.storage import save_certificate, get_certificate
from app.certificate.verifier import verify_certificate

certificates_bp = Blueprint('certificates', __name__)

@certificates_bp.route('/issue', methods=['POST'])
def issue_certificate():
    data = request.json
    certificate_id, certificate_data = generate_certificate(data)
    save_certificate(certificate_id, certificate_data)
    return jsonify({"message": "Certificate issued successfully", "certificate_id": certificate_id}), 201

@certificates_bp.route('/verify/<certificate_id>', methods=['GET'])
def verify(certificate_id):
    is_valid, certificate_data = verify_certificate(certificate_id)
    if is_valid:
        return jsonify({"message": "Certificate is valid", "data": certificate_data}), 200
    else:
        return jsonify({"message": "Certificate is invalid"}), 404

@certificates_bp.route('/certificate/<certificate_id>', methods=['GET'])
def retrieve_certificate(certificate_id):
    certificate_data = get_certificate(certificate_id)
    if certificate_data:
        return render_template('certificate.html', certificate=certificate_data), 200
    else:
        return jsonify({"message": "Certificate not found"}), 404

@certificates_bp.route('/download/<certificate_id>', methods=['GET'])
def download_certificate(certificate_id):
    certificate_data = get_certificate(certificate_id)
    if certificate_data:
        # Logic to generate and return the PDF file
        return jsonify({"message": "Download link for the certificate"}), 200
    else:
        return jsonify({"message": "Certificate not found"}), 404
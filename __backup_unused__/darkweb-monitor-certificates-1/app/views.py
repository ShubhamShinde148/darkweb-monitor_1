from flask import Blueprint, request, jsonify, render_template
from app.certificates.generator import generate_certificate
from app.certificates.storage import save_certificate, get_certificate
from app.certificates.verifier import verify_certificate
from app.certificates.display import display_certificate

certificates_bp = Blueprint('certificates', __name__)

@certificates_bp.route('/issue', methods=['POST'])
def issue_certificate():
    data = request.json
    certificate_id, certificate_hash = generate_certificate(data)
    save_certificate(certificate_id, certificate_hash, data)
    return jsonify({"message": "Certificate issued successfully", "certificate_id": certificate_id}), 201

@certificates_bp.route('/verify/<certificate_id>', methods=['GET'])
def verify(certificate_id):
    is_valid = verify_certificate(certificate_id)
    return jsonify({"certificate_id": certificate_id, "is_valid": is_valid})

@certificates_bp.route('/certificate/<certificate_id>', methods=['GET'])
def retrieve_certificate(certificate_id):
    certificate_data = get_certificate(certificate_id)
    if certificate_data:
        return render_template('certificate.html', certificate=certificate_data)
    return jsonify({"message": "Certificate not found"}), 404

@certificates_bp.route('/display/<certificate_id>', methods=['GET'])
def display(certificate_id):
    certificate_data = get_certificate(certificate_id)
    if certificate_data:
        return display_certificate(certificate_data)
    return jsonify({"message": "Certificate not found"}), 404
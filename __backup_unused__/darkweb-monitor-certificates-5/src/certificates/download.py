from flask import send_file
from flask_restful import Resource
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from models.certificate import Certificate

class CertificateDownload(Resource):
    def get(self, certificate_id):
        # Fetch the certificate details from the database
        certificate = Certificate.get_certificate_by_id(certificate_id)
        if not certificate:
            return {"message": "Certificate not found"}, 404
        
        # Create a PDF in memory
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        p.drawString(100, 750, f"Certificate of Completion")
        p.drawString(100, 730, f"This certifies that {certificate.user_name}")
        p.drawString(100, 710, f"has completed the course: {certificate.course_name}")
        p.drawString(100, 690, f"Score: {certificate.score}")
        p.drawString(100, 670, f"Issued by: {certificate.issued_by}")
        p.drawString(100, 650, f"Issue Date: {certificate.issue_date}")
        p.drawString(100, 630, f"Verification Hash: {certificate.verification_hash}")
        p.drawString(100, 610, f"Certificate ID: {certificate.certificate_id}")
        p.showPage()
        p.save()
        buffer.seek(0)

        # Send the PDF as a response
        return send_file(buffer, as_attachment=True, download_name=f"{certificate.user_name}_certificate.pdf", mimetype='application/pdf')
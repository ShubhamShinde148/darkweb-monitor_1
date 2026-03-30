from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.String(36), primary_key=True)  # Unique ID for the certificate
    user_id = db.Column(db.String(36), nullable=False)  # ID of the user who owns the certificate
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)  # Date when the certificate was issued
    verification_hash = db.Column(db.String(64), unique=True, nullable=False)  # SHA256 hash for verification
    status = db.Column(db.String(20), default='active')  # Status of the certificate (active, revoked, etc.)
    certificate_data = db.Column(db.JSON, nullable=False)  # JSON field to store certificate details

    def __repr__(self):
        return f'<Certificate {self.id} for User {self.user_id}>'
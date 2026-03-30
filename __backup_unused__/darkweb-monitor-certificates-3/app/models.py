from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from marshmallow import Schema, fields, validate

db = SQLAlchemy()

class Certificate(db.Model):
    __tablename__ = 'certificates'

    id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.String, nullable=False)
    issue_date = db.Column(db.DateTime, default=datetime.utcnow)
    expiration_date = db.Column(db.DateTime, nullable=False)
    certificate_data = db.Column(db.JSON, nullable=False)

    def __init__(self, user_id, expiration_date, certificate_data):
        self.user_id = user_id
        self.expiration_date = expiration_date
        self.certificate_data = certificate_data

class CertificateSchema(Schema):
    id = fields.String(required=True)
    user_id = fields.String(required=True, validate=validate.Length(min=1))
    issue_date = fields.DateTime()
    expiration_date = fields.DateTime(required=True)
    certificate_data = fields.Raw(required=True)
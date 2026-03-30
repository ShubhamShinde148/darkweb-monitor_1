from datetime import datetime

class Certificate:
    def __init__(self, certificate_id, user_id, user_name, course_name, score, percentage, issued_by):
        self.certificate_id = certificate_id
        self.user_id = user_id
        self.user_name = user_name
        self.course_name = course_name
        self.score = score
        self.percentage = percentage
        self.issued_by = issued_by
        self.issue_date = datetime.utcnow()
        self.verification_hash = self.generate_verification_hash()
        self.is_verified = False

    def generate_verification_hash(self):
        import hashlib
        hash_input = f"{self.certificate_id}{self.user_id}{self.issue_date}".encode()
        return hashlib.sha256(hash_input).hexdigest()
from datetime import datetime
from collections import defaultdict

class CertificateMonitor:
    def __init__(self):
        self.verification_logs = []
        self.verification_statistics = defaultdict(int)

    def log_verification_attempt(self, certificate_id, user_id, success):
        timestamp = datetime.now().isoformat()
        log_entry = {
            'certificate_id': certificate_id,
            'user_id': user_id,
            'success': success,
            'timestamp': timestamp
        }
        self.verification_logs.append(log_entry)
        self.verification_statistics[certificate_id] += 1

    def get_verification_logs(self):
        return self.verification_logs

    def get_verification_statistics(self):
        return dict(self.verification_statistics)

    def clear_logs(self):
        self.verification_logs.clear()
        self.verification_statistics.clear()
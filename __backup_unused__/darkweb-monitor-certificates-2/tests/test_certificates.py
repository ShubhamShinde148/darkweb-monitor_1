import unittest
from app.certificates.generator import generate_certificate
from app.certificates.storage import save_certificate, get_certificate
from app.certificates.verifier import verify_certificate

class TestCertificateFunctions(unittest.TestCase):

    def setUp(self):
        self.test_data = {
            'user_id': 'test_user',
            'certificate_id': 'cert_12345',
            'verification_hash': 'hash_abcde',
            'issue_date': '2023-10-01',
            'expiry_date': '2024-10-01'
        }
        self.certificate = generate_certificate(self.test_data)

    def test_certificate_generation(self):
        self.assertIsNotNone(self.certificate)
        self.assertEqual(self.certificate['certificate_id'], self.test_data['certificate_id'])

    def test_certificate_storage(self):
        save_certificate(self.certificate)
        retrieved_certificate = get_certificate(self.test_data['certificate_id'])
        self.assertEqual(retrieved_certificate['certificate_id'], self.test_data['certificate_id'])

    def test_certificate_verification(self):
        save_certificate(self.certificate)
        is_verified = verify_certificate(self.test_data['certificate_id'], self.test_data['verification_hash'])
        self.assertTrue(is_verified)

if __name__ == '__main__':
    unittest.main()
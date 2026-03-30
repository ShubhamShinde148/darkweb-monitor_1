# Dark Web Monitor Certificate System

This project is a Flask-based cybersecurity platform designed to monitor and manage certificates related to dark web activities. It includes features for certificate generation, storage, verification, display, and download, along with an admin dashboard for monitoring certificates and user performance.

## Features

- **Certificate Generation**: Automatically generate unique certificates with SHA256 hashes.
- **Certificate Storage**: Store certificates securely in Firebase Firestore.
- **Certificate Verification**: Verify certificates using unique IDs or verification hashes.
- **Certificate Display**: Render certificates in a user-friendly format, including PDF generation.
- **Admin Dashboard**: Monitor total certificates issued, recent certificates, and verification logs.
- **User Performance Tracking**: Analyze user performance metrics and statistics.

## Project Structure

```
darkweb-monitor-certificates
├── app
│   ├── __init__.py
│   ├── models.py
│   ├── views.py
│   ├── certificates
│   │   ├── generator.py
│   │   ├── storage.py
│   │   ├── verifier.py
│   │   └── display.py
│   ├── admin
│   │   ├── dashboard.py
│   │   └── performance.py
│   ├── templates
│   │   ├── certificate.html
│   │   ├── dashboard.html
│   │   └── user_performance.html
│   └── static
│       └── css
│           └── style.css
├── migrations
│   └── README.md
├── tests
│   ├── test_certificates.py
│   ├── test_admin.py
│   └── README.md
├── requirements.txt
├── config.py
├── run.py
└── README.md
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd darkweb-monitor-certificates
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up your Firebase credentials in `config.py`.

4. Run the application:
   ```
   python run.py
   ```

## Usage

- Access the user dashboard to view and manage your certificates.
- Admins can monitor overall performance and manage certificates through the admin dashboard.

## Testing

To run the tests, use the following command:
```
pytest tests/
```

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
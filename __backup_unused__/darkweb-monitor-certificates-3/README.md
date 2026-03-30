# Dark Web Monitor Certificate System

## Overview
The Dark Web Monitor Certificate System is a Flask-based application designed to generate, store, verify, display, and manage certificates related to cybersecurity. This system aims to provide a secure and efficient way to handle certificates, ensuring that users can easily access and verify their credentials.

## Features
- **Certificate Generation**: Automatically generate unique certificates with SHA256 hashes and IDs.
- **Certificate Storage**: Store certificates securely in Firebase Firestore.
- **Certificate Verification**: Verify certificates using unique IDs or verification hashes.
- **Certificate Display**: Render certificates in a user-friendly format, including PDF generation and QR code creation for easy access.
- **Admin Dashboard**: Monitor certificate statistics, including total certificates issued, recent certificates, and top users by score.

## Project Structure
```
darkweb-monitor-certificates
├── app
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── certificate
│   │   ├── generator.py
│   │   ├── storage.py
│   │   ├── verifier.py
│   │   └── display.py
│   ├── admin
│   │   ├── dashboard.py
│   │   └── views.py
│   └── templates
│       ├── certificate.html
│       ├── admin_dashboard.html
│       └── base.html
├── static
│   └── css
│       └── style.css
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

3. Configure Firebase credentials in `config.py`.

4. Run the application:
   ```
   python run.py
   ```

## Usage
- Access the application through your web browser at `http://localhost:5000`.
- Use the admin dashboard to monitor certificates and manage users.
- Generate and verify certificates through the provided routes.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
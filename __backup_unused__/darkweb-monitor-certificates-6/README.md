# Dark Web Monitor Certificate System

This project is a Flask-based cybersecurity platform designed to monitor and manage certificates related to user activities on the dark web. The system includes features for certificate generation, storage, verification, display, and download, along with an admin dashboard for monitoring certificates.

## Project Structure

```
darkweb-monitor-certificates
├── src
│   ├── app.py                     # Entry point of the Flask application
│   ├── certificates                # Certificate management functionalities
│   │   ├── generator.py            # Certificate generation logic
│   │   ├── storage.py              # Certificate storage in Firebase
│   │   ├── verifier.py             # Certificate verification logic
│   │   ├── display.py              # Certificate display logic
│   │   └── download.py             # Certificate download functionality
│   ├── admin                       # Admin functionalities
│   │   ├── dashboard.py            # Admin dashboard for monitoring
│   │   └── monitor.py              # Certificate verification monitoring
│   ├── models                      # Data models
│   │   └── certificate.py          # Certificate data model
│   ├── templates                   # HTML templates for rendering
│   │   ├── dashboard.html          # Admin dashboard template
│   │   ├── certificate_display.html # Certificate display template
│   │   └── certificate_download.html# Certificate download template
│   ├── static                      # Static files (CSS, images)
│   │   └── style.css               # CSS styles for the application
│   └── utils                       # Utility functions
│       └── helpers.py              # Helper functions for various tasks
├── requirements.txt                # Project dependencies
├── README.md                       # Project documentation
└── config.py                      # Configuration settings
```

## Features

- **Certificate Generation**: Create certificates with unique IDs and SHA256 verification hashes.
- **Certificate Storage**: Store certificates securely in Firebase Firestore.
- **Certificate Verification**: Verify certificates using their IDs and hashes.
- **Certificate Display**: Display user certificates on the dashboard.
- **Certificate Download**: Allow users to download their certificates as PDFs.
- **Admin Dashboard**: Monitor total certificates issued, recent certificates, and top users by score.
- **Certificate Monitoring**: Log verification attempts and provide insights into verification statistics.

## Setup Instructions

1. Clone the repository:
   ```
   git clone <repository-url>
   cd darkweb-monitor-certificates
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure your Firebase credentials in `config.py`.

4. Run the application:
   ```
   python src/app.py
   ```

5. Access the application in your web browser at `http://localhost:5000`.

## Usage Guidelines

- Admins can access the dashboard to monitor certificates and user activities.
- Users can generate and download their certificates through the user interface.
- Ensure that Firebase is properly set up and configured to store and retrieve certificates.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
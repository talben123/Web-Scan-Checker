
# URL Security Scanner API

A simple API for performing security scans on websites and checking for basic vulnerabilities.

## What does the system do?

The system performs basic security checks on provided URLs:

- **SSL Validation**: Verifies if the website uses HTTPS with a valid SSL certificate.
- **Security Headers Check**: Verifies if the website implements recommended security headers.
- **Open Ports Scan**: Checks if common sensitive ports are open on the server.
- **Safe Browsing Simulation**: Simulates a check to detect if the website is listed as malicious.

## System Requirements

- Python 3.6 or higher
- The following Python packages:
  - Flask
  - Requests
  - Gunicorn
  - Werkzeug

## Installation

All required libraries are already installed in the Replit environment.

If running locally, install the dependencies with:

```bash
pip install -r requirements.txt
```

## API Usage

### Scan Endpoint

```
POST /api/scan
```

### Request Format

Send a POST request with JSON payload in the following format:

```json
{
  "url": "https://example.com"
}
```

### Response Format

The system returns detailed scan results in JSON format:

```json
{
  "overall_status": "Secure",
  "overall_score": 95,
  "issues_found": {
    "ssl_validation": {
      "valid_ssl": true,
      "details": "SSL certificate is valid until Jul 16 2024."
    },
    "security_headers": {
      "missing_headers": ["X-Content-Type-Options"],
      "present_headers": ["Strict-Transport-Security", "X-Frame-Options"]
    },
    "port_scan": {
      "open_ports": [80, 443]
    },
    "safe_browsing_status": {
      "checked": "Simulated Check",
      "unsafe_detected": false
    }
  },
  "risk_summary": {
    "critical_issues": 0,
    "warnings": 1,
    "info": 1
  },
  "recommendations": [
    "⚠️ Warning: Missing X-Content-Type-Options header – Add this header to prevent browsers from interpreting files incorrectly and protect against attacks.",
    "ℹ️ Info: Safe browsing check passed – No malicious content detected on this site."
  ]
}
```

## Running the Server

The server runs automatically in the Replit environment on port 5000.

If running locally, you can start it with:

```bash
gunicorn app:app --bind 0.0.0.0:8000
```

## User Interface

Access the root page of the app to view a simple interactive UI that allows you to test the API easily.

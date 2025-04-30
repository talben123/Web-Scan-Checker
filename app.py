import os
import logging
import requests
import socket
import ssl
from flask import Flask, request, jsonify
from flask_cors import CORS

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all domains

app.secret_key = os.environ.get("SESSION_SECRET", "default_secret_key")

@app.route('/')
def index():
    """Simple home page"""
    return "<h1>Welcome to the URL Security Scanner API</h1>"

@app.route('/api/scan', methods=['POST'])
def scan_url():
    """
    API endpoint to scan a URL for security vulnerabilities
    
    Expected JSON input: {"url": "https://example.com"}
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required parameter: url'
            }), 400
        
        url = data['url']
        logger.debug(f"Received URL for scanning: {url}")
        
        results = {
            "overall_status": "Unknown",
            "overall_score": 0,
            "issues_found": {},
            "risk_summary": {
                "critical_issues": 0,
                "warnings": 0,
                "info": 0
            },
            "recommendations": []
        }

        # SSL Check
        ssl_valid = False
        ssl_details = ""
        hostname = ""
        try:
            hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(3)
                s.connect((hostname, 443))
                cert = s.getpeercert()
                ssl_valid = True
                if cert and 'notAfter' in cert:
                    expiry = cert['notAfter']
                    ssl_details = f"SSL certificate is valid until {expiry}."
                else:
                    ssl_details = "SSL certificate is valid, but expiry date could not be determined."
        except Exception as e:
            ssl_details = f"SSL validation failed: {str(e)}"

        results["issues_found"]["ssl_validation"] = {
            "valid_ssl": ssl_valid,
            "details": ssl_details
        }
        if not ssl_valid:
            results["risk_summary"]["critical_issues"] += 1
            results["recommendations"].append("Install a valid SSL certificate.")

        # Security Headers Check
        headers_info = {
            "missing_headers": [],
            "present_headers": []
        }
        try:
            if hostname:
                resp = requests.get(f"https://{hostname}", timeout=5)
                headers = resp.headers
                security_headers = ["Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"]
                for header in security_headers:
                    if header in headers:
                        headers_info["present_headers"].append(header)
                    else:
                        headers_info["missing_headers"].append(header)
            else:
                headers_info["missing_headers"] = ["Cannot verify headers (invalid hostname)"]
        except Exception as e:
            headers_info["missing_headers"] = [f"Cannot verify headers (site not reachable): {str(e)}"]

        results["issues_found"]["security_headers"] = headers_info
        if len(headers_info["missing_headers"]) > 0:
            results["risk_summary"]["warnings"] += len(headers_info["missing_headers"])
            header_recommendations = {
                "Strict-Transport-Security": "Enable HTTPS protection to force browsers to use secure connections and protect users.",
                "X-Content-Type-Options": "Add this header to prevent browsers from interpreting files incorrectly and protect against attacks.",
                "X-Frame-Options": "Add this header to prevent clickjacking by disallowing your site to be embedded."
            }
            for h in headers_info["missing_headers"]:
                if not h.startswith("Cannot verify"):
                    if h in header_recommendations:
                        results["recommendations"].append(f"Implement security header: {h} — {header_recommendations[h]}")
                    else:
                        results["recommendations"].append(f"Implement security header: {h}")

        # Open Ports Scan (Basic)
        open_ports = []
        try:
            if hostname:
                for port in [21, 22, 80, 443]:
                    sock = socket.socket()
                    sock.settimeout(1)
                    try:
                        sock.connect((hostname, port))
                        open_ports.append(port)
                    except:
                        continue
                    finally:
                        sock.close()
        except Exception as e:
            logger.error(f"Port scan error: {str(e)}")

        results["issues_found"]["port_scan"] = {
            "open_ports": open_ports
        }

        port_recommendations = {
            21: "Port 21 (FTP) is open — consider closing it if not necessary, to prevent unauthorized file access.",
            22: "Port 22 (SSH) is open — ensure SSH access is restricted or properly secured.",
            80: "Port 80 (HTTP) is open — redirect all HTTP traffic to HTTPS to secure user data."
        }

        for port in open_ports:
            if port in port_recommendations:
                results["recommendations"].append(port_recommendations[port])

        if 21 in open_ports or 22 in open_ports:
            results["risk_summary"]["critical_issues"] += 1

        results["issues_found"]["safe_browsing_status"] = {
            "checked": "Simulated Check",
            "unsafe_detected": False
        }
        results["risk_summary"]["info"] += 1

        total_issues = results["risk_summary"]["critical_issues"] + results["risk_summary"]["warnings"]
        if total_issues == 0:
            results["overall_status"] = "Secure"
            results["overall_score"] = 95
        elif results["risk_summary"]["critical_issues"] > 0:
            results["overall_status"] = "Critical"
            results["overall_score"] = 40
        else:
            results["overall_status"] = "Moderate"
            results["overall_score"] = 70

        return jsonify(results)

    except Exception as e:
        logger.error(f"General error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error processing request: {str(e)}'
        }), 500

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=True)

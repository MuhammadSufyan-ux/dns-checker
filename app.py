from flask import Flask, render_template, request, jsonify
import socket
import whois
from datetime import datetime
import requests
from urllib.parse import urlparse
import json
import time

app = Flask(__name__)
  
  
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check_domain', methods=['POST'])
def check_domain():
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Please enter a domain name'})
    
    try:
        # Add http:// if missing for parsing
        if not domain.startswith(('http://', 'https://')):
            domain_to_check = 'http://' + domain
        else:
            domain_to_check = domain
            
        parsed_url = urlparse(domain_to_check)
        domain_name = parsed_url.netloc or parsed_url.path
        
        # Get domain information
        try:
            domain_info = whois.whois(domain_name)
            is_available = False
        except whois.parser.PywhoisError:
            domain_info = None
            is_available = True
        
        # Get IP address
        try:
            ip_address = socket.gethostbyname(domain_name)
        except:
            ip_address = "Could not resolve"
            
        # Get HTTP status if available
        http_status = "N/A"
        server_info = "N/A"
        try:
            response = requests.get(domain_to_check, timeout=5)
            http_status = f"{response.status_code} {response.reason}"
            server_info = response.headers.get('Server', 'N/A')
        except:
            http_status = "No HTTP response"
        
        # Format results
        if is_available:
            result = {
                'domain': domain_name,
                'available': True,
                'message': 'This domain is available for registration!',
                'ip_address': ip_address,
                'http_status': http_status,
                'server_info': server_info
            }
        else:
            # Format dates
            def format_date(date):
                if not date:
                    return "N/A"
                if isinstance(date, list):
                    date = date[0]
                if isinstance(date, datetime):
                    return date.strftime("%Y-%m-%d %H:%M:%S")
                return str(date)
            
            # Format list items
            def format_list(items):
                if not items:
                    return "N/A"
                if isinstance(items, list):
                    return ", ".join([str(item) for item in items])
                return str(items)
            
            result = {
                'domain': domain_name,
                'available': False,
                'registrar': domain_info.registrar or 'N/A',
                'creation_date': format_date(domain_info.creation_date),
                'expiration_date': format_date(domain_info.expiration_date),
                'updated_date': format_date(domain_info.updated_date),
                'name_servers': format_list(domain_info.name_servers),
                'ip_address': ip_address,
                'http_status': http_status,
                'server_info': server_info,
                'registrant': {
                    'name': format_list(getattr(domain_info, 'name', 'N/A')),
                    'organization': format_list(getattr(domain_info, 'org', 'N/A')),
                    'country': format_list(getattr(domain_info, 'country', 'N/A'))
                }
            }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': f'An error occurred: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
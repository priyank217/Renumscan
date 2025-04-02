import os
import re
import subprocess
import csv
from collections import defaultdict

def run_dnsrecon(domain):
    try:
        folder_name = f"{domain}_report"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        
        csv_file = os.path.join(folder_name, f"{domain}_dnsrecon_results.csv")
        result = subprocess.run(['dnsrecon', '-d', domain, '-c', csv_file], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"dnsrecon output saved to {csv_file}.")
            return csv_file
        else:
            print(f"Error running dnsrecon: {result.stderr}")
            return None
    except Exception as e:
        print(f"Exception occurred while running dnsrecon: {e}")
        return None

def parse_dnsrecon_csv(csv_file):
    dns_records = defaultdict(list)
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            record = {
                'type': row['Type'],
                'name': row['Name'],
                'address': row.get('Address', ''),
                'string': row.get('String', '')
            }
            dns_records[row['Type']].append(record)
    return dns_records

def parse_verification_key(key: str) -> str:
    """Dynamically extract service names from verification keys"""

    key = re.sub(r'^_+|[\W_]+$', '', key)
    parts = re.split(r'[-_]+', key)[:3]  
    
   
    verification_terms = {
        'verification', 'verify', 'challenge', 'validation',
        'domain', 'site'}
    
    def is_unwanted(part):
        return (
            part.lower() in verification_terms or
            re.match(r'^[0-9a-f]{8,}$', part) or  # Hex strings
            re.match(r'^[a-z0-9]{16,}$', part, re.I) or  # Long random strings
            part.isdigit()
        )
    components = []
    for part in parts:
        if not is_unwanted(part):
            components.append(part.upper() if part.isupper() else part.capitalize())
            if len(components) >= 2:
                break
    
    return ' '.join(components) or 'Unknown'

def analyze_txt_records(txt_records):
    detected_services = defaultdict(int)
    security_notes = []
    unknown_services = []

    for record in txt_records:
        txt_string = record.get('string', '').strip('"\'')
        
        if 'v=spf1' in txt_string:
            spf_includes = len(re.findall(r'include:\S+', txt_string))
            detected_services['Email (SPF)'] = spf_includes
            if spf_includes > 5:
                security_notes.append(f"SPF includes {spf_includes} sources (recommend ≤5)")
            continue

        if 'v=DMARC1' in txt_string:
            detected_services['Email (DMARC)'] = 1
            if 'p=none' in txt_string:
                security_notes.append("DMARC policy set to monitor-only (p=none)")
            continue

        if '=' in txt_string:
            key_part = txt_string.split('=', 1)[0].strip()
            service_name = parse_verification_key(key_part)
            
            if service_name != 'Unknown':
                detected_services[service_name] += 1
                continue

        unknown_services.append(txt_string[:75].strip())

    return {
        'detected_services': dict(detected_services),
        'security_notes': security_notes,
        'unknown_services': unknown_services
    }
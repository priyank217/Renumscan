import os
import subprocess
import json

def run_httpx_toolkit(domain):
    try:
        folder_name = f"{domain}_report"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        
        json_file = os.path.join(folder_name, f"{domain}_httpx_results.json")
        result = subprocess.run(
            ['httpx-toolkit', '-l', os.path.join(folder_name, f"{domain}_merged_subdomains.txt"),
             "-status-code", "-tech-detect", "-follow-redirects", "-tls-grab" , "-tls-probe",'-json', '-o', json_file],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            with open(json_file, 'r') as f:
                lines = f.readlines()
        
            non_empty_lines = [line.strip('\n') for line in lines if line.strip()]
            formatted_json = '[\n' + ',\n'.join(non_empty_lines) + '\n]'
            
            with open(json_file, 'w') as f:
                f.write(formatted_json)
            
            
            print(f"httpx-toolkit output saved to {json_file}.")
            return json_file
        else:
            print(f"Error running httpx-toolkit: {result.stderr}")
            return None
    except Exception as e:
        print(f"Exception occurred while running httpx-toolkit: {e}")
        return None

def parse_httpx_json(json_file):
    httpx_results = []
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            for entry in data:
                httpx_results.append({
                    'url': entry.get('url'),
                    'webserver': entry.get('webserver'),
                    'host': entry.get('host'),
                    'chain-status-codes': entry.get('chain-status-codes'),
                    'status-code': entry.get('status-code'),
                    'a': entry.get('a'),
                    'ports': entry.get('ports'),
                    'technologies': entry.get('technologies'),
                    'tls_version': entry.get('tls-grab', {}).get('tls_version'),
                    'issuer_organization': entry.get('tls-grab', {}).get('issuer_organization'),
                    'fingerprint_sha256': entry.get('tls-grab', {}).get('fingerprint_sha256'),
                    'final-url': entry.get('final-url')
                })
    except Exception as e:
        print(f"Error parsing JSON file: {e}")
    return httpx_results
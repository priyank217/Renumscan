import subprocess
import re

def get_whois_info(domain):
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True)
        whois_data = result.stdout

        domain_name = re.search(r'Domain Name: (.+)', whois_data)
        registry_domain_id = re.search(r'Registry Domain ID: (.+)', whois_data)
        registrar_whois_server = re.search(r'Registrar WHOIS Server: (.+)', whois_data)
        registrar_url = re.search(r'Registrar URL: (.+)', whois_data)
        updated_date = re.search(r'Updated Date: (.+)', whois_data)
        expiration_date = re.search(r'Registrar Registration Expiration Date: (.+)', whois_data)
        admin_name = re.search(r'Admin Name: (.+)', whois_data)
        admin_email = re.search(r'Admin Email: (.+)', whois_data)

        whois_info = {
            'domain_name': domain_name.group(1) if domain_name else 'N/A',
            'registry_domain_id': registry_domain_id.group(1) if registry_domain_id else 'N/A',
            'registrar_whois_server': registrar_whois_server.group(1) if registrar_whois_server else 'N/A',
            'registrar_url': registrar_url.group(1) if registrar_url else 'N/A',
            'updated_date': updated_date.group(1) if updated_date else 'N/A',
            'expiration_date': expiration_date.group(1) if expiration_date else 'N/A',
            'admin_name': admin_name.group(1) if admin_name else 'N/A',
            'admin_email': admin_email.group(1) if admin_email else 'N/A'
        }
        return whois_info
    except Exception as e:
        print(f"Exception occurred while fetching WHOIS info for {domain}: {e}")
        return None

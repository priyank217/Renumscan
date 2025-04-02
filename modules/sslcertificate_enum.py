from datetime import timezone
import os
import subprocess
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
import xml.etree.ElementTree as ET

def fetch_certificate_info(domain):

    domain_ssl = "www." +domain

    context = ssl.create_default_context()
    with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain_ssl) as conn:
        conn.settimeout(5.0)
        conn.connect((domain_ssl, 443))
        cert_bin = conn.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
    public_key = cert.public_key()
    
    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_size = public_key.curve.key_size
    else:
        key_size = "Unknown"

        not_before = getattr(cert, 'not_valid_before_utc', cert.not_valid_before)
        not_after = getattr(cert, 'not_valid_after_utc', cert.not_valid_after)
        
        # Ensure timezone awareness (if not already present)
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)

    return {
        "Subject": cert.subject.rfc4514_string(),
        "Issuer": cert.issuer.rfc4514_string(),
        "Not Before": cert.not_valid_before,
        "Not After": cert.not_valid_after,
        "Signature Algorithm": cert.signature_algorithm_oid._name,
        "Public-Key Strength": key_size
    }


def run_sslscan(domain):
    folder_name = f"{domain}_report"

    domain_ssl = "www." +domain

    os.makedirs(folder_name, exist_ok=True)
    xml_file = os.path.join(folder_name, f"{domain}_sslscan_results.xml")
    try:
        result = subprocess.run(['sslscan', '--no-compression', '--no-fallback', '--no-renegotiation', '--xml={}'.format(xml_file), xml_file, domain_ssl], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"sslscan output saved to {xml_file}.")
            return xml_file
        else:
            print(f"Error running sslscan: {result.stderr}")
            return None
    except Exception as e:
        print(f"Exception occurred while running sslscan: {e}")
        return None

def parse_sslscan_xml(xml_file):
    protocols = []
    ciphers = []

    if not os.path.isfile(xml_file):
        print(f"File not found: {xml_file}")
        return {'protocols': protocols, 'ciphers': ciphers}

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        print("Root element:", root.tag)
        for child in root:
            print(f"Child element: {child.tag} with attributes {child.attrib}")

        ssltest = root.find('ssltest')
        if ssltest is not None:
            for protocol in ssltest.findall('protocol'):
                protocol_type = protocol.attrib.get('type', 'Unknown').upper() +'v' + protocol.attrib.get('version', 'Unknown')
                protocol_enabled = 'Enabled' if protocol.attrib.get('enabled') == '1' else 'Disabled'
                protocols.append({
                    'type': protocol_type,
                    'enabled': protocol_enabled
                })
            
            for cipher in ssltest.findall('cipher'):
                cipher_status = cipher.attrib.get('status', 'Unknown')
                cipher_sslversion = cipher.attrib.get('sslversion', 'Unknown')
                cipher_bits = cipher.attrib.get('bits', 'Unknown')
                cipher_name = cipher.attrib.get('cipher', 'Unknown')
                ciphers.append({
                    'status': cipher_status,
                    'sslversion': cipher_sslversion,
                    'bits': cipher_bits,
                    'cipher': cipher_name
                })
                
    except ET.ParseError as e:
        print(f"Error parsing sslscan XML: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    return protocols, ciphers

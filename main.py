import json
import os
from modules.dns_enum import run_dnsrecon, parse_dnsrecon_csv
from modules.endpoint_enum import fetch_endpoints
from modules.report import generate_dashboard
from modules.httpx_enum import parse_httpx_json, run_httpx_toolkit
from modules.sslcertificate_enum import fetch_certificate_info, run_sslscan, parse_sslscan_xml 
from modules.subdomain_enum import get_subdomains
from modules.whois_enum import get_whois_info
from modules.loginpage_enum import analyze_login_interfaces
from modules.port_enum import run_port_scan

def main():
    domain = input("Enter the domain: ")
    
    subdomains = get_subdomains(domain)

    httpx_json = run_httpx_toolkit(domain)
    httpx_json_file= run_port_scan(domain, httpx_json)
    print(httpx_json_file)
    report = {}

    if httpx_json_file:
        httpx_results = parse_httpx_json(httpx_json_file)
        if httpx_results:
            print("HTTPX results found.")

            for entry in httpx_results:
                url = entry.get('url')
                status_code = entry.get('status-code')
                
                if not url or not status_code:
                    continue  # Skip invalid entries
                    
                if str(status_code) == '200':
                    print(f"Fetching endpoints for {url}")
                    endpoints = fetch_endpoints(url)
                    if endpoints:
                        report[url] = endpoints
                        print(f"Endpoints found for {url}")
                    else:
                        print(f"No endpoints found for {url}")

            folder_name = f"{domain}_report"
            os.makedirs(folder_name, exist_ok=True)

            endpoint_json_path = os.path.join(folder_name, f"{domain}_endpoints.json")

            with open(endpoint_json_path, "w") as f:
                json.dump(report, f, indent=4)

            print("Endpoint data saved to output/endpoints.json")
        else:
            print("No HTTPX results found.")
    else:
        print("No HTTPX data found for subdomains.")

    httpx_results_for_login = parse_httpx_json(httpx_json_file)
    login_count, non_login_count, login_file = analyze_login_interfaces(httpx_results_for_login, domain)

    print(f" Login Pages: {login_count}")
    print(f" Non-Login Pages: {non_login_count}")
    print(f" Login URLs saved to: {login_file}")

    whois_final = get_whois_info(domain)
    if whois_final:
        print("WHOIS data found for the domain.")
    else:
        print("No WHOIS data found for the domain.")

    dns_csv_file = run_dnsrecon(domain)
    dns_results = []
    if dns_csv_file:
        dns_results = parse_dnsrecon_csv(dns_csv_file)
        if dns_results:
            print("DNS results found.")
        else:
            print("No DNS results found.")
    else:
        print("No DNS data found for the domain.")

    try:
        cert_info = fetch_certificate_info(domain)
        print("Certificate info fetched successfully.")
    except Exception as e:
        print(f"Failed to fetch certificate info: {e}")
        cert_info = {}

    sslscan_xml_file = run_sslscan(domain)
    protocols, ciphers = [], []
    if sslscan_xml_file:
        protocols, ciphers = parse_sslscan_xml(sslscan_xml_file)
        print("sslscan results found.")
    else:
        print("No sslscan data found for the domain.")
    
    generate_dashboard(
        subdomains, 
        httpx_results, 
        report, 
        whois_final, 
        dns_results,
        cert_info,
        protocols, 
        ciphers, 
        domain, 
        login_count=login_count,
        non_login_count=non_login_count,
        template_path='template_dashboard.html',
        output_file=f"{domain}_dashboard.html"
    )

if __name__ == "__main__":
    main()
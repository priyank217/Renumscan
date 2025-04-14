import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from modules.dns_enum import analyze_txt_records
from collections import defaultdict, Counter

def generate_dashboard(subdomains, 
                       httpx_results, 
                       report, whois_final, 
                       dns_records, cert_info, 
                       protocols, 
                       ciphers, 
                       domain,
                       login_count=0,
                       non_login_count=0,
                       template_path='template_dashboard.html', output_file="dashoard.html"):
    
    folder_name = f"{domain}_report"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    report_path = os.path.join(folder_name, output_file)
    template_dir = os.path.join(os.path.dirname(__file__), os.path.pardir, 'templates')
    template_dir = os.path.abspath(template_dir)

    print(report_path)

    txt_records = dns_records.get('TXT', [])
    service_analysis = analyze_txt_records(txt_records)

    tech_counts = {}
    for result in httpx_results:
        technologies = result.get('technologies') or []
        if isinstance(technologies, str):
            technologies = [tech.strip() for tech in technologies.strip("[]").split(",")]
        elif not isinstance(technologies, list):
            technologies = []

        for tech in technologies:
            tech = tech.strip("' ") 
            if tech and tech.lower() != 'none':
                tech_counts[tech] = tech_counts.get(tech, 0) + 1


    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template(template_path)

    warning_message = 'The Registry database contains ONLY .COM, .NET, .EDU domains and Registrars.'

    data = {
        'subdomains': subdomains,
        'tech_counts': tech_counts 
    }
    subdomain_endpoint_count = {}
    for subdomain, endpoints in report.items():
        subdomain_endpoint_count[subdomain] = len(endpoints)

    top_5_subdomains = sorted(subdomain_endpoint_count.items(), key=lambda x: x[1], reverse=True)[:5]
    top_subdomain_labels = [item[0] for item in top_5_subdomains]
    top_subdomain_counts = [item[1] for item in top_5_subdomains]

    data['top_subdomain_labels'] = top_subdomain_labels
    data['top_subdomain_counts'] = top_subdomain_counts

    httpx_column_filters = defaultdict(set)

    def safe_add(filter_dict, key, value):
        if isinstance(value, list):
            for item in value:
                if item:
                    filter_dict[key].add(str(item).strip())
        elif value:
            filter_dict[key].add(str(value).strip())

    for r in httpx_results:
        safe_add(httpx_column_filters, 'url', r.get('url'))
        safe_add(httpx_column_filters, 'webserver', r.get('webserver'))
        safe_add(httpx_column_filters, 'host', r.get('host'))
        safe_add(httpx_column_filters, 'chain-status-codes', r.get('chain-status-codes'))
        safe_add(httpx_column_filters, 'status-code', r.get('status-code'))
        safe_add(httpx_column_filters, 'technologies', r.get('technologies'))
        safe_add(httpx_column_filters, 'final-url', r.get('final-url'))
        safe_add(httpx_column_filters, 'tls_version', r.get('tls_version'))
        safe_add(httpx_column_filters, 'issuer_organization', r.get('issuer_organization'))
        safe_add(httpx_column_filters, 'fingerprint_sha256', r.get('fingerprint_sha256'))
        safe_add(httpx_column_filters, 'a', r.get('a'))
        safe_add(httpx_column_filters, 'ports', r.get('ports'))

    httpx_column_filters = {
    k: sorted(v) for k, v in httpx_column_filters.items() if v
    }
    
    tls_versions = []
    issuers = []

    for r in httpx_results:
        tls = r.get('tls_version')
        if isinstance(tls, str):
            tls_versions.append(tls)

        issuer = r.get('issuer_organization')
        if isinstance(issuer, list):
            issuers.extend(str(i).strip() for i in issuer if i)
        elif isinstance(issuer, str):
            issuers.append(issuer.strip())  

    tls_version_counts = dict(Counter(tls_versions))
    issuer_organization_counts = dict(Counter(issuers))

    # Count open ports
    port_counter = Counter()
    for r in httpx_results:
        ports = r.get('ports')
        if isinstance(ports, list):
            for port in ports:
                if isinstance(port, int) or (isinstance(port, str) and port.isdigit()):
                    port_counter[int(port)] += 1
        elif isinstance(ports, str):
            for port in ports.split(','):
                port = port.strip()
                if port.isdigit():
                    port_counter[int(port)] += 1

    print(port_counter)

    port_numbers = list(map(str, sorted(port_counter.keys())))
    port_counts = [port_counter[port] for port in sorted(port_counter.keys())]
    
    print("TLS Version Counts:", tls_version_counts)
    print("Issuer Organization Counts:", issuer_organization_counts)
    
    filled_template = template.render(data=data, 
                                      whois_final=whois_final,
                                      service_analysis=service_analysis, 
                                      warning_message=warning_message, 
                                      httpx_results=httpx_results,
                                      httpx_column_filters=httpx_column_filters,
                                      report= report,
                                      dns_results=dns_records, cert_info=cert_info, 
                                      protocols=protocols, 
                                      ciphers=ciphers, 
                                      domain=domain,
                                      login_count=login_count,
                                      non_login_count=non_login_count,
                                      tls_version_counts=tls_version_counts,
                                      port_numbers=port_numbers,
                                      port_counts=port_counts,
                                      issuer_organization_counts=issuer_organization_counts,
                                      generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    with open(report_path, 'w') as f:
         f.write(filled_template + "\n")

    print(f"Dashboard generated: {report_path}")
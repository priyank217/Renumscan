import os
import subprocess
import requests
from typing import List

def run_sublist3r(domain: str) -> List[str]:
    """Run Sublist3r and return subdomains."""
    subdomains = []
    try:
        result = subprocess.run(['sublist3r', '-d', domain, '-o', 'sublist3r.txt'], capture_output=True, text=True)
        if result.returncode == 0:
            with open('sublist3r.txt', 'r') as file:
                subdomains = file.read().splitlines()
            os.remove('sublist3r.txt')
        else:
            print(f"Error running Sublist3r: {result.stderr}")
    except Exception as e:
        print(f"Exception occurred while running Sublist3r: {e}")
    return subdomains

def run_assetfinder(domain: str) -> List[str]:
    """Run AssetFinder and return subdomains."""
    subdomains = []
    try:
        result = subprocess.run(['assetfinder', '-subs-only', domain], capture_output=True, text=True)
        if result.returncode == 0:
            subdomains = result.stdout.splitlines()
        else:
            print(f"Error running AssetFinder: {result.stderr}")
    except Exception as e:
        print(f"Exception occurred while running AssetFinder: {e}")
    return subdomains

def run_crtsh(domain: str) -> List[str]:
    """Query crt.sh and return subdomains."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                common_name = entry.get("common_name", "")
                name_value = entry.get("name_value", "")
                if common_name:
                    subdomains.add(common_name)
                if name_value:
                    subdomains.update(name_value.split("\n"))
        else:
            print(f"Failed to fetch data from crt.sh. Status code: {response.status_code}")
    except Exception as e:
        print(f"Exception occurred while querying crt.sh: {e}")
    return list(subdomains)

def save_subdomains_to_file(subdomains: List[str], domain: str, tool_name: str):
    """
    Save subdomains to a file in the domain's report folder.
    """
    folder_name = f"{domain}_report"
    os.makedirs(folder_name, exist_ok=True)
    file_name = os.path.join(folder_name, f"{domain}_{tool_name}_subdomains.txt")

    with open(file_name, 'w') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")

    print(f"Subdomains from {tool_name} saved to {file_name}")

def merge_and_deduplicate_subdomains(domain: str):
    """
    Merge subdomains from all tools, deduplicate, and save to a final file using shell commands.
    Remove subdomains that do not belong to the target domain.
    """
    folder_name = f"{domain}_report"
    merged_file_name = os.path.join(folder_name, f"{domain}_merged_subdomains.txt")

    try:
        subprocess.run(
            f"cat {folder_name}/{domain}_*_subdomains.txt | sort | uniq > {merged_file_name}",
            shell=True,
            check=True,
        )
        print(f"Merged and deduplicated subdomains saved to {merged_file_name}")

        with open(merged_file_name, 'r') as f:
            subdomains = f.read().splitlines()

        filtered_subdomains = [subdomain for subdomain in subdomains if subdomain.endswith(f".{domain}") or subdomain == domain]

        with open(merged_file_name, 'w') as f:
            for subdomain in filtered_subdomains:
                f.write(f"{subdomain}\n")

        print(f"Filtered subdomains saved to {merged_file_name}")
    except subprocess.CalledProcessError as e:
        print(f"Error merging and deduplicating subdomains: {e}")
    except Exception as e:
        print(f"Error filtering subdomains: {e}")

def get_subdomains(domain: str) -> List[str]:

    sublist3r_subdomains = run_sublist3r(domain)
    save_subdomains_to_file(sublist3r_subdomains, domain, 'sublist3r')

    assetfinder_subdomains = run_assetfinder(domain)
    save_subdomains_to_file(assetfinder_subdomains, domain, 'assetfinder')

    crtsh_subdomains = run_crtsh(domain)
    save_subdomains_to_file(crtsh_subdomains, domain, 'crtsh')

    merge_and_deduplicate_subdomains(domain)

    merged_file_name = os.path.join(f"{domain}_report", f"{domain}_merged_subdomains.txt")
    with open(merged_file_name, 'r') as f:
        return f.read().splitlines()

import json
import subprocess
import threading
import os
from queue import Queue

def run_port_scan(domain, httpx_json_file):
    output_dir = os.path.join(f"{domain}_report", "naabu_results")
    os.makedirs(output_dir, exist_ok=True)

    with open(httpx_json_file, "r") as f:
        data = json.load(f)

    unique_ips = sorted(set(
        ip for entry in data if "a" in entry and isinstance(entry["a"], list)
        for ip in entry["a"]
    ))

    common_ports = sorted(set([
        21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 139, 143,
        161, 162, 389, 443, 445, 465, 500, 514, 587, 636, 993, 995, 1080,
        8080, 8081, 8443, 8888, 9000, 9090, 9443, 1433, 1521, 2375, 2379,
        3306, 3389, 5432, 5984, 6379, 7001, 8000, 8086, 9042, 9200, 9300,
        11211, 27017, 28017, 4848, 7002, 8009, 8088, 8161, 8880, 9001,
        9091, 9600, 1883, 1900, 2323, 3000, 3478, 4000, 4789, 25565, 27015,
        32768, 49152, 50000, 60000
    ]))
    ports_str = ",".join(str(p) for p in common_ports)

    def run_parallel_scans(ip_list, thread_count=10):
        output_queue = Queue()
        results = {}
        total = len(ip_list)

        def thread_wrapper(ip, idx):
            print(f"[{idx}/{total}] → Scanning {ip} ...", end="", flush=True)
            found_ports = []
            try:
                output_file = os.path.join(output_dir, f"{ip}.txt")
                subprocess.run([
                    "naabu",
                    "-host", ip,
                    "-p", ports_str,
                    "-o", output_file,
                    "-rate", "100",
                    "-silent"
                ], capture_output=True, text=True)

                if os.path.exists(output_file):
                    with open(output_file, "r") as f:
                        for line in f:
                            if ":" in line:
                                ip, port = line.strip().split(":")
                                port = int(port)
                                found_ports.append(port)
                                output_queue.put((ip, port))

                status = f" {len(found_ports)} ports open" if found_ports else " no ports found"
                print(status)

            except Exception as e:
                print(f" error: {e}")

        threads = []
        for idx, ip in enumerate(ip_list, 1):
            t = threading.Thread(target=thread_wrapper, args=(ip, idx))
            t.start()
            threads.append(t)

            if len(threads) >= thread_count:
                for t in threads:
                    t.join()
                threads = []

        for t in threads:
            t.join()

        while not output_queue.empty():
            ip, port = output_queue.get()
            results.setdefault(ip, []).append(port)

        return results

    print(f"[*] Starting parallel Naabu scan with {len(unique_ips)} targets...")
    results = run_parallel_scans(unique_ips, thread_count=10)

    for entry in data:
        entry_ports = set()
        if "a" in entry and isinstance(entry["a"], list):
            for ip in entry["a"]:
                if ip in results:
                    entry_ports.update(results[ip])
        if entry_ports:
            entry["ports"] = sorted(entry_ports)

    with open(httpx_json_file, "w") as f:
        json.dump(data, f, indent=2)

    return httpx_json_file
    print(f"\n Scan complete. Ports merged and saved back to {httpx_json_file}")

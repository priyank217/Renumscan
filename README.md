
## Renumscan
Renumscan is a reconnaissance tool developed to identify and collect all available information on the internet that is associated with a specific organization. This type of data is essential for understanding an organization’s external digital footprint and identifying potential security risks, enabling SOC teams to take proactive measures.

### Key Features and Capabilities:

- **Domain and Subdomain Enumeration**  
  Identifies the main domain and any subdomains used by the organization.

- **IP Address and Server Discovery**  
  Discovers IP addresses and collects metadata about public-facing servers.

- **Technology Fingerprinting**  
  Detects the technologies used on the organization’s web assets (e.g., CMS, frameworks, databases, etc.).

- **WHOIS and DNS Record Lookup**  
  Retrieves ownership details, registrar data, and DNS configurations.

- **Public Service and API Exposure**  
  Finds open services or APIs that may be vulnerable to abuse or attack.

- **SSL/TLS Certificate Inspection**  
  Reviews SSL certificates for configuration details, expiration dates, and security practices.

- **Multi-format Output Support**  
  Saves scan results in various formats:
  - SSL scan results (XML)
  - DNS records (CSV)
  - Endpoint results (JSON)
  - Active subdomains with details (JSON)
  - Full list of discovered subdomains (TXT)
  - Self-contained, shareable HTML
## Screenshot
![image](https://github.com/user-attachments/assets/46907ecd-78d5-4918-bf95-f8036d4a0beb)
![image](https://github.com/user-attachments/assets/e930cb6c-5035-4c09-a09d-5fab92abec17)
![image](https://github.com/user-attachments/assets/06c3398b-b954-4c76-a4db-c9e39199eeb6)

## Installation & Usage

### Installation on Kali Linux

```bash
git clone https://github.com/priyank217/Renumscan.git
cd Renumscan
sudo su
chmod +x install.sh
./install.sh
python3 main.py   //If getting error then try python main.py
```
This will install dependencies and execute the scan.  
The final report file will be saved in your current working directory within folder domain_report.

## 🐳 Docker Setup (Cross-Platform)

Renumscan also supports Docker for platform-independent usage.

### 🔧 Build the Docker Image

```bash
docker build -t renumscan .
```

### ▶️ Run the Docker Container

```bash
docker run -it -v "/path/to/your/renumscan:/app" renumscan
python3 main.py
```
> Replace `/path/to/your/renumscan` with the full absolute path to the directory on your system where Renumscan is located and where the report should be stored.
---

### 📁 Report Output
After the scan is complete, you’ll find the `domain_report` directory inside your mapped local directory:

```
/path/to/your/local/domain_report
```
✅ **No server required** — simply open the HTML report in any modern browser.

## To-Do List
- [ ] Risk scoring and prioritization based on identified assets and exposure levels
- [ ] Leaked data check using breach databases or open-source APIs  
- [ ] IP address scanning for open ports and services (e.g., using Nmap,Masscan or rustscan)  
- [ ] IP rotation during scanning to avoid detection and rate-limiting  
- [ ] Parallel processing to increase scan efficiency and reduce runtime  
- [ ] Social media and employee footprint analysis (open-source intelligence)  
- [ ] GitHub and code repo exposure scanning
- [ ] CLI flags for modular/custom scan operations
- [ ] Enhance HTML report.

## ⚠️ Disclaimer

Renumscan is intended for **authorized security assessments** only.  
Unauthorized use against systems you do not own or have explicit permission to test may violate laws and ethical guidelines.

## 🙏 Acknowledgements

This project wouldn’t be possible without the incredible tools, libraries, and knowledge shared by the open-source community.
Special thanks to all the developers and contributors who make cybersecurity tooling more accessible and powerful for everyone.
